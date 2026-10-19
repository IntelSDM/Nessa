#include "Shared.h"

#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#include "llvm/IR/IntrinsicInst.h"

#include <chrono>
#include <cstring>
#include <random>
#include <string>

using namespace llvm;

void MarkMetadata(Instruction* i, const char* tag)
{
    if (!i || i->getMetadata(tag)) return;
    i->setMetadata(tag, MDNode::get(i->getContext(), {}));
}

bool HasMetadata(const Instruction* i, const char* tag)
{
    return i && i->getMetadata(tag) != nullptr;
}

void MarkGateRegion(Instruction* i, unsigned siteid)
{
    if (!i) return;
    LLVMContext& c = i->getContext();
    i->setMetadata(MdGateRegion, MDNode::get(c, { MDString::get(c, std::to_string(siteid)) }));
}

bool IsOurHelperName(StringRef n)
{
    return n.starts_with(PrefixIndirection)
        || n.starts_with(PrefixDepmarker)
        || n.starts_with(PrefixTlskey)
        || n.starts_with(PrefixRetkey)
        || n.starts_with(PrefixGateHash)
        || n.starts_with(PrefixChain)
        || n.starts_with(PrefixCallerkey)
        || n.starts_with(PrefixCleanup)
        || n.starts_with("DependencyMarker_");
}

static constexpr std::uint64_t MaskSeed = 0xC3C3C3C3DEFACED1ULL;
static std::uint64_t MaskState = MaskSeed;

void ResetMaskStream()
{
    MaskState = MaskSeed;
}

std::uint64_t NextMask()
{
    MaskState += 0x9E3779B97F4A7C15ULL;
    std::uint64_t x = MaskState;
    x ^= x >> 30; x *= 0xBF58476D1CE4E5B9ULL;
    x ^= x >> 27; x *= 0x94D049BB133111EBULL;
    x ^= x >> 31;
    return x | 1;
}

ArxParams Arx = { 0, 0, 0, 0, 0, 0 };

static std::mt19937_64& ArxRng()
{
    static std::mt19937_64 rng = []
    {
        std::random_device rd;
        auto seed = (std::uint64_t)rd() ^ std::chrono::high_resolution_clock::now().time_since_epoch().count();
        return std::mt19937_64(seed);
    }();
    return rng;
}

static int PickRot()
{
    std::uniform_int_distribution<int> d(1, 63);
    return d(ArxRng());
}

static std::uint64_t PickKey64()
{
    std::uniform_int_distribution<std::uint64_t> d(1, UINT64_MAX);
    return d(ArxRng());
}

void ArxInit()
{
    Arx.KdfSalt = PickKey64();
    Arx.HashSalt = PickKey64();
    Arx.KdfVal1 = PickRot(); Arx.KdfVal2 = 64 - Arx.KdfVal1;
    Arx.HashVal1 = PickRot(); Arx.HashVal2 = 64 - Arx.HashVal1;
}

std::uint64_t Rotl64(std::uint64_t x, int n)
{
    n &= 63;
    return n == 0 ? x : (x << n) | (x >> (64 - n));
}

std::uint64_t Rotr64(std::uint64_t x, int n)
{
    n &= 63;
    return n == 0 ? x : (x >> n) | (x << (64 - n));
}

std::uint64_t ArxEncCt(std::uint64_t v, std::uint64_t k, int val1, int val2)
{
    std::uint64_t r = v;
    r = r + k;
    r = Rotl64(r, val1);
    r = r ^ k;
    r = r + k;
    r = Rotr64(r, val2);
    return r;
}

Value* ArxEncRt(IRBuilder<>& b, Value* v, Value* k, int val1, int val2, const Twine& tag)
{
    Type* i64 = v->getType();
    Value* a = ConstantInt::get(i64, (std::uint64_t)val1);
    Value* ac = ConstantInt::get(i64, (std::uint64_t)(64 - val1));
    Value* bb = ConstantInt::get(i64, (std::uint64_t)val2);
    Value* bc = ConstantInt::get(i64, (std::uint64_t)(64 - val2));
    Value* r = b.CreateAdd(v, k, tag + ".e.a1");
    r = b.CreateOr(b.CreateShl(r, a), b.CreateLShr(r, ac), tag + ".e.rotl");
    r = b.CreateXor(r, k, tag + ".e.x");
    r = b.CreateAdd(r, k, tag + ".e.a2");
    r = b.CreateOr(b.CreateLShr(r, bb), b.CreateShl(r, bc), tag + ".e.rotr");
    return r;
}

Value* ArxDecRt(IRBuilder<>& b, Value* v, Value* k, int val1, int val2, const Twine& tag)
{
    Type* i64 = v->getType();
    Value* a = ConstantInt::get(i64, (std::uint64_t)val1);
    Value* ac = ConstantInt::get(i64, (std::uint64_t)(64 - val1));
    Value* bb = ConstantInt::get(i64, (std::uint64_t)val2);
    Value* bc = ConstantInt::get(i64, (std::uint64_t)(64 - val2));
    Value* r = v;
    r = b.CreateOr(b.CreateShl(r, bb), b.CreateLShr(r, bc), tag + ".d.rotl");
    r = b.CreateSub(r, k, tag + ".d.s1");
    r = b.CreateXor(r, k, tag + ".d.x");
    r = b.CreateOr(b.CreateLShr(r, a), b.CreateShl(r, ac), tag + ".d.rotr");
    r = b.CreateSub(r, k, tag + ".d.s2");
    return r;
}

std::uint64_t CompileKdf(std::uint64_t v)
{
    return ArxEncCt(v, Arx.KdfSalt, Arx.KdfVal1, Arx.KdfVal2);
}

Value* OpaqueLaunder(Value* v, IRBuilder<>& b, const Twine& tag)
{
    Type* t = v->getType();
    FunctionType* asmty = FunctionType::get(t, { t }, false);
    InlineAsm* launder = InlineAsm::get(asmty, "mov $0, $1", "=r,r,~{dirflag},~{fpsr},~{flags}", true, false, InlineAsm::AD_Intel);
    return b.CreateCall(launder, { v }, tag);
}

static unsigned ParseDepMarkerSuffixAnnot(StringRef s)
{
    const StringRef prefix = "DependencyMarker_";
    while (!s.empty() && s.back() == '\0') s = s.drop_back();
    if (!s.starts_with(prefix)) return 0;
    StringRef suffix = s.drop_front(prefix.size());
    unsigned n = 0;
    if (suffix.getAsInteger(10, n) || n == 0) return 0;
    return n;
}

static unsigned ParseDepMarkerSuffixName(StringRef s)
{
    const StringRef prefix = "DependencyMarker_";
    while (!s.empty() && s.back() == '\0') s = s.drop_back();

    size_t pos = s.find(prefix);
    if (pos == StringRef::npos) return 0;
    StringRef suffix = s.drop_front(pos + prefix.size());

    unsigned i = 0;
    while (i < suffix.size() && suffix[i] >= '0' && suffix[i] <= '9') ++i;
    if (i == 0) return 0;
    if (i < suffix.size() && suffix[i] == '_') return 0;

    StringRef digits = suffix.take_front(i);
    unsigned n = 0;
    if (digits.getAsInteger(10, n) || n == 0) return 0;
    return n;
}

unsigned GetDepmarkerNameId(StringRef name)
{
    return ParseDepMarkerSuffixName(name);
}

static std::vector<Function*> AnchorPool;

void CollectAnchorPool(Module& m)
{
    AnchorPool.clear();
    for (Function& f : m)
    {
        if (f.isDeclaration() || f.isIntrinsic()) continue;
        if (IsOurHelperName(f.getName())) continue;
        if (ParseDepMarkerSuffixName(f.getName()) != 0) continue;
        auto l = f.getLinkage();
        if (l != GlobalValue::ExternalLinkage
            && l != GlobalValue::InternalLinkage
            && l != GlobalValue::PrivateLinkage
            && l != GlobalValue::LinkOnceODRLinkage
            && l != GlobalValue::WeakAnyLinkage
            && l != GlobalValue::WeakODRLinkage)
            continue;
        AnchorPool.push_back(&f);
    }
}

Function* PickAnchor(Function* fallback)
{
    if (AnchorPool.empty()) return fallback;
    std::uniform_int_distribution<size_t> d(0, AnchorPool.size() - 1);
    return AnchorPool[d(ArxRng())];
}

Value* IndirectSlotAddr(IRBuilder<>& b, GlobalVariable* slot, Function* anchor, const Twine& tag)
{
    LLVMContext& c = b.getContext();
    Module* m = anchor->getParent();
    Type* i64 = Type::getInt64Ty(c);
    Type* ptrt = PointerType::get(c, 0);

    const std::uint64_t k1 = PickKey64();
    const std::uint64_t k2 = PickKey64();
    const int rota = PickRot();
    const std::uint64_t k3 = k1 ^ Rotr64(k2, rota);
    const std::uint64_t addmask = PickKey64();

    // bug: COFF rejects XOR on symbol expressions in static initializers, must use ADD
    Constant* sloti = ConstantExpr::getPtrToInt(slot, i64);
    Constant* anchori = ConstantExpr::getPtrToInt(anchor, i64);
    Constant* delta = ConstantExpr::getSub(sloti, anchori);
    Constant* maskeddelta = ConstantExpr::getAdd(delta, ConstantInt::get(i64, addmask));

    auto* deltagv = new GlobalVariable(*m, i64, true, GlobalValue::PrivateLinkage, maskeddelta, "__dmp_sd");
    deltagv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);

    Value* maskeddeltart = b.CreateLoad(i64, deltagv, tag + ".sd");
    Value* deltart = b.CreateSub(maskeddeltart, b.getInt64(addmask), tag + ".delta");

    Value* r = b.CreatePtrToInt(anchor, i64, tag + ".anc");
    r = OpaqueLaunder(r, b, tag + ".anc.op");

    r = b.CreateXor(r, b.getInt64(k1), tag + ".x1");
    r = b.CreateOr(
        b.CreateShl(r, b.getInt64((std::uint64_t)rota), tag + ".shl1"),
        b.CreateLShr(r, b.getInt64((std::uint64_t)(64 - rota)), tag + ".shr1"),
        tag + ".rl");
    r = b.CreateXor(r, b.getInt64(k2), tag + ".x2");
    r = b.CreateOr(
        b.CreateLShr(r, b.getInt64((std::uint64_t)rota), tag + ".shr2"),
        b.CreateShl(r, b.getInt64((std::uint64_t)(64 - rota)), tag + ".shl2"),
        tag + ".rr");
    r = b.CreateXor(r, b.getInt64(k3), tag + ".x3");

    r = b.CreateAdd(r, deltart, tag + ".addr");
    return b.CreateIntToPtr(r, ptrt, tag + ".ptr");
}

Value* EmitInlineEncoded(IRBuilder<>& b, Function* anchor, std::uint64_t rawconst, const Twine& tag)
{
    LLVMContext& c = b.getContext();
    Type* i64 = Type::getInt64Ty(c);

    Constant* anchorct = ConstantExpr::getPtrToInt(anchor, i64);
    Constant* encoded = ConstantExpr::getAdd(anchorct, ConstantInt::get(i64, rawconst));

    Value* anchorrt = b.CreatePtrToInt(anchor, i64, tag + ".anc");
    Value* anchorop = OpaqueLaunder(anchorrt, b, tag + ".op");

    return b.CreateSub(encoded, anchorop, tag);
}

bool IsCrtSpecialName(StringRef n)
{
    return n == "DllMain"
        || n == "_DllMainCRTStartup"
        || n == "DllMainCRTStartup"
        || n == "maincrtstartup"
        || n == "wmaincrtstartup"
        || n == "WinMainCRTStartup"
        || n == "wwinmaincrtstartup"
        || n == "_CRT_INIT"
        || n.starts_with("_tls_callback")
        || n == "__scrt_common_main"
        || n == "__scrt_common_main_seh"
        || n == "__scrt_dllmain_before_initialize_c"
        || n == "__scrt_dllmain_after_initialize_c";
}

bool IsCompilerHelperName(StringRef n)
{
    if (n == "_chkstk" || n == "__chkstk" || n == "__chkstk_ms") return true;
    if (n == "__security_check_cookie") return true;
    if (n == "__security_init_cookie") return true;
    if (n.starts_with("__GSHandlerCheck")) return true;
    if (n == "__CxxFrameHandler3" || n == "__CxxFrameHandler4") return true;
    if (n == "__C_specific_handler") return true;
    if (n == "__CxxThrowException") return true;
    if (n == "__std_terminate") return true;
    if (n == "__std_exception_copy" || n == "__std_exception_destroy") return true;
    if (n == "__RTDynamicCast" || n == "__RTtypeid" || n == "__RTCastToVoid") return true;
    if (n == "_purecall" || n == "__purecall") return true;
    if (n.starts_with("_RTC_")) return true;
    if (n == "__report_rangecheckfailure") return true;
    if (n == "__report_securityfailure") return true;
    if (n.starts_with("__scrt_")) return true;
    if (n.starts_with("__acrt_")) return true;
    if (n.starts_with("__crt_")) return true;
    if (n == "_Init_thread_header" || n == "_Init_thread_footer" || n == "_Init_thread_abort" || n == "_Init_thread_epoch") return true;
    if (n == "__msvc_align") return true;
    return false;
}

bool IsMsvcHelperCallee(StringRef n)
{
    return n == "__chkstk"
        || n == "_alloca_probe"
        || n == "__security_check_cookie"
        || n == "__security_init_cookie"
        || n == "__GSHandlerCheck"
        || n == "__GSHandlerCheck_SEH"
        || n == "__GSHandlerCheck_EH"
        || n == "__CxxFrameHandler3"
        || n == "__CxxFrameHandler4"
        || n == "__C_specific_handler"
        || n == "_setjmp"
        || n == "_setjmp3"
        || n == "longjmp"
        || n.starts_with("__imp_")
        || n.starts_with("__delayLoadHelper");
}

bool IsVtableGv(StringRef n)
{
    if (n.starts_with("??_7")) return true;
    if (n.starts_with("??_R4")) return true;
    if (n.starts_with("_ZTV")) return true;
    if (n.starts_with("_ZTC")) return true;
    if (n.starts_with("_ZTT")) return true;
    return false;
}

void CollectGlobalCtorDtorFuncs(Module& m, DenseSet<Function*>& out)
{
    const StringRef tables[] = { "llvm.global_ctors", "llvm.global_dtors" };
    for (StringRef tn : tables)
    {
        GlobalVariable* gv = m.getNamedGlobal(tn);
        if (!gv || !gv->hasInitializer()) continue;
        auto* ca = dyn_cast<ConstantArray>(gv->getInitializer());
        if (!ca) continue;
        for (unsigned i = 0; i < ca->getNumOperands(); ++i)
        {
            auto* cs = dyn_cast<ConstantStruct>(ca->getOperand(i));
            if (!cs || cs->getNumOperands() < 2) continue;
            Value* v = cs->getOperand(1)->stripPointerCasts();
            if (auto* f = dyn_cast<Function>(v))
                out.insert(f);
        }
    }
}

static bool UserLeadsOnlyToMetadataGlobals(User* u, DenseSet<User*>& visited)
{
    if (!visited.insert(u).second) return true;

    if (auto* gv = dyn_cast<GlobalVariable>(u))
    {
        StringRef n = gv->getName();
        return n == "llvm.global.annotations"
            || n == "llvm.used"
            || n == "llvm.compiler.used"
            || n == "llvm.metadata";
    }
    if (isa<Instruction>(u)) return false;
    if (u->user_empty()) return false;
    for (User* uu : u->users())
        if (!UserLeadsOnlyToMetadataGlobals(uu, visited))
            return false;
    return true;
}

bool DetectAddressTaken(Function& f)
{
    for (User* u : f.users())
    {
        if (auto* cb = dyn_cast<CallBase>(u))
        {
            if (cb->getCalledOperand() != &f) return true;
            continue;
        }
        DenseSet<User*> visited;
        if (!UserLeadsOnlyToMetadataGlobals(u, visited))
            return true;
    }
    return false;
}

bool IsRewritableConstOp(Instruction& i, unsigned opidx)
{
    if (isa<PHINode>(i)) return false;
    if (isa<BranchInst>(i)) return false;
    if (isa<SwitchInst>(i)) return false;
    if (isa<IndirectBrInst>(i)) return false;
    if (isa<LandingPadInst>(i)) return false;
    if (isa<FuncletPadInst>(i)) return false;
    if (isa<DbgInfoIntrinsic>(i)) return false;

    if (auto* call = dyn_cast<CallBase>(&i))
    {
        if (opidx >= call->arg_size()) return false;
        if (call->paramHasAttr(opidx, Attribute::ImmArg)) return false;
        return true;
    }

    if (auto* gep = dyn_cast<GetElementPtrInst>(&i))
    {
        if (opidx == 0) return false;
        auto gti = gep_type_begin(gep);
        auto end = gep_type_end(gep);
        for (unsigned k = 1; k < opidx && gti != end; ++k, ++gti) {}
        if (gti == end) return false;
        return gti.getStructTypeOrNull() == nullptr;
    }

    return true;
}

static bool HasAnnotationTag(Function& f, const char* tag)
{
    Module* m = f.getParent();
    GlobalVariable* ga = m->getGlobalVariable("llvm.global.annotations");
    if (!ga || !ga->hasInitializer()) return false;
    auto* ca = dyn_cast<ConstantArray>(ga->getOperand(0));
    if (!ca) return false;

    for (unsigned i = 0; i < ca->getNumOperands(); ++i)
    {
        auto* cs = dyn_cast<ConstantStruct>(ca->getOperand(i));
        if (!cs || cs->getNumOperands() < 2) continue;
        if (cs->getOperand(0)->stripPointerCasts() != &f) continue;

        auto* annogv = dyn_cast<GlobalVariable>(cs->getOperand(1)->stripPointerCasts());
        if (!annogv || !annogv->hasInitializer()) continue;

        auto* cds = dyn_cast<ConstantDataSequential>(annogv->getInitializer());
        if (!cds || !cds->isString()) continue;

        if (strcmp(cds->getAsString().str().c_str(), tag) == 0)
            return true;
    }
    return false;
}

bool HasNoobfuscateAnnotation(Function& f)
{
    return HasAnnotationTag(f, "noobfus");
}

bool HasRetcryptAnnotation(Function& f)
{
    if (f.hasFnAttribute("retcrypt")) return true;
    return HasAnnotationTag(f, "retcrypt");
}

bool HasNoretcryptAnnotation(Function& f)
{
    return HasAnnotationTag(f, "noretcrypt");
}

std::vector<unsigned> GetDepmarkerAnnotationIds(Function& f)
{
    std::vector<unsigned> out;
    Module* m = f.getParent();
    GlobalVariable* ga = m->getGlobalVariable("llvm.global.annotations");
    if (!ga) return out;

    ConstantArray* ca = dyn_cast<ConstantArray>(ga->getOperand(0));
    if (!ca) return out;

    for (unsigned i = 0; i < ca->getNumOperands(); ++i)
    {
        ConstantStruct* cs = dyn_cast<ConstantStruct>(ca->getOperand(i));
        if (!cs) continue;
        if (cs->getOperand(0)->stripPointerCasts() != &f) continue;

        auto* annogv = dyn_cast<GlobalVariable>(cs->getOperand(1)->stripPointerCasts());
        if (!annogv || !annogv->hasInitializer()) continue;

        auto* cds = dyn_cast<ConstantDataSequential>(annogv->getInitializer());
        if (!cds || !cds->isString()) continue;

        unsigned n = ParseDepMarkerSuffixAnnot(cds->getAsString());
        if (!n) continue;
        bool already = false;
        for (unsigned x : out) if (x == n) { already = true; break; }
        if (!already) out.push_back(n);
    }
    return out;
}