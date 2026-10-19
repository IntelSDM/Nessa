#include "KeySources.h"
#include "Shared.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include <algorithm>
#include <cstdint>
#include <vector>

using namespace llvm;

static constexpr std::uint64_t RetAddrTolerance = 64;

static void TakeOwnership(KeyContext& ctx, Value* v)
{
    if (auto* i = dyn_cast<Instruction>(v))
    {
        ctx.Own.insert(i);
        MarkMetadata(i, MdKeySource);
    }
}

static void TakeOwnershipComposite(KeyContext& ctx, Value* v)
{
    if (auto* i = dyn_cast<Instruction>(v))
    {
        ctx.Own.insert(i);
        MarkMetadata(i, MdKeyComposite);
    }
}

static void EnsurePrologue(Function& f, KeyContext& ctx)
{
    if (ctx.PrologueBb) return;

    LLVMContext& ctxllvm = f.getContext();
    BasicBlock* origentry = &f.getEntryBlock();
    if (origentry->getName() == "obf.entry")
    {
        ctx.PrologueBb = origentry;
        ctx.OrigEntryBb = origentry->getTerminator()->getSuccessor(0);
        return;
    }

    origentry->setName("obf.orig_entry");
    BasicBlock* newentry = BasicBlock::Create(ctxllvm, "obf.entry", &f, origentry);
    IRBuilder<> b(newentry);
    b.CreateBr(origentry);

    ctx.PrologueBb = newentry;
    ctx.OrigEntryBb = origentry;
}

static IRBuilder<> BuilderAtPrologueEnd(KeyContext& ctx)
{
    return IRBuilder<>(ctx.PrologueBb->getTerminator());
}

static void InstallChainSource(KeyContext& ctx, const CloneRegistry& reg)
{
    Function& f = *ctx.F;
    auto itk = reg.ChainK.find(&f);
    auto itc = reg.ChainC.find(&f);
    auto itidx = reg.ChainKeyArgIdx.find(&f);
    if (itk == reg.ChainK.end() || itc == reg.ChainC.end() || itidx == reg.ChainKeyArgIdx.end())
        return;

    const std::uint64_t kf = itk->second;
    const std::uint64_t cf = itc->second;
    Argument* kin = f.getArg(itidx->second);
    if (!kin || !kin->getType()->isIntegerTy(64)) return;

    IRBuilder<> b = BuilderAtPrologueEnd(ctx);
    Value* k = b.CreateXor(kin, ConstantInt::get(Type::getInt64Ty(f.getContext()), cf), "obf.k_chain");
    TakeOwnership(ctx, k);

    ctx.KChainRt = k;
    ctx.KChainCt = kf;
}

static void InstallCallerKeySource(KeyContext& ctx, const CloneRegistry& reg)
{
    Function& f = *ctx.F;
    auto it = reg.CallerKeyConsts.find(&f);
    if (it == reg.CallerKeyConsts.end() || it->second.empty()) return;

    IRBuilder<> b = BuilderAtPrologueEnd(ctx);
    Type* i64 = Type::getInt64Ty(f.getContext());

    Value* sumrt = nullptr;
    std::uint64_t sumct = 0;
    for (const ConstArgRecord& r : it->second)
    {
        if (r.ParamIdx >= f.arg_size()) continue;
        Argument* a = f.getArg(r.ParamIdx);
        if (!a->getType()->isIntegerTy()) continue;

        unsigned bw = a->getType()->getIntegerBitWidth();
        Value* zext;
        if (bw == 64)
            zext = a;
        else if (bw < 64)
        {
            zext = b.CreateZExt(a, i64, "obf.ckey.z64");
            TakeOwnership(ctx, zext);
        }
        else
        {
            zext = b.CreateTrunc(a, i64, "obf.ckey.tr64");
            TakeOwnership(ctx, zext);
        }

        if (!sumrt)
            sumrt = zext;
        else
        {
            sumrt = b.CreateAdd(sumrt, zext, "obf.ckey.sum");
            TakeOwnership(ctx, sumrt);
        }
        sumct += r.Value;
    }

    if (!sumrt) return;
    ctx.KCallerRt = sumrt;
    ctx.KCallerCt = sumct;
}

static GlobalVariable* GetOrCreateTlsSlot(Module& m)
{
    const char* name = "__tlskey_slot";
    if (GlobalVariable* gv = m.getNamedGlobal(name)) return gv;
    LLVMContext& ctx = m.getContext();
    Type* i64 = Type::getInt64Ty(ctx);
    auto* gv = new GlobalVariable(m, i64, false, GlobalValue::InternalLinkage, ConstantInt::get(i64, 0), name, nullptr, GlobalValue::GeneralDynamicTLSModel);
    gv->setAlignment(Align(8));
    return gv;
}

static void InstallTlsKeySource(KeyContext& ctx, const CloneRegistry& reg, Module& m)
{
    Function& f = *ctx.F;
    auto it = reg.TlsK.find(&f);
    if (it == reg.TlsK.end()) return;
    const std::uint64_t kf = it->second;

    GlobalVariable* slot = GetOrCreateTlsSlot(m);

    IRBuilder<> b = BuilderAtPrologueEnd(ctx);
    Type* i64 = Type::getInt64Ty(f.getContext());
    LoadInst* ld = b.CreateLoad(i64, slot, "obf.k_tls");
    ld->setVolatile(true);
    ld->setAlignment(Align(8));
    TakeOwnership(ctx, ld);

    ctx.KTlsRt = ld;
    ctx.KTlsCt = kf;

    SmallVector<CallInst*, 8> callers;
    for (User* u : f.users())
    {
        auto* ci = dyn_cast<CallInst>(u);
        if (!ci) continue;
        if (ci->getCalledOperand() != &f) continue;
        callers.push_back(ci);
    }
    for (CallInst* ci : callers)
    {
        IRBuilder<> cb(ci);
        auto* st = cb.CreateStore(ConstantInt::get(i64, kf), slot);
        st->setVolatile(true);
        st->setAlignment(Align(8));
        MarkMetadata(st, MdKeyWrite);
    }
}

static Constant* SplitCallsiteAndGetBa(CallBase* cb)
{
    Function* caller = cb->getFunction();
    BasicBlock* after = nullptr;

    if (auto* ci = dyn_cast<CallInst>(cb))
    {
        BasicBlock* callerbb = ci->getParent();
        Instruction* splitat = ci->getNextNode();
        if (!splitat) return nullptr;
        after = SplitBlock(callerbb, splitat, (DomTreeUpdater*)nullptr, nullptr, nullptr, "obf.ret_after");
        ci->setTailCallKind(CallInst::TCK_NoTail);
    }
    else if (auto* ii = dyn_cast<InvokeInst>(cb))
    {
        after = SplitEdge(ii->getParent(), ii->getNormalDest(), nullptr, nullptr, nullptr);
        after->setName("obf.ret_after");
    }
    else
    {
        return nullptr;
    }
    return BlockAddress::get(caller, after);
}

static void InstallRetKeySource(KeyContext& ctx, CloneRegistry& reg)
{
    Function& f = *ctx.F;
    MergedClone* mc = nullptr;
    for (MergedClone& m : reg.Clones)
    {
        if (m.Clone == &f && (m.Schemes & SchemeRetKey)) { mc = &m; break; }
    }
    if (!mc || !mc->Callsite || !mc->Callsite->getParent()) return;

    auto itba = reg.RetCallerBa.find(&f);
    Constant* ba = (itba != reg.RetCallerBa.end()) ? itba->second : nullptr;
    if (!ba)
    {
        ba = SplitCallsiteAndGetBa(mc->Callsite);
        if (!ba) return;
        reg.RetCallerBa[&f] = ba;
    }

    LLVMContext& ctxllvm = f.getContext();
    Type* i64 = Type::getInt64Ty(ctxllvm);

    IRBuilder<> b = BuilderAtPrologueEnd(ctx);
    Function* rafn = Intrinsic::getDeclaration(f.getParent(), Intrinsic::returnaddress);
    Value* ra = b.CreateCall(rafn, { b.getInt32(0) }, "obf.ret.ra");
    Value* ra64 = b.CreatePtrToInt(ra, i64, "obf.ret.ra64");
    TakeOwnership(ctx, ra);
    TakeOwnership(ctx, ra64);

    Value* ba64rt = b.CreatePtrToInt(ba, i64, "obf.ret.ba64rt");
    TakeOwnership(ctx, ba64rt);

    Value* rawdiff = b.CreateSub(ra64, ba64rt, "obf.ret.rawdiff");
    Value* biased = b.CreateAdd(rawdiff, ConstantInt::get(i64, RetAddrTolerance), "obf.ret.bias");
    Value* issmall = b.CreateICmpULT(biased, ConstantInt::get(i64, 2 * RetAddrTolerance), "obf.ret.small");
    Value* keydiff = b.CreateSelect(issmall, ConstantInt::get(i64, 0), rawdiff, "obf.ret.keydiff");
    TakeOwnership(ctx, rawdiff);
    TakeOwnership(ctx, biased);
    TakeOwnership(ctx, issmall);
    TakeOwnership(ctx, keydiff);

    ctx.KRetRt = ra64;
    ctx.KeyDiffRetRt = keydiff;
    ctx.KRetCtCexpr = ConstantExpr::getPtrToInt(ba, i64);
}

struct DepMarkerShare
{
    GlobalVariable* Slot = nullptr;
    Function* Anchor = nullptr;
    std::uint64_t ShareValue = 0;
    std::uint64_t KeyMask = 0;
    int RotKa = 0;
    int RotKb = 0;
    std::uint64_t PtrMask = 0;
    int RotPa = 0;
    int RotPb = 0;
    unsigned MarkerId = 0;
    Function* ParentFn = nullptr;
};

struct DepMarkerContext
{
    DenseMap<unsigned, Function*> IdToMarker;
    std::vector<std::pair<Function*, std::vector<unsigned>>> AnnotatedFns;
    DenseMap<Function*, std::uint64_t> FnKMaster;
    DenseMap<Function*, std::vector<DepMarkerShare>> FnShares;
    DenseMap<unsigned, std::vector<DepMarkerShare>> IdToShares;
};

static int PickRotLocal()
{
    std::uint64_t m = NextMask();
    return (int)((m % 63u) + 1u);
}

static void BuildDepMarkerContext(Module& m, DepMarkerContext& dmc)
{
    for (Function& f : m)
    {
        if (f.isDeclaration()) continue;
        auto ids = GetDepmarkerAnnotationIds(f);
        if (ids.empty()) continue;
        if (HasNoobfuscateAnnotation(f)) continue;
        dmc.AnnotatedFns.push_back({ &f, std::move(ids) });
    }

    for (Function& f : m)
    {
        unsigned id = GetDepmarkerNameId(f.getName());
        if (!id || dmc.IdToMarker.count(id)) continue;
        dmc.IdToMarker[id] = &f;
        f.addFnAttr(Attribute::NoInline);
        f.removeFnAttr(Attribute::AlwaysInline);
    }

    Type* i64 = Type::getInt64Ty(m.getContext());

    for (auto& fe : dmc.AnnotatedFns)
    {
        Function* f = fe.first;
        const std::vector<unsigned>& ids = fe.second;

        bool allpresent = true;
        for (unsigned id : ids)
            if (!dmc.IdToMarker.count(id)) { allpresent = false; break; }
        if (!allpresent) continue;

        const size_t n = ids.size();
        const std::uint64_t kmaster = NextMask();
        dmc.FnKMaster[f] = kmaster;

        std::vector<DepMarkerShare> shares(n);
        std::uint64_t accum = 0;
        for (size_t i = 0; i + 1 < n; ++i)
        {
            shares[i].ShareValue = NextMask();
            accum ^= shares[i].ShareValue;
        }
        shares[n - 1].ShareValue = kmaster ^ accum;

        for (size_t i = 0; i < n; ++i)
        {
            DepMarkerShare& sh = shares[i];
            sh.KeyMask = NextMask();
            sh.PtrMask = NextMask();
            sh.RotKa = PickRotLocal(); sh.RotKb = 64 - sh.RotKa;
            sh.RotPa = PickRotLocal(); sh.RotPb = 64 - sh.RotPa;
            sh.Anchor = dmc.IdToMarker.find(ids[i])->second;
            sh.MarkerId = ids[i];
            sh.ParentFn = f;

            std::string tail = ("_" + f->getName() + "_" + std::to_string(ids[i])).str();
            sh.Slot = new GlobalVariable(m, i64, false, GlobalValue::PrivateLinkage, ConstantInt::get(i64, 0), ("__dmp_slot" + Twine(tail)).str());
        }

        dmc.FnShares[f] = shares;
        for (const DepMarkerShare& sh : shares)
            dmc.IdToShares[sh.MarkerId].push_back(sh);
    }
}

static void InstallDepMarkerSource(KeyContext& ctx, Module& m, const DepMarkerContext& dmc)
{
    Function& f = *ctx.F;
    auto it = dmc.FnShares.find(&f);
    if (it == dmc.FnShares.end() || it->second.empty()) return;
    const std::vector<DepMarkerShare>& shares = it->second;

    LLVMContext& ctxllvm = f.getContext();
    Type* i64 = Type::getInt64Ty(ctxllvm);
    Type* ptrt = PointerType::getUnqual(ctxllvm);

    IRBuilder<> b = BuilderAtPrologueEnd(ctx);

    Value* kmasterrt = nullptr;
    for (size_t i = 0; i < shares.size(); ++i)
    {
        const DepMarkerShare& sh = shares[i];

        Function* slotanc = PickAnchor(sh.Anchor);
        Value* slotptr = IndirectSlotAddr(b, sh.Slot, slotanc, "dmp.sl");
        Value* enc = b.CreateLoad(i64, slotptr, "dmp.enc");

        Function* pmanc = PickAnchor(sh.Anchor);
        Value* pm = EmitInlineEncoded(b, pmanc, sh.PtrMask, "dmp.pm");

        Value* ptrint = ArxDecRt(b, enc, pm, sh.RotPa, sh.RotPb, "dmp.p");
        Value* heap = b.CreateIntToPtr(ptrint, ptrt, "dmp.heap");
        Value* share = b.CreateLoad(i64, heap, "dmp.share");

        for (Value* v : { slotptr, enc, pm, ptrint, heap, share })
            if (auto* ins = dyn_cast<Instruction>(v))
            {
                ctx.Own.insert(ins);
                MarkMetadata(ins, MdKeySource);
            }

        if (i == 0)
            kmasterrt = share;
        else
        {
            kmasterrt = b.CreateXor(kmasterrt, share, "dmp.master");
            if (auto* ins = dyn_cast<Instruction>(kmasterrt))
            {
                ctx.Own.insert(ins);
                MarkMetadata(ins, MdKeySource);
            }
        }
    }

    ctx.KDepmarkerRt = kmasterrt;
    ctx.KDepmarkerCt = dmc.FnKMaster.lookup(&f);
    (void)m;
}

static FunctionCallee GetMallocDecl(Module& m)
{
    LLVMContext& c = m.getContext();
    Type* ptrt = PointerType::getUnqual(c);
    Type* i64 = Type::getInt64Ty(c);
    FunctionType* ft = FunctionType::get(ptrt, { i64 }, false);
    return m.getOrInsertFunction("malloc", ft);
}

static void EmitMarkerInit(CallBase* call, FunctionCallee mallocfn, ArrayRef<DepMarkerShare> entries)
{
    LLVMContext& ctx = call->getContext();
    Type* i64 = Type::getInt64Ty(ctx);

    IRBuilder<> b(call);
    for (const DepMarkerShare& e : entries)
    {
        Value* heap = b.CreateCall(mallocfn, { b.getInt64(8) }, "dmp.heap");

        const std::uint64_t kenc = ArxEncCt(e.ShareValue, e.KeyMask, e.RotKa, e.RotKb);
        Function* keanc = PickAnchor(e.Anchor);
        Function* kmanc = PickAnchor(e.Anchor);
        Function* pmanc = PickAnchor(e.Anchor);
        Value* ke = EmitInlineEncoded(b, keanc, kenc, "dmp.ke");
        Value* km = EmitInlineEncoded(b, kmanc, e.KeyMask, "dmp.km");
        Value* k = ArxDecRt(b, ke, km, e.RotKa, e.RotKb, "dmp.k");
        b.CreateStore(k, heap);

        Value* pm = EmitInlineEncoded(b, pmanc, e.PtrMask, "dmp.pm");
        Value* pint = b.CreatePtrToInt(heap, i64, "dmp.pi");
        Value* penc = ArxEncRt(b, pint, pm, e.RotPa, e.RotPb, "dmp.p");

        Function* slotanc = PickAnchor(e.Anchor);
        Value* slotptr = IndirectSlotAddr(b, e.Slot, slotanc, "dmp.sl");
        b.CreateStore(penc, slotptr);

        for (Value* v : { heap, ke, km, k, pm, pint, penc, slotptr })
            if (auto* ins = dyn_cast<Instruction>(v))
                MarkMetadata(ins, MdKeySource);
    }
}

static void ProcessMarkerCallSites(Module& m, DepMarkerContext& dmc)
{
    if (dmc.IdToShares.empty()) return;
    FunctionCallee mallocfn = GetMallocDecl(m);

    for (auto& kv : dmc.IdToShares)
    {
        unsigned id = kv.first;
        ArrayRef<DepMarkerShare> shares = kv.second;
        auto itmarker = dmc.IdToMarker.find(id);
        if (itmarker == dmc.IdToMarker.end()) continue;

        Function* markerfn = itmarker->second;

        std::vector<CallBase*> callsites;
        for (User* u : markerfn->users())
            if (auto* cb = dyn_cast<CallBase>(u))
                if (cb->getCalledFunction() == markerfn)
                    callsites.push_back(cb);

        for (CallBase* call : callsites)
        {
            EmitMarkerInit(call, mallocfn, shares);
            call->eraseFromParent();
        }
    }
}

static Value* WidenToI64(Value* v, IRBuilder<>& b, const Twine& tag)
{
    if (!v) return nullptr;
    LLVMContext& c = b.getContext();
    Type* i64 = Type::getInt64Ty(c);
    Type* t = v->getType();
    if (!t) return nullptr;
    if (t == i64) return v;
    if (t->isIntegerTy())
    {
        unsigned bw = t->getIntegerBitWidth();
        if (bw > 64) return b.CreateTrunc(v, i64, tag + ".tr64");
        if (bw < 1) return nullptr;
        return b.CreateZExt(v, i64, tag + ".z64");
    }
    if (t->isFloatTy())
    {
        Value* v32 = b.CreateBitCast(v, Type::getInt32Ty(c), tag + ".bc32");
        return b.CreateZExt(v32, i64, tag + ".z64");
    }
    if (t->isDoubleTy()) return b.CreateBitCast(v, i64, tag + ".bc64");
    return nullptr;
}

static Value* EmitRuntimeKdf(Value* v, IRBuilder<>& b)
{
    Value* v64 = WidenToI64(v, b, "obf.kv");
    if (!v64) return nullptr;
    Value* vop = OpaqueLaunder(v64, b, "obf.kv.op");
    Type* i64 = Type::getInt64Ty(b.getContext());
    Value* k = ConstantInt::get(i64, Arx.KdfSalt);
    return ArxEncRt(b, vop, k, Arx.KdfVal1, Arx.KdfVal2, "obf.k");
}

struct KsLivePointerSet
{
    DenseSet<const Value*> Values;
    DenseSet<const BasicBlock*> Blocks;
};

static void BuildLivePointerSet(Function& f, KsLivePointerSet& out)
{
    for (Argument& a : f.args()) out.Values.insert(&a);
    for (BasicBlock& bb : f)
    {
        out.Blocks.insert(&bb);
        for (Instruction& i : bb) out.Values.insert(&i);
    }
}

static void InstallEqualityGateSource(KeyContext& ctx, const GateTable& gatetable)
{
    Function& f = *ctx.F;
    KsLivePointerSet live;
    BuildLivePointerSet(f, live);

    for (const GateRegion& r : gatetable.Regions)
    {
        if (r.F != &f) continue;
        if (!r.SplitBb || !live.Blocks.contains(r.SplitBb)) continue;
        if (!r.V || !live.Values.contains(r.V)) continue;

        RegionKeyLanes lanes;
        lanes.SiteId = r.SiteId;

        if (r.Kind == GateKind::String || r.Kind == GateKind::WString)
        {
            if (!r.StringHashCall || !live.Values.contains(r.StringHashCall))
                continue;
            lanes.KGateRt = r.StringHashCall;
            lanes.KGateCtPlain = r.CBits;
        }
        else
        {
            auto ip = r.SplitBb->getFirstInsertionPt();
            if (ip == r.SplitBb->end()) continue;

            Type* vt = r.V->getType();
            if (!vt) continue;
            bool typeok = false;
            if (vt->isIntegerTy())
            {
                unsigned bw = vt->getIntegerBitWidth();
                typeok = (bw >= 1 && bw <= 128);
            }
            else if (vt->isFloatTy() || vt->isDoubleTy())
            {
                typeok = true;
            }
            if (!typeok) continue;

            IRBuilder<> b(&*ip);
            Value* k = EmitRuntimeKdf(r.V, b);
            if (!k) continue;
            TakeOwnership(ctx, k);
            lanes.KGateRt = k;
            lanes.KGateCtPlain = CompileKdf(r.CBits);
        }
        ctx.Regions[r.SiteId] = lanes;
    }
}

void InstallKeySources(Module& m, const FunctionCatalog&, const CloneRegistry& registry, const GateTable& gatetable, DenseMap<Function*, KeyContext>& outctxs, const KeyInstallConfig& cfg)
{
    DepMarkerContext dmc;
    if (cfg.InstallDepMarker)
        BuildDepMarkerContext(m, dmc);

    CloneRegistry& reg = const_cast<CloneRegistry&>(registry);

    DenseSet<Function*> fnsneedingctx;
    for (const MergedClone& mc : registry.Clones)
        if (mc.Clone) fnsneedingctx.insert(mc.Clone);
    for (const GateRegion& r : gatetable.Regions)
        if (r.F) fnsneedingctx.insert(r.F);
    for (auto& kv : dmc.FnShares)
        if (kv.first) fnsneedingctx.insert(kv.first);

    std::vector<Function*> fnlist(fnsneedingctx.begin(), fnsneedingctx.end());
    for (Function* f : fnlist)
    {
        if (!f || f->isDeclaration() || f->empty()) continue;

        KeyContext ctx;
        ctx.F = f;
        ctx.Schemes = reg.CloneSchemes.lookup(f);

        EnsurePrologue(*f, ctx);
        if (!ctx.PrologueBb) continue;

        if ((ctx.Schemes & SchemeChain) && cfg.InstallChain) InstallChainSource(ctx, reg);
        if ((ctx.Schemes & SchemeCallerKey) && cfg.InstallCallerKey) InstallCallerKeySource(ctx, reg);
        if ((ctx.Schemes & SchemeTlsKey) && cfg.InstallTlsKey) InstallTlsKeySource(ctx, reg, m);
        if ((ctx.Schemes & SchemeRetKey) && cfg.InstallRetKey) InstallRetKeySource(ctx, reg);
        if (cfg.InstallDepMarker) InstallDepMarkerSource(ctx, m, dmc);
        if (cfg.InstallEqualityGate) InstallEqualityGateSource(ctx, gatetable);

        if (ctx.KRetRt) ctx.HasRetKeyLayer = true;

        outctxs[f] = std::move(ctx);
    }

    if (cfg.InstallDepMarker)
        ProcessMarkerCallSites(m, dmc);
}

void DeriveCompositeKeys(Module& m, DenseMap<Function*, KeyContext>& ctxs, const GateTable&)
{
    LLVMContext& mctx = m.getContext();
    Type* i64 = Type::getInt64Ty(mctx);
    Type* i32 = Type::getInt32Ty(mctx);
    Type* i16 = Type::getInt16Ty(mctx);
    Type* i8 = Type::getInt8Ty(mctx);

    for (auto& kv : ctxs)
    {
        KeyContext& ctx = kv.second;
        Function* f = ctx.F;
        if (!f || f->isDeclaration()) continue;

        ctx.KFnCtPlain = ctx.KChainCt ^ ctx.KCallerCt ^ ctx.KTlsCt ^ ctx.KDepmarkerCt;

        Constant* plainc = ConstantInt::get(i64, ctx.KFnCtPlain);
        ctx.KFnCtCexpr = ctx.KRetCtCexpr ? ConstantExpr::getXor(plainc, ctx.KRetCtCexpr) : plainc;

        IRBuilder<> b = ctx.PrologueBb ? IRBuilder<>(ctx.PrologueBb->getTerminator()) : IRBuilder<>(&f->getEntryBlock().front());

        Value* krt = nullptr;
        auto foldin = [&](Value* src)
        {
            if (!src) return;
            if (!krt) { krt = src; return; }
            krt = b.CreateXor(krt, src, "obf.K_fn_rt");
            TakeOwnershipComposite(ctx, krt);
        };
        foldin(ctx.KChainRt);
        foldin(ctx.KCallerRt);
        foldin(ctx.KTlsRt);
        foldin(ctx.KDepmarkerRt);

        if (!krt) krt = ConstantInt::get(i64, 0);
        ctx.KFnRt = krt;

        if (auto* ins = dyn_cast<Instruction>(krt))
        {
            IRBuilder<> b2(ins->getNextNode());
            ctx.KFnRt32 = b2.CreateTrunc(krt, i32, "obf.K_fn_rt32");
            ctx.KFnRt16 = b2.CreateTrunc(krt, i16, "obf.K_fn_rt16");
            ctx.KFnRt8 = b2.CreateTrunc(krt, i8, "obf.K_fn_rt8");
        }
        else if (isa<Argument>(krt))
        {
            IRBuilder<> b2(ctx.PrologueBb->getTerminator());
            ctx.KFnRt32 = b2.CreateTrunc(krt, i32, "obf.K_fn_rt32");
            ctx.KFnRt16 = b2.CreateTrunc(krt, i16, "obf.K_fn_rt16");
            ctx.KFnRt8 = b2.CreateTrunc(krt, i8, "obf.K_fn_rt8");
        }
        else if (auto* kc = dyn_cast<Constant>(krt))
        {
            ctx.KFnRt32 = ConstantExpr::getTrunc(kc, i32);
            ctx.KFnRt16 = ConstantExpr::getTrunc(kc, i16);
            ctx.KFnRt8 = ConstantExpr::getTrunc(kc, i8);
        }
        else
        {
            continue;
        }
        TakeOwnershipComposite(ctx, ctx.KFnRt32);
        TakeOwnershipComposite(ctx, ctx.KFnRt16);
        TakeOwnershipComposite(ctx, ctx.KFnRt8);

        {
            IRBuilder<> b3(ctx.PrologueBb->getTerminator());
            ctx.KeyDiffFnPlain = b3.CreateSub(ConstantInt::get(i64, ctx.KFnCtPlain), ctx.KFnRt, "obf.key_diff_fn");
            TakeOwnershipComposite(ctx, ctx.KeyDiffFnPlain);
        }

        for (auto& regkv : ctx.Regions)
        {
            RegionKeyLanes& lanes = regkv.second;
            lanes.KRegionCtPlain = ctx.KFnCtPlain ^ lanes.KGateCtPlain;

            Constant* regc = ConstantInt::get(i64, lanes.KRegionCtPlain);
            lanes.KRegionCtCexpr = ctx.KRetCtCexpr ? ConstantExpr::getXor(regc, ctx.KRetCtCexpr) : (Constant*)regc;

            if (!lanes.KGateRt) continue;
            Instruction* kgateinst = dyn_cast<Instruction>(lanes.KGateRt);
            if (!kgateinst) continue;
            IRBuilder<> br(kgateinst->getNextNode());
            Value* krr = br.CreateXor(ctx.KFnRt, lanes.KGateRt, "obf.K_region_rt");
            Value* kd = br.CreateSub(ConstantInt::get(i64, lanes.KRegionCtPlain), krr, "obf.key_diff_region");
            TakeOwnershipComposite(ctx, krr);
            TakeOwnershipComposite(ctx, kd);
            lanes.KRegionRt = krr;
            lanes.KeyDiffRegionPlain = kd;
        }
    }
}