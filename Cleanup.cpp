#include "Cleanup.h"
#include "Shared.h"

#include "llvm/ADT/APInt.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CallingConv.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"

#include <cstdint>
#include <vector>

using namespace llvm;

static int PickRotLocal()
{
    std::uint64_t m = NextMask();
    return (int)((m % 63u) + 1u);
}

static std::uint64_t PickKey()
{
    std::uint64_t k = NextMask();
    return k | 1;
}

static bool IsCleanupCandidate(Function& f, const DenseMap<Function*, KeyContext>& ctxs, const DenseSet<Function*>& ctordtorset)
{
    if (f.isDeclaration() || f.isIntrinsic()) return false;
    if (f.hasFnAttribute(Attribute::Naked)) return false;
    if (ctxs.count(&f)) return false;

    StringRef n = f.getName();
    if (IsOurHelperName(n)) return false;
    if (IsCrtSpecialName(n)) return false;
    if (IsCompilerHelperName(n)) return false;
    if (ctordtorset.contains(&f)) return false;

    if (f.hasFnAttribute(FaExternalThunk) || f.hasFnAttribute(FaPipelineHelper))
        return false;
    return true;
}

static bool IsOwnedGv(const GlobalVariable& gv)
{
    StringRef n = gv.getName();
    if (n.starts_with(PrefixTlskey)) return true;
    if (n.starts_with(PrefixDepmarker)) return true;
    if (n.starts_with(PrefixIndirection)) return true;
    if (n.starts_with(PrefixGateHash)) return true;
    if (n.starts_with(PrefixRetkey)) return true;
    if (n.starts_with(PrefixChain)) return true;
    if (n.starts_with(PrefixCallerkey)) return true;
    if (n.starts_with(PrefixCleanup)) return true;
    if (n.starts_with("llvm.")) return true;
    if (IsVtableGv(n)) return true;
    return false;
}

static bool IsOurScaffoldingCallee(StringRef name)
{
    if (name.starts_with(PrefixIndirection)) return true;
    if (name.starts_with(PrefixChain)) return true;
    if (name.starts_with(PrefixCallerkey)) return true;
    if (name.starts_with(PrefixTlskey)) return true;
    if (name.starts_with(PrefixRetkey)) return true;
    if (name.starts_with(PrefixGateHash)) return true;
    if (name.starts_with(PrefixDepmarker)) return true;
    if (name.starts_with(PrefixCleanup)) return true;
    if (name.starts_with("DependencyMarker_")) return true;
    return false;
}

static Function* ResolveCallee(CallBase* cb)
{
    if (Function* f = cb->getCalledFunction()) return f;
    Value* v = cb->getCalledOperand();
    if (!v) return nullptr;
    v = v->stripPointerCasts();
    for (unsigned i = 0; i < 8; ++i)
    {
        auto* ga = dyn_cast<GlobalAlias>(v);
        if (!ga) break;
        Constant* aliasee = ga->getAliasee();
        if (!aliasee) break;
        v = aliasee->stripPointerCasts();
    }
    return dyn_cast<Function>(v);
}

static void StringLiteralsArxDecryptAtEntryIn(Function& f)
{
    if (f.empty()) return;

    DenseSet<GlobalVariable*> seen;
    std::vector<GlobalVariable*> entries;

    for (BasicBlock& bb : f)
    {
        for (Instruction& i : bb)
        {
            for (unsigned oi = 0, oe = i.getNumOperands(); oi != oe; ++oi)
            {
                Value* op = i.getOperand(oi);
                Value* stripped = op;
                while (auto* gep = dyn_cast<GEPOperator>(stripped))
                    stripped = gep->getPointerOperand();

                auto* gv = dyn_cast<GlobalVariable>(stripped);
                if (!gv) continue;
                if (!gv->isConstant() || !gv->hasInitializer()) continue;
                if (IsOwnedGv(*gv)) continue;

                auto* arrt = dyn_cast<ArrayType>(gv->getValueType());
                if (!arrt) continue;
                Type* elemt = arrt->getElementType();
                if (!elemt->isIntegerTy(8) && !elemt->isIntegerTy(16)) continue;
                auto* init = dyn_cast<ConstantDataSequential>(gv->getInitializer());
                if (!init) continue;

                if (seen.insert(gv).second)
                    entries.push_back(gv);
            }
        }
    }

    if (entries.empty()) return;

    Type* i64 = Type::getInt64Ty(f.getContext());

    for (GlobalVariable* gv : entries)
    {
        auto* init = cast<ConstantDataSequential>(gv->getInitializer());
        auto* arrt = cast<ArrayType>(gv->getValueType());
        unsigned ebits = arrt->getElementType()->getIntegerBitWidth();
        unsigned esize = ebits / 8;
        unsigned nelems = init->getNumElements();
        unsigned total = nelems * esize;
        unsigned padded = ((total + 7) / 8) * 8;
        unsigned nchunks = padded / 8;
        unsigned elemsperchunk = 8 / esize;
        if (nchunks == 0) continue;

        const std::uint64_t key = PickKey();
        const int val1 = PickRotLocal();
        const int val2 = 64 - val1;

        IRBuilder<> be(&f.getEntryBlock(), f.getEntryBlock().begin());
        AllocaInst* slot = be.CreateAlloca(i64, ConstantInt::get(i64, nchunks), "__cleanup_strbuf");

        IRBuilder<> bs(f.getEntryBlock().getFirstNonPHIOrDbg());
        bs.SetInsertPoint(slot->getNextNode());

        Value* keyv = ConstantInt::get(i64, key);
        Value* keylau = OpaqueLaunder(keyv, bs, "__cleanup_strkey");
        if (auto* ins = dyn_cast<Instruction>(keylau))
            MarkMetadata(ins, MdKeySource);

        for (unsigned chunkidx = 0; chunkidx < nchunks; ++chunkidx)
        {
            std::uint64_t plain = 0;
            for (unsigned k = 0; k < elemsperchunk; ++k)
            {
                unsigned elemidx = chunkidx * elemsperchunk + k;
                if (elemidx >= nelems) break;
                std::uint64_t v = init->getElementAsInteger(elemidx);
                plain |= v << (k * ebits);
            }
            const std::uint64_t cipherct = ArxEncCt(plain, key, val1, val2);
            Value* cipherc = ConstantInt::get(i64, cipherct);
            Value* dec = ArxDecRt(bs, cipherc, keylau, val1, val2, "__cleanup_strdec");
            if (auto* ins = dyn_cast<Instruction>(dec))
                MarkMetadata(ins, MdDecrypt);
            Value* dst = bs.CreateGEP(i64, slot, ConstantInt::get(i64, chunkidx), "__cleanup_strdst");
            bs.CreateStore(dec, dst);
        }

        std::vector<Use*> toreplace;
        for (Use& u : gv->uses())
        {
            auto* useri = dyn_cast<Instruction>(u.getUser());
            if (!useri) continue;
            if (useri->getFunction() != &f) continue;
            toreplace.push_back(&u);
        }
        for (Use* u : toreplace)
            u->set(slot);
    }
}

static void DirectCallsArxIndirectionIn(Function& f)
{
    if (f.empty()) return;

    LLVMContext& c = f.getContext();
    Module* m = f.getParent();
    Type* i64ty = Type::getInt64Ty(c);
    Type* ptrty = PointerType::getUnqual(c);

    SmallVector<std::pair<CallBase*, Function*>, 32> toindirect;
    for (BasicBlock& bb : f)
    {
        for (Instruction& i : bb)
        {
            auto* call = dyn_cast<CallBase>(&i);
            if (!call) continue;
            if (isa<CallBrInst>(call) || call->isInlineAsm()) continue;
            if (auto* ci = dyn_cast<CallInst>(call))
                if (ci->isMustTailCall()) continue;

            Function* callee = ResolveCallee(call);
            if (!callee || callee->isIntrinsic()) continue;
            StringRef name = callee->getName();
            if (IsOurScaffoldingCallee(name)) continue;
            if (IsMsvcHelperCallee(name)) continue;
            if (callee->getFunctionType() != call->getFunctionType()) continue;

            toindirect.push_back({ call, callee });
        }
    }

    for (auto& e : toindirect)
    {
        CallBase* call = e.first;
        Function* callee = e.second;

        const std::uint64_t mask = PickKey();
        const std::uint64_t key = PickKey();
        const int val1 = PickRotLocal();
        const int val2 = 64 - val1;

        Constant* addr = ConstantExpr::getPtrToInt(callee, i64ty);
        Constant* maskc = ConstantInt::get(i64ty, mask);
        Constant* enc = ConstantExpr::getAdd(addr, maskc);

        auto* gv = new GlobalVariable(*m, i64ty, false, GlobalValue::PrivateLinkage, enc, "__cleanup_ind_call");
        gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);

        IRBuilder<> b(call);
        Value* loaded = b.CreateLoad(i64ty, gv, "__cleanup.c.load");
        Value* base = b.CreateSub(loaded, maskc, "__cleanup.c.base");

        Value* keyv = ConstantInt::get(i64ty, key);
        Value* keylau = OpaqueLaunder(keyv, b, "__cleanup.c.key");
        Value* arxenc = ArxEncRt(b, base, keylau, val1, val2, "__cleanup.c.enc");
        Value* arxdec = ArxDecRt(b, arxenc, keylau, val1, val2, "__cleanup.c.dec");

        Value* fn = b.CreateIntToPtr(arxdec, ptrty, "__cleanup.c.p");

        for (Value* v : { loaded, base, keylau, arxenc, arxdec, fn })
            if (auto* ins = dyn_cast<Instruction>(v))
                MarkMetadata(ins, MdKeyComposite);

        call->setCalledOperand(fn);
    }
}

static void IntegerConstantsXorMaskIn(Function& f)
{
    if (f.empty()) return;

    SmallVector<Instruction*, 256> worklist;
    for (BasicBlock& bb : f)
        for (Instruction& i : bb)
            worklist.push_back(&i);

    for (Instruction* i : worklist)
    {
        if (isa<PHINode>(i)) continue;
        if (HasMetadata(i, MdKeySource)) continue;
        if (HasMetadata(i, MdKeyComposite)) continue;
        if (HasMetadata(i, MdDecrypt)) continue;
        if (HasMetadata(i, MdKeyWrite)) continue;

        const unsigned nops = i->getNumOperands();
        for (unsigned op = 0; op < nops; ++op)
        {
            auto* cop = dyn_cast<ConstantInt>(i->getOperand(op));
            if (!cop) continue;

            Type* t = cop->getType();
            if (!t->isIntegerTy()) continue;
            unsigned bw = t->getIntegerBitWidth();
            if (bw != 32 && bw != 64) continue;
            if (!IsRewritableConstOp(*i, op)) continue;

            const std::uint64_t keyfull = PickKey();
            APInt kap(bw, keyfull, false);
            APInt encbits = cop->getValue() ^ kap;
            Constant* enc = ConstantInt::get(t, encbits);
            Constant* kct = ConstantInt::get(t, kap);

            Module* m = f.getParent();
            auto* keygv = new GlobalVariable(*m, t, true, GlobalValue::PrivateLinkage, kct, "__cleanup_k");
            keygv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);

            IRBuilder<> b(i);
            Value* keyload = b.CreateLoad(t, keygv, "__cleanup.k.key");
            Value* dec = b.CreateXor(enc, keyload, "__cleanup.k.dec");
            if (auto* ins = dyn_cast<Instruction>(keyload))
                MarkMetadata(ins, MdKeySource);
            if (auto* ins = dyn_cast<Instruction>(dec))
                MarkMetadata(ins, MdDecrypt);

            i->setOperand(op, dec);
        }
    }
}

void SweepUnprotectedFunctions(Module& m, const DenseMap<Function*, KeyContext>& ctxs, const CleanupConfig& cfg)
{
    DenseSet<Function*> ctordtorset;
    CollectGlobalCtorDtorFuncs(m, ctordtorset);

    SmallVector<Function*, 128> fnlist;
    for (Function& f : m) fnlist.push_back(&f);

    for (Function* f : fnlist)
    {
        if (!IsCleanupCandidate(*f, ctxs, ctordtorset)) continue;
        if (cfg.StringLiterals) StringLiteralsArxDecryptAtEntryIn(*f);
        if (cfg.DirectCalls) DirectCallsArxIndirectionIn(*f);
        if (cfg.IntegerConsts) IntegerConstantsXorMaskIn(*f);
    }
}