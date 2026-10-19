#include "Encryption.h"
#include "Shared.h"

#include "llvm/ADT/APInt.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

#include <cstdint>

using namespace llvm;

static constexpr unsigned PrologueMaxFragments = 8;
static constexpr unsigned PrologueMinInsts = 4;

static bool WidthLanes(const KeyContext& ctx, unsigned bw, Value*& outrt, Constant*& outctcexprtruncd, LLVMContext& lc)
{
    Type* ty = nullptr;
    switch (bw)
    {
        case 8: ty = Type::getInt8Ty(lc); outrt = ctx.KFnRt8; break;
        case 16: ty = Type::getInt16Ty(lc); outrt = ctx.KFnRt16; break;
        case 32: ty = Type::getInt32Ty(lc); outrt = ctx.KFnRt32; break;
        case 64: ty = Type::getInt64Ty(lc); outrt = ctx.KFnRt; break;
        default: return false;
    }
    if (!outrt || !ctx.KFnCtCexpr) return false;
    outctcexprtruncd = ConstantExpr::getTrunc(ctx.KFnCtCexpr, ty);
    return outctcexprtruncd != nullptr;
}

static bool PickRtLane(const KeyContext& ctx, unsigned bw, Value*& outrt)
{
    switch (bw)
    {
        case 8: outrt = ctx.KFnRt8; break;
        case 16: outrt = ctx.KFnRt16; break;
        case 32: outrt = ctx.KFnRt32; break;
        case 64: outrt = ctx.KFnRt; break;
        default: outrt = nullptr; return false;
    }
    return outrt != nullptr;
}

static bool IsScaffolding(const Instruction* i, const KeyContext& ctx)
{
    if (!i) return false;
    if (ctx.Own.count(const_cast<Instruction*>(i))) return true;
    if (HasMetadata(i, MdKeySource)) return true;
    if (HasMetadata(i, MdKeyComposite)) return true;
    if (HasMetadata(i, MdKeyWrite)) return true;
    if (HasMetadata(i, MdDecrypt)) return true;
    return false;
}

static bool IsPrologueOrFrag(const BasicBlock& bb, const KeyContext& ctx)
{
    if (&bb == ctx.PrologueBb) return true;
    return bb.getName().starts_with("obf.prologue_frag");
}

static void EncryptIntegerConstantsIn(Function& f, KeyContext& ctx)
{
    if (!ctx.PrologueBb || !ctx.KFnCtCexpr || !ctx.KFnRt) return;
    if (ctx.HasRetKeyLayer) return;

    LLVMContext& lc = f.getContext();

    SmallVector<Instruction*, 256> worklist;
    for (BasicBlock& bb : f)
    {
        if (&bb == ctx.PrologueBb) continue;
        for (Instruction& i : bb) worklist.push_back(&i);
    }

    for (Instruction* i : worklist)
    {
        if (IsScaffolding(i, ctx)) continue;
        if (isa<PHINode>(i)) continue;

        const unsigned nops = i->getNumOperands();
        for (unsigned op = 0; op < nops; ++op)
        {
            auto* c = dyn_cast<ConstantInt>(i->getOperand(op));
            if (!c) continue;

            Type* t = c->getType();
            if (!t->isIntegerTy()) continue;
            unsigned bw = t->getIntegerBitWidth();
            if (bw != 8 && bw != 16 && bw != 32 && bw != 64) continue;
            if (!IsRewritableConstOp(*i, op)) continue;

            Value* krtw = nullptr;
            Constant* kctw = nullptr;
            if (!WidthLanes(ctx, bw, krtw, kctw, lc)) continue;
            auto* kctci = dyn_cast<ConstantInt>(kctw);
            if (!kctci) continue;

            APInt encbits = c->getValue() ^ kctci->getValue();
            Constant* enc = ConstantInt::get(c->getType(), encbits);

            IRBuilder<> b(i);
            Value* dec = b.CreateXor(enc, krtw, "obf.int.dec");
            if (auto* deci = dyn_cast<Instruction>(dec))
                MarkMetadata(deci, MdDecrypt);
            i->setOperand(op, dec);
        }
    }
}

static void EncryptPhiOperandsIn(Function& f, KeyContext& ctx)
{
    if (!ctx.PrologueBb || !ctx.KFnRt) return;
    if (ctx.HasRetKeyLayer) return;

    SmallVector<PHINode*, 32> phis;
    for (BasicBlock& bb : f)
    {
        if (&bb == ctx.PrologueBb) continue;
        for (Instruction& i : bb)
        {
            auto* phi = dyn_cast<PHINode>(&i);
            if (!phi) break;
            phis.push_back(phi);
        }
    }

    for (PHINode* phi : phis)
    {
        if (IsScaffolding(phi, ctx)) continue;
        Type* phity = phi->getType();
        if (!phity->isIntegerTy()) continue;
        unsigned bw = phity->getIntegerBitWidth();
        if (bw != 8 && bw != 16 && bw != 32 && bw != 64) continue;

        Value* krtw = nullptr;
        if (!PickRtLane(ctx, bw, krtw)) continue;

        const unsigned ninc = phi->getNumIncomingValues();
        for (unsigned i = 0; i < ninc; ++i)
        {
            auto* c = dyn_cast<ConstantInt>(phi->getIncomingValue(i));
            if (!c) continue;

            BasicBlock* pred = phi->getIncomingBlock(i);
            if (!pred || pred == ctx.PrologueBb) continue;
            Instruction* term = pred->getTerminator();
            if (!term) continue;
            if (isa<InvokeInst>(term) || isa<CallBrInst>(term)) continue;

            APInt kct(bw, (uint64_t)ctx.KFnCtPlain, false);
            APInt encbits = c->getValue() + kct;
            Constant* enc = ConstantInt::get(phity, encbits);

            IRBuilder<> b(term);
            Value* dec = b.CreateSub(enc, krtw, "obf.phi.dec");
            if (auto* deci = dyn_cast<Instruction>(dec))
                MarkMetadata(deci, MdDecrypt);
            phi->setIncomingValue(i, dec);
        }
    }
}

static void EncryptGepIndicesIn(Function& f, KeyContext& ctx)
{
    if (!ctx.PrologueBb || !ctx.KFnRt) return;
    if (ctx.HasRetKeyLayer) return;

    SmallVector<GetElementPtrInst*, 64> geps;
    for (BasicBlock& bb : f)
    {
        if (&bb == ctx.PrologueBb) continue;
        for (Instruction& i : bb)
            if (auto* gep = dyn_cast<GetElementPtrInst>(&i))
                geps.push_back(gep);
    }

    for (GetElementPtrInst* gep : geps)
    {
        if (IsScaffolding(gep, ctx)) continue;

        unsigned opidx = 1;
        for (auto gi = gep_type_begin(gep); gi != gep_type_end(gep); ++gi, ++opidx)
        {
            if (opidx >= gep->getNumOperands()) break;
            if (gi.isStruct()) continue;

            auto* c = dyn_cast<ConstantInt>(gep->getOperand(opidx));
            if (!c) continue;
            Type* t = c->getType();
            unsigned bw = t->getIntegerBitWidth();
            if (bw != 8 && bw != 16 && bw != 32 && bw != 64) continue;

            Value* krtw = nullptr;
            if (!PickRtLane(ctx, bw, krtw)) continue;

            APInt kct(bw, (uint64_t)ctx.KFnCtPlain, false);
            APInt encbits = c->getValue() + kct;
            Constant* enc = ConstantInt::get(t, encbits);

            IRBuilder<> b(gep);
            Value* dec = b.CreateSub(enc, krtw, "obf.gep.dec");
            if (auto* deci = dyn_cast<Instruction>(dec))
                MarkMetadata(deci, MdDecrypt);
            gep->setOperand(opidx, dec);
        }
    }
}

static void EncryptSwitchCasesIn(Function& f, KeyContext& ctx)
{
    if (!ctx.PrologueBb || !ctx.KFnRt) return;
    if (ctx.HasRetKeyLayer) return;

    SmallVector<SwitchInst*, 8> switches;
    for (BasicBlock& bb : f)
    {
        if (&bb == ctx.PrologueBb) continue;
        if (auto* sw = dyn_cast<SwitchInst>(bb.getTerminator()))
            switches.push_back(sw);
    }

    for (SwitchInst* sw : switches)
    {
        if (IsScaffolding(sw, ctx)) continue;
        Value* cond = sw->getCondition();
        Type* condty = cond->getType();
        if (!condty->isIntegerTy()) continue;
        unsigned bw = condty->getIntegerBitWidth();
        if (bw != 8 && bw != 16 && bw != 32 && bw != 64) continue;
        if (sw->getNumCases() == 0) continue;

        Value* krtw = nullptr;
        if (!PickRtLane(ctx, bw, krtw)) continue;

        IRBuilder<> b(sw);
        Value* enccond = b.CreateAdd(cond, krtw, "obf.sw.enccond");
        if (auto* enci = dyn_cast<Instruction>(enccond))
            MarkMetadata(enci, MdDecrypt);
        sw->setCondition(enccond);

        APInt kct(bw, (uint64_t)ctx.KFnCtPlain, false);
        LLVMContext& ctxllvm = f.getContext();
        for (auto& ch : sw->cases())
        {
            APInt encbits = ch.getCaseValue()->getValue() + kct;
            ch.setValue(ConstantInt::get(ctxllvm, encbits));
        }
    }
}

enum class CallResolveKind
{
    Direct,
    StripCast,
    Alias,
    Unresolved
};

static Function* ResolveCallee(CallBase* cb, CallResolveKind& kind)
{
    if (Function* f = cb->getCalledFunction())
    {
        kind = CallResolveKind::Direct;
        return f;
    }
    Value* v = cb->getCalledOperand();
    if (!v) { kind = CallResolveKind::Unresolved; return nullptr; }

    Value* stripped = v->stripPointerCasts();
    bool strippedchanged = (stripped != v);
    v = stripped;

    bool wentthroughalias = false;
    for (unsigned i = 0; i < 8; ++i)
    {
        auto* ga = dyn_cast<GlobalAlias>(v);
        if (!ga) break;
        Constant* aliasee = ga->getAliasee();
        if (!aliasee) break;
        v = aliasee->stripPointerCasts();
        wentthroughalias = true;
    }

    auto* f = dyn_cast<Function>(v);
    if (!f) { kind = CallResolveKind::Unresolved; return nullptr; }
    kind = wentthroughalias ? CallResolveKind::Alias : strippedchanged ? CallResolveKind::StripCast : CallResolveKind::Direct;
    return f;
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
    if (name.starts_with("DependencyMarker_")) return true;
    return false;
}

static uint64_t PerSiteMask()
{
    uint64_t m = NextMask();
    return m == 0 ? 1 : m;
}

static void IndirectDirectCallsIn(Function& f, KeyContext& ctx)
{
    if (!ctx.PrologueBb || !ctx.KeyDiffFnPlain) return;
    if (ctx.HasRetKeyLayer) return;

    LLVMContext& ctxllvm = f.getContext();
    Module* m = f.getParent();
    Type* i64ty = Type::getInt64Ty(ctxllvm);
    Type* ptrty = PointerType::getUnqual(ctxllvm);

    SmallVector<std::pair<CallBase*, Function*>, 32> toindirect;
    for (BasicBlock& bb : f)
    {
        if (IsPrologueOrFrag(bb, ctx)) continue;
        for (Instruction& i : bb)
        {
            if (IsScaffolding(&i, ctx)) continue;
            auto* call = dyn_cast<CallBase>(&i);
            if (!call) continue;
            if (isa<CallBrInst>(call) || call->isInlineAsm()) continue;
            if (auto* ci = dyn_cast<CallInst>(call))
                if (ci->isMustTailCall()) continue;

            CallResolveKind rkind;
            Function* callee = ResolveCallee(call, rkind);
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

        uint64_t mask = PerSiteMask();
        Constant* addr = ConstantExpr::getPtrToInt(callee, i64ty);
        Constant* maskc = ConstantInt::get(i64ty, mask);
        Constant* enc = ConstantExpr::getAdd(addr, maskc);

        auto* gv = new GlobalVariable(*m, i64ty, false, GlobalValue::PrivateLinkage, enc, "__obf_ind_call");
        gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);

        IRBuilder<> b(call);
        Value* loaded = b.CreateLoad(i64ty, gv, "obf.indcall.load");
        Value* effmask = b.CreateAdd(maskc, ctx.KeyDiffFnPlain, "obf.indcall.emask");
        Value* dec = b.CreateSub(loaded, effmask, "obf.indcall.dec");
        Value* fn = b.CreateIntToPtr(dec, ptrty, "obf.indcall.p");

        for (Value* v : { loaded, effmask, dec, fn })
            if (auto* di = dyn_cast<Instruction>(v))
            {
                ctx.Own.insert(di);
                MarkMetadata(di, MdKeyComposite);
            }

        call->setCalledOperand(fn);
    }
}

static void IndirectBranchesIn(Function& f, KeyContext& ctx)
{
    if (!ctx.PrologueBb || !ctx.KeyDiffFnPlain) return;
    if (ctx.HasRetKeyLayer) return;

    LLVMContext& ctxllvm = f.getContext();
    Module* m = f.getParent();
    Type* i64ty = Type::getInt64Ty(ctxllvm);
    Type* i32ty = Type::getInt32Ty(ctxllvm);
    Type* ptrty = PointerType::getUnqual(ctxllvm);

    SmallVector<BranchInst*, 32> toindirect;
    DenseMap<BasicBlock*, unsigned> tgtidx;
    SmallVector<BasicBlock*, 32> tgtordered;

    for (BasicBlock& bb : f)
    {
        if (IsPrologueOrFrag(bb, ctx)) continue;
        auto* br = dyn_cast<BranchInst>(bb.getTerminator());
        if (!br) continue;
        if (IsScaffolding(br, ctx)) continue;

        bool hasehsucc = false;
        for (BasicBlock* succ : br->successors())
            if (succ && succ->isEHPad()) { hasehsucc = true; break; }
        if (hasehsucc) continue;

        toindirect.push_back(br);
        for (BasicBlock* succ : br->successors())
            if (tgtidx.insert({ succ, (unsigned)tgtordered.size() }).second)
                tgtordered.push_back(succ);
    }
    if (toindirect.empty()) return;

    unsigned n = (unsigned)tgtordered.size();
    ArrayType* at = ArrayType::get(i64ty, n);
    SmallVector<Constant*, 32> addrentries(n);
    SmallVector<Constant*, 32> maskentries(n);
    for (unsigned i = 0; i < n; ++i)
    {
        uint64_t mask = PerSiteMask();
        Constant* ba = BlockAddress::get(&f, tgtordered[i]);
        Constant* baint = ConstantExpr::getPtrToInt(ba, i64ty);
        Constant* maskc = ConstantInt::get(i64ty, mask);
        addrentries[i] = ConstantExpr::getAdd(baint, maskc);
        maskentries[i] = maskc;
    }

    auto* addrtable = new GlobalVariable(*m, at, false, GlobalValue::PrivateLinkage, ConstantArray::get(at, addrentries), "__obf_ind_br_addrtbl");
    addrtable->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    auto* masktable = new GlobalVariable(*m, at, false, GlobalValue::PrivateLinkage, ConstantArray::get(at, maskentries), "__obf_ind_br_masktbl");
    masktable->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);

    Constant* zero32 = ConstantInt::get(i32ty, 0);
    for (BranchInst* br : toindirect)
    {
        IRBuilder<> b(br);
        Value* idx;
        if (br->isConditional())
        {
            Constant* idxt = ConstantInt::get(i32ty, tgtidx[br->getSuccessor(0)]);
            Constant* idxf = ConstantInt::get(i32ty, tgtidx[br->getSuccessor(1)]);
            idx = b.CreateSelect(br->getCondition(), idxt, idxf, "obf.indbr.idx");
        }
        else
        {
            idx = ConstantInt::get(i32ty, tgtidx[br->getSuccessor(0)]);
        }
        Value* agep = b.CreateGEP(at, addrtable, { zero32, idx }, "obf.indbr.agep");
        Value* mgep = b.CreateGEP(at, masktable, { zero32, idx }, "obf.indbr.mgep");
        Value* loaded = b.CreateLoad(i64ty, agep, "obf.indbr.load");
        Value* mask = b.CreateLoad(i64ty, mgep, "obf.indbr.mask");
        Value* effmask = b.CreateAdd(mask, ctx.KeyDiffFnPlain, "obf.indbr.emask");
        Value* dec = b.CreateSub(loaded, effmask, "obf.indbr.dec");
        Value* tgt = b.CreateIntToPtr(dec, ptrty, "obf.indbr.p");

        for (Value* v : { idx, agep, mgep, loaded, mask, effmask, dec, tgt })
            if (auto* di = dyn_cast<Instruction>(v))
            {
                ctx.Own.insert(di);
                MarkMetadata(di, MdKeyComposite);
            }

        SmallVector<BasicBlock*, 2> succs;
        for (BasicBlock* sc : br->successors()) succs.push_back(sc);
        auto* ibr = IndirectBrInst::Create(tgt, (unsigned)succs.size(), br);
        for (BasicBlock* sc : succs) ibr->addDestination(sc);
        ctx.Own.insert(ibr);
        MarkMetadata(ibr, MdKeyComposite);
        br->eraseFromParent();
    }
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

static void DecryptStringLiteralsIn(Function& f, KeyContext& ctx)
{
    if (!ctx.PrologueBb || !ctx.KFnRt) return;
    if (ctx.HasRetKeyLayer) return;

    DenseSet<GlobalVariable*> seen;
    std::vector<GlobalVariable*> entries;

    for (BasicBlock& bb : f)
    {
        if (&bb == ctx.PrologueBb) continue;
        for (Instruction& i : bb)
        {
            if (IsScaffolding(&i, ctx)) continue;
            for (unsigned oi = 0, oe = i.getNumOperands(); oi != oe; ++oi)
            {
                Value* op = i.getOperand(oi);
                Value* stripped = op;
                while (auto* gep = dyn_cast<GEPOperator>(stripped))
                    stripped = gep->getPointerOperand();

                auto* gv = dyn_cast<GlobalVariable>(stripped);
                if (!gv) continue;
                if (IsOwnedGv(*gv)) continue;
                if (!gv->isConstant() || !gv->hasInitializer()) continue;

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
        bool externaluse = false;
        for (User* u : gv->users())
        {
            if (auto* useri = dyn_cast<Instruction>(u))
            {
                if (useri->getFunction() != &f) { externaluse = true; break; }
            }
            else
            {
                externaluse = true;
                break;
            }
        }
        if (externaluse) continue;

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

        IRBuilder<> be(&f.getEntryBlock(), f.getEntryBlock().begin());
        AllocaInst* slot = be.CreateAlloca(i64, ConstantInt::get(i64, nchunks), "obf.strbuf");
        MarkMetadata(slot, MdKeyComposite);
        ctx.Own.insert(slot);

        IRBuilder<> bs(ctx.PrologueBb->getTerminator());

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

            const std::uint64_t cipherct = plain ^ ctx.KFnCtPlain;
            Value* cipherc = ConstantInt::get(i64, cipherct);
            Value* dec = bs.CreateXor(cipherc, ctx.KFnRt, "obf.str.dec");
            Value* dst = bs.CreateGEP(i64, slot, ConstantInt::get(i64, chunkidx), "obf.str.dst");
            auto* st = bs.CreateStore(dec, dst);

            if (auto* ins = dyn_cast<Instruction>(dec))
            {
                ctx.Own.insert(ins);
                MarkMetadata(ins, MdDecrypt);
            }
            if (auto* ins = dyn_cast<Instruction>(dst))
            {
                ctx.Own.insert(ins);
                MarkMetadata(ins, MdKeyComposite);
            }
            ctx.Own.insert(st);
            MarkMetadata(st, MdKeyComposite);
        }

        std::vector<Use*> toreplace;
        for (Use& u : gv->uses())
        {
            auto* useri = dyn_cast<Instruction>(u.getUser());
            if (!useri) continue;
            if (useri->getFunction() != &f) continue;
            if (IsScaffolding(useri, ctx)) continue;
            toreplace.push_back(&u);
        }
        for (Use* u : toreplace)
            u->set(slot);
    }
}

struct EncGvClassifiedUse
{
    Instruction* Inst = nullptr;
    LoadInst* Load = nullptr;
    StoreInst* Store = nullptr;
    bool Bad = false;
};

static EncGvClassifiedUse ClassifyUser(User* u, GlobalVariable* gv)
{
    EncGvClassifiedUse out;
    out.Inst = dyn_cast<Instruction>(u);
    if (!out.Inst) { out.Bad = true; return out; }
    if (auto* li = dyn_cast<LoadInst>(u))
    {
        if (li->getPointerOperand() != gv) { out.Bad = true; return out; }
        out.Load = li;
        return out;
    }
    if (auto* si = dyn_cast<StoreInst>(u))
    {
        if (si->getPointerOperand() != gv) { out.Bad = true; return out; }
        out.Store = si;
        return out;
    }
    out.Bad = true;
    return out;
}

static void EncryptGlobalInitializersAcrossModule(Module& m, DenseMap<Function*, KeyContext>& ctxs)
{
    SmallVector<GlobalVariable*, 128> gvlist;
    for (GlobalVariable& gv : m.globals()) gvlist.push_back(&gv);

    for (GlobalVariable* gv : gvlist)
    {
        if (!gv->hasInitializer() || gv->isConstant() || gv->isDeclaration()) continue;
        if (IsOwnedGv(*gv)) continue;

        auto* initci = dyn_cast<ConstantInt>(gv->getInitializer());
        if (!initci) continue;
        Type* initty = initci->getType();
        unsigned bw = initci->getBitWidth();
        if (bw != 8 && bw != 16 && bw != 32 && bw != 64) continue;

        Function* readerfn = nullptr;
        SmallVector<LoadInst*, 8> loads;
        SmallVector<StoreInst*, 8> stores;
        bool bad = false;
        for (User* u : gv->users())
        {
            EncGvClassifiedUse gu = ClassifyUser(u, gv);
            if (gu.Bad) { bad = true; break; }
            Function* ufn = gu.Inst->getFunction();
            if (!ufn) { bad = true; break; }
            if (!readerfn) readerfn = ufn;
            else if (readerfn != ufn) { bad = true; break; }
            if (gu.Load && gu.Load->getType() != initty) { bad = true; break; }
            if (gu.Store && gu.Store->getValueOperand()->getType() != initty) { bad = true; break; }
            if (gu.Load) loads.push_back(gu.Load);
            if (gu.Store) stores.push_back(gu.Store);
        }
        if (bad || !readerfn || (loads.empty() && stores.empty())) continue;

        auto it = ctxs.find(readerfn);
        if (it == ctxs.end()) continue;
        KeyContext& ctx = it->second;
        if (!ctx.KFnRt || ctx.HasRetKeyLayer) continue;

        Value* krtw = nullptr;
        if (!PickRtLane(ctx, bw, krtw)) continue;

        APInt kct(bw, (uint64_t)ctx.KFnCtPlain, false);
        APInt encbits = initci->getValue() + kct;
        gv->setInitializer(ConstantInt::get(initty, encbits));

        for (LoadInst* li : loads)
        {
            IRBuilder<> b(li->getNextNode());
            Instruction* dec = cast<Instruction>(b.CreateSub(li, krtw, "obf.gvinit.dec"));
            MarkMetadata(dec, MdDecrypt);
            li->replaceUsesWithIf(dec, [&](Use& u) { return u.getUser() != dec; });
        }
        for (StoreInst* si : stores)
        {
            IRBuilder<> b(si);
            Value* encv = b.CreateAdd(si->getValueOperand(), krtw, "obf.gvinit.enc");
            if (auto* enci = dyn_cast<Instruction>(encv))
                MarkMetadata(enci, MdDecrypt);
            si->setOperand(0, encv);
        }
    }
}

static bool IsAlreadyLaundered(const Value* v)
{
    if (!v) return false;
    auto* ci = dyn_cast<CallInst>(v);
    if (!ci) return false;
    return ci->isInlineAsm();
}

static Value* LaunderLane(Value* v, Function&, KeyContext& ctx)
{
    if (!v) return nullptr;
    if (IsAlreadyLaundered(v)) return v;

    if (isa<Constant>(v))
    {
        if (!ctx.PrologueBb) return v;
        IRBuilder<> b(ctx.PrologueBb->getTerminator());
        Value* lau = OpaqueLaunder(v, b, "obf.lau");
        if (auto* laui = dyn_cast<Instruction>(lau))
            MarkMetadata(laui, MdKeyComposite);
        return lau;
    }

    Instruction* ipafter = nullptr;
    if (auto* i = dyn_cast<Instruction>(v))
    {
        ipafter = i->getNextNode();
        if (!ipafter) return v;
    }
    else if (isa<Argument>(v))
    {
        if (!ctx.PrologueBb) return v;
        ipafter = ctx.PrologueBb->getFirstNonPHIOrDbg();
        if (!ipafter) ipafter = ctx.PrologueBb->getTerminator();
    }
    else
    {
        return v;
    }

    IRBuilder<> b(ipafter);
    Value* lau = OpaqueLaunder(v, b, "obf.lau");
    if (auto* laui = dyn_cast<Instruction>(lau))
        MarkMetadata(laui, MdKeyComposite);

    v->replaceUsesWithIf(lau, [&](Use& u)
    {
        Instruction* ui = dyn_cast<Instruction>(u.getUser());
        return ui != cast<Instruction>(lau);
    });
    return lau;
}

static unsigned FragmentPrologue(KeyContext& ctx)
{
    BasicBlock* p = ctx.PrologueBb;
    if (!p) return 0;

    SmallVector<Instruction*, 32> insts;
    for (Instruction& i : *p)
    {
        if (i.isTerminator()) break;
        insts.push_back(&i);
    }

    unsigned n = (unsigned)insts.size();
    if (n < PrologueMinInsts) return 0;

    unsigned numfrags = std::min(n, PrologueMaxFragments);
    if (numfrags < 2) return 0;

    BasicBlock* current = p;
    unsigned created = 0;
    for (unsigned i = 1; i < numfrags; ++i)
    {
        unsigned splitidx = (n * i) / numfrags;
        if (splitidx == 0 || splitidx >= n) continue;
        Instruction* splitat = insts[splitidx];
        if (!splitat || splitat->getParent() != current) continue;
        current = current->splitBasicBlock(splitat->getIterator(), ("obf.prologue_frag" + Twine(i)).str());
        ++created;
    }
    return created;
}

static void StripPipelineMetadata(Instruction* i)
{
    static const char* tags[] = { MdKeySource, MdKeyComposite, MdDecrypt, MdKeyWrite, MdGateRegion };
    for (const char* tag : tags)
    {
        unsigned kindid = i->getContext().getMDKindID(tag);
        if (i->getMetadata(kindid))
            i->setMetadata(kindid, nullptr);
    }
}

void RunEncryption(Module& m, DenseMap<Function*, KeyContext>& ctxs, const GateTable&, const EncryptionConfig& cfg)
{
    for (auto& kv : ctxs)
    {
        KeyContext& ctx = kv.second;
        Function* f = ctx.F;
        if (!f || f->isDeclaration() || f->empty()) continue;

        if (cfg.EncryptIntegers) EncryptIntegerConstantsIn(*f, ctx);
        if (cfg.EncryptPhi) EncryptPhiOperandsIn(*f, ctx);
        if (cfg.EncryptGep) EncryptGepIndicesIn(*f, ctx);
        if (cfg.EncryptSwitch) EncryptSwitchCasesIn(*f, ctx);
        if (cfg.IndirectCalls) IndirectDirectCallsIn(*f, ctx);
        if (cfg.IndirectBranches) IndirectBranchesIn(*f, ctx);
        if (cfg.DecryptStringLiterals) DecryptStringLiteralsIn(*f, ctx);
    }

    if (cfg.EncryptInitializers)
        EncryptGlobalInitializersAcrossModule(m, ctxs);

    if (cfg.LaunderKeys)
        LaunderKeySources(m, ctxs);
}

void LaunderKeySources(Module& m, DenseMap<Function*, KeyContext>& ctxs)
{
    for (auto& kv : ctxs)
    {
        KeyContext& ctx = kv.second;
        Function* f = ctx.F;
        if (!f || f->isDeclaration() || f->empty()) continue;
        if (!ctx.PrologueBb) continue;

        ctx.KChainRt = LaunderLane(ctx.KChainRt, *f, ctx);
        ctx.KCallerRt = LaunderLane(ctx.KCallerRt, *f, ctx);
        ctx.KTlsRt = LaunderLane(ctx.KTlsRt, *f, ctx);
        ctx.KDepmarkerRt = LaunderLane(ctx.KDepmarkerRt, *f, ctx);
        ctx.KRetRt = LaunderLane(ctx.KRetRt, *f, ctx);
        ctx.KeyDiffRetRt = LaunderLane(ctx.KeyDiffRetRt, *f, ctx);

        ctx.KFnRt = LaunderLane(ctx.KFnRt, *f, ctx);
        ctx.KFnRt32 = LaunderLane(ctx.KFnRt32, *f, ctx);
        ctx.KFnRt16 = LaunderLane(ctx.KFnRt16, *f, ctx);
        ctx.KFnRt8 = LaunderLane(ctx.KFnRt8, *f, ctx);
        ctx.KeyDiffFnPlain = LaunderLane(ctx.KeyDiffFnPlain, *f, ctx);

        for (auto& regkv : ctx.Regions)
        {
            RegionKeyLanes& r = regkv.second;
            r.KGateRt = LaunderLane(r.KGateRt, *f, ctx);
            r.KRegionRt = LaunderLane(r.KRegionRt, *f, ctx);
            r.KeyDiffRegionPlain = LaunderLane(r.KeyDiffRegionPlain, *f, ctx);
        }
    }

    for (auto& kv : ctxs)
    {
        KeyContext& ctx = kv.second;
        Function* f = ctx.F;
        if (!f || f->isDeclaration() || f->empty()) continue;
        if (!ctx.PrologueBb) continue;
        FragmentPrologue(ctx);
    }

    for (Function& f : m)
    {
        if (f.isDeclaration()) continue;
        for (BasicBlock& bb : f)
            for (Instruction& i : bb)
                StripPipelineMetadata(&i);
    }
}