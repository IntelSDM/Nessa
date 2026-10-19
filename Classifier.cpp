#include "Classifier.h"
#include "Shared.h"

#include "llvm/ADT/APFloat.h"
#include "llvm/ADT/APInt.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Cloning.h"

#include <cstdint>
#include <cstring>
#include <vector>

using namespace llvm;

static constexpr unsigned MaxInlineDepth = 4;
static constexpr unsigned MaxCalleeBlocks = 100;
static constexpr unsigned MaxRegionForInlining = 1500;
static constexpr unsigned MaxFixpointRounds = 3;
static constexpr unsigned MaxCompoundLeaves = 8;

static constexpr const char* MdGateProcessed = "obfus.gate_processed";

static void MarkStomped(Instruction* i)
{
    MarkMetadata(i, MdGateProcessed);
}

static bool IsStomped(const Instruction* i)
{
    return HasMetadata(i, MdGateProcessed);
}

static DenseMap<Function*, unsigned> CalleeBlockCache;

static unsigned GetCalleeBlockCountCached(Function* f)
{
    auto it = CalleeBlockCache.find(f);
    if (it != CalleeBlockCache.end()) return it->second;
    unsigned n = f->size();
    CalleeBlockCache[f] = n;
    return n;
}

static bool ShouldInlineForGate(CallInst* call)
{
    if (call->isMustTailCall()) return false;
    Function* callee = call->getCalledFunction();
    if (!callee) return false;
    if (callee->isDeclaration()) return false;
    if (callee->isIntrinsic()) return false;
    if (callee->isVarArg()) return false;
    if (IsOurHelperName(callee->getName())) return false;
    if (callee == call->getFunction()) return false;
    if (HasNoobfuscateAnnotation(*callee)) return false;
    // bug: inlining a marker body strips its call and the key-source install never fires
    if (callee->getName().starts_with("DependencyMarker_")) return false;
    if (GetCalleeBlockCountCached(callee) > MaxCalleeBlocks) return false;
    return true;
}

struct ClassifierDetectedSite
{
    Instruction* Term = nullptr;
    CmpInst* Cmp = nullptr;
    Value* V = nullptr;
    std::uint64_t CBits = 0;
    unsigned BitWidth = 0;
    unsigned GateSuccIdx = 0;
    GateKind Kind = GateKind::IntEq;
    Value* StringHashCall = nullptr;
    BasicBlock* PreSplitTrueBb = nullptr;
    BasicBlock* TrueBb = nullptr;
};

static void MarkSiteProcessed(const ClassifierDetectedSite& s)
{
    if (s.Kind == GateKind::Compound)
    {
        if (auto* br = dyn_cast<BranchInst>(s.Term))
            if (auto* condi = dyn_cast<Instruction>(br->getCondition()))
                MarkStomped(condi);
        return;
    }
    if (isa<SwitchInst>(s.Term))
    {
        if (s.TrueBb && s.TrueBb->getTerminator())
            MarkStomped(s.TrueBb->getTerminator());
        return;
    }
    if (auto* br = dyn_cast<BranchInst>(s.Term))
        if (auto* condi = dyn_cast<Instruction>(br->getCondition()))
            MarkStomped(condi);
}

static bool CollectAndLeaves(Value* root, std::vector<ICmpInst*>& out)
{
    if (auto* bin = dyn_cast<BinaryOperator>(root))
    {
        if (bin->getOpcode() == Instruction::And)
        {
            if (!CollectAndLeaves(bin->getOperand(0), out)) return false;
            if (out.size() > MaxCompoundLeaves) return false;
            if (!CollectAndLeaves(bin->getOperand(1), out)) return false;
            return true;
        }
    }
    if (auto* c = dyn_cast<ICmpInst>(root))
    {
        if (out.size() >= MaxCompoundLeaves) return false;
        if (c->getPredicate() != CmpInst::ICMP_EQ) return false;
        Value* lhs = c->getOperand(0);
        Value* rhs = c->getOperand(1);
        if (!isa<ConstantInt>(lhs) && !isa<ConstantInt>(rhs)) return false;
        Value* v = isa<ConstantInt>(rhs) ? lhs : rhs;
        if (!v->getType()->isIntegerTy()) return false;
        unsigned bw = v->getType()->getIntegerBitWidth();
        if (bw < 8 || bw > 64) return false;
        out.push_back(c);
        return true;
    }
    return false;
}

static bool TryDetectCompoundSite(BranchInst* br, std::vector<ClassifierDetectedSite>& out)
{
    if (IsStomped(br)) return false;
    auto* andi = dyn_cast<BinaryOperator>(br->getCondition());
    if (!andi || andi->getOpcode() != Instruction::And) return false;
    if (IsStomped(andi)) return false;

    std::vector<ICmpInst*> leaves;
    if (!CollectAndLeaves(andi, leaves) || leaves.size() < 2 || leaves.size() > MaxCompoundLeaves)
        return false;

    for (ICmpInst* c : leaves)
        if (IsStomped(c)) return false;

    ICmpInst* primary = leaves[0];
    Value* lhs = primary->getOperand(0);
    Value* rhs = primary->getOperand(1);
    ConstantInt* ci = dyn_cast<ConstantInt>(rhs);
    Value* v = lhs;
    if (!ci) { ci = dyn_cast<ConstantInt>(lhs); v = rhs; }
    if (!ci) return false;

    ClassifierDetectedSite s;
    s.Term = br;
    s.V = v;
    s.CBits = ci->getZExtValue();
    s.BitWidth = ci->getBitWidth();
    s.GateSuccIdx = 0;
    s.Kind = GateKind::Compound;
    s.PreSplitTrueBb = br->getSuccessor(0);
    out.push_back(s);
    return true;
}

static std::uint64_t CompileStrHash(ArrayRef<std::uint64_t> chars)
{
    std::uint64_t h = 5381;
    for (std::uint64_t c : chars) h = h * 33 + c;
    return h;
}

static bool ExtractCString(Value* arg, unsigned charsize, std::vector<std::uint64_t>& outchars)
{
    while (auto* ce = dyn_cast<GEPOperator>(arg))
    {
        for (auto& idx : ce->indices())
        {
            auto* ci = dyn_cast<ConstantInt>(idx);
            if (!ci || !ci->isZero()) return false;
        }
        arg = ce->getPointerOperand();
    }
    auto* gv = dyn_cast<GlobalVariable>(arg);
    if (!gv || !gv->isConstant() || !gv->hasInitializer()) return false;
    auto* init = dyn_cast<ConstantDataSequential>(gv->getInitializer());
    if (!init) return false;

    Type* elemt = init->getElementType();
    if (!elemt->isIntegerTy()) return false;
    if (elemt->getIntegerBitWidth() != charsize * 8) return false;

    outchars.clear();
    for (unsigned i = 0, n = init->getNumElements(); i < n; ++i)
    {
        std::uint64_t c = init->getElementAsInteger(i);
        if (c == 0) break;
        outchars.push_back(c);
    }
    return true;
}

static Function* GetOrCreateStrHasher(Module& m, bool wide)
{
    const char* name = wide ? "__gate_hash_wstr" : "__gate_hash_str";
    if (Function* existing = m.getFunction(name)) return existing;

    LLVMContext& ctx = m.getContext();
    Type* i16 = Type::getInt16Ty(ctx);
    Type* i64 = Type::getInt64Ty(ctx);
    Type* chart = wide ? i16 : Type::getInt8Ty(ctx);
    PointerType* ptrt = PointerType::get(ctx, 0);

    FunctionType* ft = FunctionType::get(i64, { ptrt }, false);
    Function* f = Function::Create(ft, GlobalValue::InternalLinkage, name, &m);
    f->addFnAttr(Attribute::AlwaysInline);
    f->addFnAttr(Attribute::NoUnwind);
    f->addFnAttr(Attribute::WillReturn);
    f->getArg(0)->setName("s");

    BasicBlock* entry = BasicBlock::Create(ctx, "entry", f);
    BasicBlock* loop = BasicBlock::Create(ctx, "loop", f);
    BasicBlock* body = BasicBlock::Create(ctx, "body", f);
    BasicBlock* exit = BasicBlock::Create(ctx, "exit", f);

    IRBuilder<> b(entry);
    b.CreateBr(loop);

    b.SetInsertPoint(loop);
    PHINode* pphi = b.CreatePHI(ptrt, 2, "p");
    PHINode* hphi = b.CreatePHI(i64, 2, "h");
    Value* c = b.CreateLoad(chart, pphi, "c");
    Value* isnul = b.CreateICmpEQ(c, ConstantInt::get(chart, 0), "isnul");
    b.CreateCondBr(isnul, exit, body);

    b.SetInsertPoint(body);
    Value* cz = b.CreateZExt(c, i64, "cz");
    Value* h33 = b.CreateMul(hphi, ConstantInt::get(i64, 33), "h33");
    Value* hnew = b.CreateAdd(h33, cz, "hnew");
    Value* pnext = b.CreateGEP(chart, pphi, ConstantInt::get(i64, 1), "pnext");
    b.CreateBr(loop);

    pphi->addIncoming(f->getArg(0), entry);
    pphi->addIncoming(pnext, body);
    hphi->addIncoming(ConstantInt::get(i64, 5381), entry);
    hphi->addIncoming(hnew, body);

    b.SetInsertPoint(exit);
    b.CreateRet(hphi);

    return f;
}

static bool TryDetectStringSite(Module& m, BranchInst* br, std::vector<ClassifierDetectedSite>& out)
{
    if (!br->isConditional()) return false;

    auto* cmp = dyn_cast<ICmpInst>(br->getCondition());
    if (!cmp || !cmp->hasOneUse()) return false;
    if (*cmp->user_begin() != br) return false;

    const CmpInst::Predicate p = cmp->getPredicate();
    if (p != CmpInst::ICMP_EQ && p != CmpInst::ICMP_NE) return false;

    Value* lhs = cmp->getOperand(0);
    Value* rhs = cmp->getOperand(1);
    auto* zeroci = dyn_cast<ConstantInt>(rhs);
    Value* callside = lhs;
    if (!zeroci || !zeroci->isZero())
    {
        zeroci = dyn_cast<ConstantInt>(lhs);
        callside = rhs;
        if (!zeroci || !zeroci->isZero()) return false;
    }

    auto* callinst = dyn_cast<CallInst>(callside);
    if (!callinst || !callinst->hasOneUse()) return false;
    if (*callinst->user_begin() != cmp) return false;

    Function* callee = callinst->getCalledFunction();
    if (!callee) return false;
    StringRef fname = callee->getName();
    bool wide;
    if (fname == "strcmp" || fname == "_strcmp") wide = false;
    else if (fname == "wcscmp" || fname == "_wcscmp") wide = true;
    else return false;

    if (callinst->arg_size() != 2) return false;

    Value* a0 = callinst->getArgOperand(0);
    Value* a1 = callinst->getArgOperand(1);
    unsigned charsize = wide ? 2u : 1u;

    std::vector<std::uint64_t> chars;
    Value* runtimev = nullptr;
    if (ExtractCString(a1, charsize, chars))
    {
        runtimev = a0;
        std::vector<std::uint64_t> otherchars;
        if (ExtractCString(a0, charsize, otherchars)) return false;
    }
    else if (ExtractCString(a0, charsize, chars))
    {
        runtimev = a1;
    }
    else
    {
        return false;
    }

    const std::uint64_t precomp = CompileStrHash(chars);

    Function* hasher = GetOrCreateStrHasher(m, wide);

    IRBuilder<> b1(callinst);
    Value* hashresult = b1.CreateCall(hasher, { runtimev }, "shash");

    IRBuilder<> b2(cmp);
    LLVMContext& ctx = cmp->getContext();
    Value* precompv = ConstantInt::get(Type::getInt64Ty(ctx), precomp);
    Value* newcmp = b2.CreateICmp(p, hashresult, precompv, "scmp");

    cmp->replaceAllUsesWith(newcmp);
    cmp->eraseFromParent();
    callinst->eraseFromParent();

    const unsigned gateidx = (p == CmpInst::ICMP_EQ) ? 0u : 1u;

    ClassifierDetectedSite s;
    s.Term = br;
    s.Cmp = cast<CmpInst>(newcmp);
    s.V = runtimev;
    s.CBits = precomp;
    s.BitWidth = 64;
    s.GateSuccIdx = gateidx;
    s.Kind = wide ? GateKind::WString : GateKind::String;
    s.StringHashCall = hashresult;
    s.PreSplitTrueBb = br->getSuccessor(gateidx);
    out.push_back(s);
    return true;
}

static void CollectSites(Function& f, std::vector<ClassifierDetectedSite>& out)
{
    for (BasicBlock& bb : f)
    {
        Instruction* term = bb.getTerminator();

        if (auto* br = dyn_cast<BranchInst>(term))
        {
            if (!br->isConditional()) continue;

            if (auto* condi = dyn_cast<Instruction>(br->getCondition()))
                if (IsStomped(condi)) continue;

            if (TryDetectStringSite(*f.getParent(), br, out)) continue;
            if (TryDetectCompoundSite(br, out)) continue;

            auto* cmp = dyn_cast<CmpInst>(br->getCondition());
            if (!cmp || IsStomped(cmp)) continue;

            const CmpInst::Predicate p = cmp->getPredicate();
            const bool isieq = (p == CmpInst::ICMP_EQ);
            const bool isine = (p == CmpInst::ICMP_NE);
            const bool isfeq = (p == CmpInst::FCMP_OEQ);
            const bool isfne = (p == CmpInst::FCMP_UNE);
            if (!isieq && !isine && !isfeq && !isfne) continue;

            const bool isfp = (isfeq || isfne);
            const unsigned gateidx = (isieq || isfeq) ? 0u : 1u;

            Value* lhs = cmp->getOperand(0);
            Value* rhs = cmp->getOperand(1);

            Constant* cconst = dyn_cast<Constant>(rhs);
            Value* v = lhs;
            if (!cconst) { cconst = dyn_cast<Constant>(lhs); v = rhs; }
            if (!cconst || isa<Constant>(v)) continue;

            std::uint64_t cbits = 0;
            unsigned bw = 0;

            if (isfp)
            {
                if (!v->getType()->isFloatTy() && !v->getType()->isDoubleTy()) continue;
                auto* cfp = dyn_cast<ConstantFP>(cconst);
                if (!cfp) continue;
                const APFloat& apf = cfp->getValueAPF();
                if (apf.isNaN() || apf.isZero()) continue;
                const APInt bits = apf.bitcastToAPInt();
                bw = bits.getBitWidth();
                if (bw != 32 && bw != 64) continue;
                cbits = bits.getZExtValue();
            }
            else
            {
                auto* ci = dyn_cast<ConstantInt>(cconst);
                if (!ci) continue;
                if (!v->getType()->isIntegerTy()) continue;
                bw = ci->getBitWidth();
                if (bw < 8 || bw > 64) continue;
                cbits = ci->getZExtValue();
            }

            ClassifierDetectedSite s;
            s.Term = br;
            s.Cmp = cmp;
            s.V = v;
            s.CBits = cbits;
            s.BitWidth = bw;
            s.GateSuccIdx = gateidx;
            s.Kind = isieq ? GateKind::IntEq
                   : isine ? GateKind::IntNe
                   : isfeq ? GateKind::FpEq
                   : GateKind::FpNe;
            s.PreSplitTrueBb = br->getSuccessor(gateidx);
            out.push_back(s);
            continue;
        }

        if (auto* sw = dyn_cast<SwitchInst>(term))
        {
            Value* v = sw->getCondition();
            if (!v->getType()->isIntegerTy()) continue;
            const unsigned bw = v->getType()->getIntegerBitWidth();
            if (bw < 8 || bw > 64) continue;
            if (isa<Constant>(v)) continue;

            for (auto cs : sw->cases())
            {
                ConstantInt* c = cs.getCaseValue();
                if (!c) continue;

                const unsigned gateidx = cs.getSuccessorIndex();
                BasicBlock* succ = sw->getSuccessor(gateidx);
                if (succ && succ->getTerminator() && IsStomped(succ->getTerminator()))
                    continue;

                ClassifierDetectedSite s;
                s.Term = sw;
                s.V = v;
                s.CBits = c->getZExtValue();
                s.BitWidth = bw;
                s.GateSuccIdx = gateidx;
                s.Kind = GateKind::Switch;
                s.PreSplitTrueBb = succ;
                out.push_back(s);
            }
        }
    }
}

static bool SplitAndCollectRegion(ClassifierDetectedSite& s, DominatorTree& dt, std::vector<BasicBlock*>& region)
{
    if (!s.Term || !s.Term->isTerminator()) return false;
    if (s.Term->getNumSuccessors() <= s.GateSuccIdx) return false;

    if (s.Cmp)
    {
        auto* br = dyn_cast<BranchInst>(s.Term);
        if (!br || !br->isConditional() || br->getCondition() != s.Cmp)
            return false;
    }

    s.PreSplitTrueBb = s.Term->getSuccessor(s.GateSuccIdx);
    if (!s.PreSplitTrueBb) return false;

    BasicBlock* pred = s.Term->getParent();
    if (!pred || pred->getTerminator() != s.Term) return false;

    CriticalEdgeSplittingOptions opts(&dt);
    BasicBlock* newt = SplitCriticalEdge(s.Term, s.GateSuccIdx, opts);
    if (!newt)
    {
        if (s.PreSplitTrueBb->getUniquePredecessor() == pred)
            newt = s.PreSplitTrueBb;
        else
            return false;
    }
    s.TrueBb = newt;

    for (BasicBlock& bb : *pred->getParent())
        if (dt.dominates(newt, &bb))
            region.push_back(&bb);
    return true;
}

static void ProcessFunction(Function& f, GateTable& table)
{
    if (f.isDeclaration()) return;
    if (f.getName().starts_with(PrefixGateHash)) return;
    if (IsOurHelperName(f.getName())) return;
    if (HasNoobfuscateAnnotation(f)) return;

    for (unsigned round = 0; round < MaxFixpointRounds; ++round)
    {
        std::vector<ClassifierDetectedSite> sites;
        CollectSites(f, sites);
        if (sites.empty()) break;

        DominatorTree dt; dt.recalculate(f);
        LoopInfo li; li.analyze(dt);

        for (ClassifierDetectedSite& s : sites)
        {
            std::vector<BasicBlock*> region;
            if (!SplitAndCollectRegion(s, dt, region))
                continue;

            for (unsigned depth = 0; depth < MaxInlineDepth; ++depth)
            {
                std::vector<CallInst*> toinline;
                for (BasicBlock* bb : region)
                    for (Instruction& i : *bb)
                        if (auto* call = dyn_cast<CallInst>(&i))
                            if (ShouldInlineForGate(call))
                                toinline.push_back(call);

                if (toinline.empty()) break;

                bool inlinedany = false;
                for (CallInst* call : toinline)
                {
                    InlineFunctionInfo ifi;
                    if (InlineFunction(*call, ifi).isSuccess())
                        inlinedany = true;
                }
                if (!inlinedany) break;

                dt.recalculate(f);
                li = LoopInfo{};
                li.analyze(dt);
                region.clear();
                for (BasicBlock& bb : f)
                    if (dt.dominates(s.TrueBb, &bb))
                        region.push_back(&bb);

                if (region.size() > MaxRegionForInlining) break;
            }

            // bug: inlining can replace the SSA source backing s.V, refresh from the cmp operands
            if (s.Cmp && s.Kind != GateKind::String && s.Kind != GateKind::WString)
            {
                Value* lhs = s.Cmp->getOperand(0);
                Value* rhs = s.Cmp->getOperand(1);
                if (isa<Constant>(rhs)) s.V = lhs;
                else if (isa<Constant>(lhs)) s.V = rhs;
                else continue;
            }
            else if (s.Kind == GateKind::String || s.Kind == GateKind::WString)
            {
                if (auto* hashcall = dyn_cast<CallInst>(s.StringHashCall))
                    s.V = hashcall->getArgOperand(0);
            }
            else if (auto* sw = dyn_cast<SwitchInst>(s.Term))
            {
                s.V = sw->getCondition();
            }

            unsigned siteid = (unsigned)table.Regions.size();
            GateRegion r;
            r.SiteId = siteid;
            r.F = &f;
            r.Term = s.Term;
            r.Cmp = s.Cmp;
            r.V = s.V;
            r.CBits = s.CBits;
            r.BitWidth = s.BitWidth;
            r.GateSuccIdx = s.GateSuccIdx;
            r.Kind = s.Kind;
            r.SplitBb = s.TrueBb;
            r.StringHashCall = s.StringHashCall;
            r.Blocks = std::move(region);
            for (BasicBlock* bb : r.Blocks)
                table.BbToSite[bb] = siteid;
            table.Regions.push_back(std::move(r));

            if (s.TrueBb && s.TrueBb->getTerminator())
                MarkGateRegion(s.TrueBb->getTerminator(), siteid);
            MarkSiteProcessed(s);
        }
    }
}

GateTable DetectEqualityGates(Module& m)
{
    CalleeBlockCache.clear();
    GateTable table;
    for (Function& f : m)
        ProcessFunction(f, table);
    return table;
}

static bool HasPlainAnnotationTag(Function& f, const char* tag)
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
        StringRef s = cds->getAsString();
        if (s.starts_with(tag) && s.size() == strlen(tag) + 1)
            return true;
    }
    return false;
}

static void PopulateVetoes(Function& f, SchemeVetoes& v)
{
    v.NoObfus = HasNoobfuscateAnnotation(f);
    v.NoChain = HasPlainAnnotationTag(f, "nochaincrypt");
    v.NoCallerKey = HasPlainAnnotationTag(f, "nocallerconstkey");
    v.NoRetKey = HasNoretcryptAnnotation(f);
    v.NoTlsKey = HasPlainAnnotationTag(f, "notlscrypt");
}

static FunctionProfile BuildProfile(Function& f, const DenseSet<Function*>& ctordtorset)
{
    FunctionProfile p;

    if (f.isDeclaration() || f.isIntrinsic()) { p.Reason = SkipReason::Declaration; return p; }

    StringRef name = f.getName();
    if (IsOurHelperName(name)) { p.Reason = SkipReason::OurHelper; return p; }
    if (f.hasFnAttribute(FaExternalThunk) || f.hasFnAttribute(FaPipelineHelper))
    {
        p.Reason = SkipReason::OurHelper;
        return p;
    }
    if (f.hasFnAttribute(Attribute::Naked)) { p.Reason = SkipReason::Naked; return p; }
    if (IsCrtSpecialName(name)) { p.Reason = SkipReason::CrtSpecial; return p; }
    if (IsCompilerHelperName(name)) { p.Reason = SkipReason::CompilerHelper; return p; }
    if (ctordtorset.contains(&f)) { p.Reason = SkipReason::GlobalCtorDtor; return p; }

    PopulateVetoes(f, p.Vetoes);
    if (p.Vetoes.NoObfus) { p.Reason = SkipReason::NoObfusAnnot; return p; }

    for (BasicBlock& bb : f)
    {
        for (Instruction& i : bb)
        {
            ++p.SizeInstrs;
            if (isa<FuncletPadInst>(&i)) { p.Reason = SkipReason::FuncletPadInst; return p; }
            if (isa<CatchReturnInst>(&i)) { p.Reason = SkipReason::FuncletCatchRet; return p; }
            if (isa<CleanupReturnInst>(&i)) { p.Reason = SkipReason::FuncletCleanupRet; return p; }
            if (auto* ci = dyn_cast<CallInst>(&i))
                if (ci->isMustTailCall()) { p.Reason = SkipReason::MustTailBody; return p; }
            if (isa<InvokeInst>(&i))
                p.HasInvokesInBody = true;
        }
    }

    p.IsVariadic = f.isVarArg();
    p.HasPersonality = f.hasPersonalityFn();
    p.AddressTaken = DetectAddressTaken(f);
    p.IsCrossModuleVisible = !f.hasLocalLinkage();

    for (User* u : f.users())
    {
        auto* cb = dyn_cast<CallBase>(u);
        if (!cb) continue;
        if (cb->getCalledOperand() != &f) continue;
        ++p.DirectCallers;
        if (auto* ci = dyn_cast<CallInst>(cb))
        {
            if (ci->isMustTailCall()) { p.Reason = SkipReason::MustTailReceiver; return p; }
            ++p.CallInstCallers;
        }
        if (cb->getFunction() == &f)
            p.IsSelfRecursive = true;
    }
    return p;
}

FunctionCatalog ClassifyFunctions(Module& m)
{
    FunctionCatalog cat;
    CollectGlobalCtorDtorFuncs(m, cat.CtorDtorSet);
    for (Function& f : m)
        cat.Profiles[&f] = BuildProfile(f, cat.CtorDtorSet);
    return cat;
}