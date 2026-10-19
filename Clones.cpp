#include "Clones.h"
#include "Shared.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/ValueMapper.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

using namespace llvm;

static constexpr unsigned ChainThunkCap = 1024;
static constexpr unsigned TlsSizeBudget = 4096;
static constexpr unsigned RetSizeBudget = 4096;

static std::uint64_t Gen64()
{
    return NextMask();
}

static bool HasMustTailInBody(Function& f)
{
    for (BasicBlock& bb : f)
        for (Instruction& i : bb)
            if (auto* ci = dyn_cast<CallInst>(&i))
                if (ci->isMustTailCall()) return true;
    return false;
}

static bool HasFuncletPadInBody(Function& f)
{
    for (BasicBlock& bb : f)
        for (Instruction& i : bb)
        {
            if (isa<FuncletPadInst>(&i)) return true;
            if (isa<CatchReturnInst>(&i)) return true;
            if (isa<CleanupReturnInst>(&i)) return true;
            if (isa<CatchSwitchInst>(&i)) return true;
        }
    return false;
}

static unsigned CountDirectCallInstCallers(Function& f)
{
    unsigned n = 0;
    for (User* u : f.users())
        if (auto* ci = dyn_cast<CallInst>(u))
            if (ci->getCalledOperand() == &f) ++n;
    return n;
}

static Function* CreateExternalThunk(Function& f, StringRef origname)
{
    Module* m = f.getParent();
    LLVMContext& ctx = m->getContext();

    GlobalValue::LinkageTypes origlink = f.getLinkage();
    GlobalValue::DLLStorageClassTypes origdll = f.getDLLStorageClass();
    GlobalValue::VisibilityTypes origvis = f.getVisibility();
    Comdat* origcomdat = f.getComdat();
    CallingConv::ID origcc = f.getCallingConv();

    Function* thunk = Function::Create(f.getFunctionType(), origlink, origname + ".thunk_tmp", m);
    thunk->setCallingConv(origcc);
    thunk->copyAttributesFrom(&f);
    thunk->setDLLStorageClass(origdll);
    thunk->setVisibility(origvis);
    if (origcomdat) thunk->setComdat(origcomdat);
    thunk->addFnAttr(FaExternalThunk, "true");
    thunk->addFnAttr(Attribute::NoInline);
    thunk->addFnAttr(Attribute::NoMerge);

    f.setName(origname + ".impl");
    f.setLinkage(GlobalValue::PrivateLinkage);
    f.setDLLStorageClass(GlobalValue::DefaultStorageClass);
    f.setVisibility(GlobalValue::DefaultVisibility);
    f.setComdat(nullptr);

    thunk->setName(origname);
    f.replaceAllUsesWith(thunk);

    BasicBlock* entry = BasicBlock::Create(ctx, "entry", thunk);
    IRBuilder<> b(entry);

    SmallVector<Value*, 8> args;
    for (auto& arg : thunk->args()) args.push_back(&arg);

    CallInst* tailcall = b.CreateCall(f.getFunctionType(), &f, args);
    tailcall->setTailCallKind(CallInst::TCK_Tail);
    tailcall->setCallingConv(origcc);

    if (f.getReturnType()->isVoidTy())
        b.CreateRetVoid();
    else
        b.CreateRet(tailcall);

    return thunk;
}

void CreateExternalSymbolThunks(Module& m)
{
    DenseSet<Function*> ctordtorset;
    CollectGlobalCtorDtorFuncs(m, ctordtorset);

    SmallVector<Function*, 128> candidates;
    for (Function& f : m)
    {
        if (f.isDeclaration()) continue;
        if (f.hasFnAttribute(Attribute::Naked)) continue;

        StringRef name = f.getName();
        if (IsOurHelperName(name) || IsCrtSpecialName(name) || IsCompilerHelperName(name)) continue;
        if (ctordtorset.contains(&f)) continue;
        if (HasRetcryptAnnotation(f) || HasNoretcryptAnnotation(f)) continue;
        if (f.hasFnAttribute(FaExternalThunk)) continue;

        if (f.isVarArg()) continue;
        if (f.hasPersonalityFn()) continue;
        if (HasFuncletPadInBody(f)) continue;
        if (HasMustTailInBody(f)) continue;
        if (f.hasComdat()) continue;

        bool atk = DetectAddressTaken(f);
        unsigned ncs = CountDirectCallInstCallers(f);
        if (!atk && ncs > 0) continue;

        candidates.push_back(&f);
    }

    for (Function* f : candidates)
        CreateExternalThunk(*f, f->getName().str());
}

static bool IsSchemeEligible(const FunctionProfile& p, unsigned scheme)
{
    if (p.Reason != SkipReason::NotSkipped) return false;
    if (p.Vetoes.NoObfus) return false;
    switch (scheme)
    {
        case SchemeChain:
            if (p.Vetoes.NoChain) return false;
            if (p.AddressTaken || p.HasPersonality || p.HasInvokesInBody) return false;
            if (p.IsVariadic) return false;
            return true;
        case SchemeCallerKey:
            if (p.Vetoes.NoCallerKey) return false;
            return true;
        case SchemeTlsKey:
            if (p.Vetoes.NoTlsKey) return false;
            if (p.AddressTaken || p.HasPersonality || p.HasInvokesInBody) return false;
            return true;
        case SchemeRetKey:
            if (p.Vetoes.NoRetKey) return false;
            if (p.AddressTaken || p.HasPersonality || p.HasInvokesInBody) return false;
            if (p.IsVariadic || p.IsSelfRecursive) return false;
            return true;
    }
    return false;
}

static void PlanChain(Module& m, const FunctionCatalog& cat, const CloneConfig& cfg, std::vector<CloneRequest>& out)
{
    if (!cfg.EnableChain) return;

    for (Function& f : m)
    {
        auto it = cat.Profiles.find(&f);
        if (it == cat.Profiles.end()) continue;
        const FunctionProfile& p = it->second;
        if (!IsSchemeEligible(p, SchemeChain)) continue;
        if (p.CallInstCallers < 1) continue;
        if (p.CallInstCallers > cfg.ChainCloneCap) continue;

        std::uint64_t kf = Gen64();
        std::uint64_t cf = Gen64();

        for (User* u : f.users())
        {
            auto* ci = dyn_cast<CallInst>(u);
            if (!ci) continue;
            if (ci->getCalledOperand() != &f) continue;
            if (ci->isMustTailCall()) continue;
            if (!ci->getFunction() || ci->getFunction()->isDeclaration()) continue;

            CloneRequest req;
            req.Original = &f;
            req.Callsite = ci;
            req.Scheme = SchemeChain;
            req.TrailingArgs = TrailChainKey;
            req.Chain.KF = kf;
            req.Chain.CF = cf;
            out.push_back(req);
        }
    }
}

static void PlanCallerKey(Module& m, const FunctionCatalog& cat, const CloneConfig& cfg, std::vector<CloneRequest>& out)
{
    if (!cfg.EnableCallerKey) return;

    for (Function& f : m)
    {
        auto it = cat.Profiles.find(&f);
        if (it == cat.Profiles.end()) continue;
        if (it->second.Reason != SkipReason::NotSkipped) continue;

        for (BasicBlock& bb : f)
        {
            for (Instruction& i : bb)
            {
                auto* cb = dyn_cast<CallBase>(&i);
                if (!cb || cb->isInlineAsm()) continue;
                if (isa<InvokeInst>(cb) || isa<CallBrInst>(cb)) continue;
                if (auto* ci = dyn_cast<CallInst>(cb))
                    if (ci->isMustTailCall()) continue;

                Function* callee = cb->getCalledFunction();
                if (!callee || callee->isIntrinsic()) continue;

                auto cit = cat.Profiles.find(callee);
                if (cit == cat.Profiles.end()) continue;
                if (!IsSchemeEligible(cit->second, SchemeCallerKey)) continue;

                std::vector<ConstArgRecord> consts;
                unsigned nfixed = callee->getFunctionType()->getNumParams();
                unsigned nargs = std::min<unsigned>(cb->arg_size(), nfixed);
                for (unsigned pi = 0; pi < nargs; ++pi)
                {
                    auto* ci = dyn_cast<ConstantInt>(cb->getArgOperand(pi));
                    if (!ci) continue;
                    unsigned bw = ci->getBitWidth();
                    if (bw != 8 && bw != 16 && bw != 32 && bw != 64) continue;
                    ConstArgRecord r;
                    r.ParamIdx = pi;
                    r.BitWidth = bw;
                    r.Value = ci->getZExtValue();
                    consts.push_back(r);
                }
                if (consts.empty()) continue;

                CloneRequest req;
                req.Original = callee;
                req.Callsite = cb;
                req.Scheme = SchemeCallerKey;
                req.TrailingArgs = TrailNone;
                req.CallerKey.Consts = std::move(consts);
                req.CallerKey.Cascade = false;
                req.CallerKey.ParentFn = &f;
                out.push_back(req);
            }
        }
    }
}

static void PlanTlsKey(Module& m, const FunctionCatalog& cat, const CloneConfig& cfg, std::vector<CloneRequest>& out)
{
    if (!cfg.EnableTlsKey) return;

    for (Function& f : m)
    {
        auto it = cat.Profiles.find(&f);
        if (it == cat.Profiles.end()) continue;
        const FunctionProfile& p = it->second;
        if (!IsSchemeEligible(p, SchemeTlsKey)) continue;
        if (p.CallInstCallers == 0) continue;
        if (p.CallInstCallers >= cfg.TlsCloneCap) continue;
        if (p.SizeInstrs > TlsSizeBudget) continue;
        if (p.IsSelfRecursive) continue;
        if (p.IsCrossModuleVisible) continue;

        for (User* u : f.users())
        {
            auto* ci = dyn_cast<CallInst>(u);
            if (!ci) continue;
            if (ci->getCalledOperand() != &f) continue;
            if (ci->isMustTailCall()) continue;
            if (!ci->getFunction() || ci->getFunction()->isDeclaration()) continue;

            CloneRequest req;
            req.Original = &f;
            req.Callsite = ci;
            req.Scheme = SchemeTlsKey;
            req.TrailingArgs = TrailNone;
            req.TlsKey.KF = Gen64();
            out.push_back(req);
        }
    }
}

static bool HasReturnAddressOptIn(Function& f)
{
    if (f.hasFnAttribute("retcrypt")) return true;
    return HasRetcryptAnnotation(f);
}

static void PlanRetKey(Module& m, const FunctionCatalog& cat, const CloneConfig& cfg, std::vector<CloneRequest>& out)
{
    if (!cfg.EnableRetKey) return;

    for (Function& f : m)
    {
        auto it = cat.Profiles.find(&f);
        if (it == cat.Profiles.end()) continue;
        const FunctionProfile& p = it->second;
        if (!IsSchemeEligible(p, SchemeRetKey)) continue;
        if (!HasReturnAddressOptIn(f)) continue;
        if (p.DirectCallers == 0) continue;
        if (p.DirectCallers > cfg.RetCloneXrefCap) continue;
        if (p.SizeInstrs > RetSizeBudget) continue;

        for (User* u : f.users())
        {
            auto* cb = dyn_cast<CallBase>(u);
            if (!cb) continue;
            if (cb->getCalledOperand() != &f) continue;
            if (isa<CallBrInst>(cb)) continue;
            if (auto* ci = dyn_cast<CallInst>(cb))
                if (ci->isMustTailCall()) continue;
            if (!cb->getFunction() || cb->getFunction()->isDeclaration()) continue;
            if (cb->getParent()->isEHPad()) continue;

            CloneRequest req;
            req.Original = &f;
            req.Callsite = cb;
            req.Scheme = SchemeRetKey;
            req.TrailingArgs = TrailNone;
            req.RetKey.BakedBa = false;
            out.push_back(req);
        }
    }
}

static std::vector<MergedClone> MergeRequests(const std::vector<CloneRequest>& requests)
{
    DenseMap<std::pair<Function*, CallBase*>, size_t> indexbykey;
    std::vector<MergedClone> merged;

    for (const CloneRequest& r : requests)
    {
        auto key = std::make_pair(r.Original, r.Callsite);
        auto it = indexbykey.find(key);
        if (it == indexbykey.end())
        {
            MergedClone m;
            m.Original = r.Original;
            m.Callsite = r.Callsite;
            m.Schemes = r.Scheme;
            m.TrailingArgs = r.TrailingArgs;
            if (r.Scheme == SchemeChain) m.Chain = r.Chain;
            if (r.Scheme == SchemeCallerKey) m.CallerKey = r.CallerKey;
            if (r.Scheme == SchemeTlsKey) m.TlsKey = r.TlsKey;
            if (r.Scheme == SchemeRetKey) m.RetKey = r.RetKey;
            indexbykey[key] = merged.size();
            merged.push_back(std::move(m));
        }
        else
        {
            MergedClone& m = merged[it->second];
            if (!(m.Schemes & r.Scheme))
            {
                m.Schemes |= r.Scheme;
                m.TrailingArgs |= r.TrailingArgs;
                if (r.Scheme == SchemeChain) m.Chain = r.Chain;
                if (r.Scheme == SchemeCallerKey) m.CallerKey = r.CallerKey;
                if (r.Scheme == SchemeTlsKey) m.TlsKey = r.TlsKey;
                if (r.Scheme == SchemeRetKey) m.RetKey = r.RetKey;
            }
        }
    }
    return merged;
}

static std::string SchemeTag(unsigned schemes)
{
    std::string s;
    auto add = [&](const char* t)
    {
        if (!s.empty()) s += "_";
        s += t;
    };
    if (schemes & SchemeChain) add("chain");
    if (schemes & SchemeCallerKey) add("ckey");
    if (schemes & SchemeTlsKey) add("tkey");
    if (schemes & SchemeRetKey) add("rkey");
    return s.empty() ? std::string("none") : s;
}

static Function* CloneBodyKeepSignature(Function* f, StringRef suffix)
{
    Function* clone = Function::Create(f->getFunctionType(), GlobalValue::InternalLinkage, f->getAddressSpace(), f->getName() + suffix, f->getParent());
    clone->copyAttributesFrom(f);
    clone->setLinkage(GlobalValue::PrivateLinkage);
    clone->setUnnamedAddr(GlobalValue::UnnamedAddr::Local);
    clone->setCallingConv(f->getCallingConv());
    clone->addFnAttr(Attribute::NoInline);
    clone->addFnAttr(Attribute::NoMerge);
    clone->addFnAttr("disable-tail-calls", "true");
    clone->removeFnAttr(Attribute::AlwaysInline);
    clone->removeFnAttr(Attribute::InlineHint);

    ValueToValueMapTy vmap;
    auto oit = f->arg_begin();
    auto nit = clone->arg_begin();
    for (; oit != f->arg_end(); ++oit, ++nit)
    {
        nit->setName(oit->getName());
        vmap[&*oit] = &*nit;
    }
    SmallVector<ReturnInst*, 4> returns;
    CloneFunctionInto(clone, f, vmap, CloneFunctionChangeType::LocalChangesOnly, returns);
    return clone;
}

static unsigned CloneCounter = 0;

static void ExecuteMerged(std::vector<MergedClone>& merged, CloneRegistry& registry)
{
    for (MergedClone& m : merged)
    {
        if (!m.Original || m.Original->isDeclaration()) continue;
        if (!m.Callsite || !m.Callsite->getParent()) continue;

        std::string suffix = ".obf" + std::to_string(CloneCounter++) + "." + SchemeTag(m.Schemes);
        Function* clone = CloneBodyKeepSignature(m.Original, suffix);
        m.Clone = clone;

        if (m.TrailingArgs != TrailNone)
            clone->addFnAttr(FaSigMutated);
        if ((m.Schemes & SchemeCallerKey) && (m.TrailingArgs & TrailCallerKey))
            clone->addFnAttr(FaCallerKeyed);
        if (m.Schemes & SchemeRetKey)
            clone->addFnAttr(FaRetaddrKeyed);

        m.Callsite->setCalledOperand(clone);

        registry.CloneOrigin[clone] = m.Original;
        registry.CloneSchemes[clone] = m.Schemes;

        if (m.Schemes & SchemeChain)
        {
            registry.ChainK[clone] = m.Chain.KF;
            registry.ChainC[clone] = m.Chain.CF;
        }
        if (m.Schemes & SchemeCallerKey)
            registry.CallerKeyConsts[clone] = m.CallerKey.Consts;
        if (m.Schemes & SchemeTlsKey)
            registry.TlsK[clone] = m.TlsKey.KF;

        registry.Clones.push_back(std::move(m));
    }
}

static Function* CreateChainForwarderThunk(Function* g, unsigned idx)
{
    LLVMContext& ctx = g->getContext();
    Module* m = g->getParent();
    FunctionType* ft = g->getFunctionType();
    Function* t = Function::Create(ft, GlobalValue::InternalLinkage, g->getAddressSpace(), g->getName() + ".cfwd" + Twine(idx), m);
    t->copyAttributesFrom(g);
    t->setCallingConv(g->getCallingConv());
    t->setLinkage(GlobalValue::InternalLinkage);
    t->setUnnamedAddr(GlobalValue::UnnamedAddr::Local);
    if (t->hasPersonalityFn()) t->setPersonalityFn(nullptr);
    t->addFnAttr(Attribute::NoInline);
    t->removeFnAttr(Attribute::AlwaysInline);
    t->removeFnAttr(Attribute::InlineHint);

    unsigned i = 0;
    for (Argument& a : t->args())
        a.setName(g->getArg(i++)->getName());

    BasicBlock* bb = BasicBlock::Create(ctx, "entry", t);
    IRBuilder<> b(bb);
    SmallVector<Value*, 8> args;
    for (Argument& a : t->args()) args.push_back(&a);
    CallInst* fwd = b.CreateCall(g, args);
    fwd->setCallingConv(g->getCallingConv());
    fwd->setTailCall(true);

    if (g->getReturnType()->isVoidTy()) b.CreateRetVoid();
    else b.CreateRet(fwd);
    return t;
}

static void SalvageChainOverCap(Module& m, const FunctionCatalog& cat, const CloneConfig& cfg, std::vector<CloneRequest>& requests)
{
    if (!cfg.EnableChain) return;

    SmallVector<Function*, 128> overcap;
    for (Function& f : m)
    {
        auto it = cat.Profiles.find(&f);
        if (it == cat.Profiles.end()) continue;
        if (!IsSchemeEligible(it->second, SchemeChain)) continue;
        if (it->second.CallInstCallers <= cfg.ChainCloneCap) continue;
        overcap.push_back(&f);
    }

    for (Function* g : overcap)
    {
        SmallVector<CallInst*, 32> xrefs;
        for (User* u : g->users())
        {
            auto* ci = dyn_cast<CallInst>(u);
            if (!ci) continue;
            if (ci->getCalledOperand() != g) continue;
            if (ci->isMustTailCall()) continue;
            xrefs.push_back(ci);
        }
        if (xrefs.size() < 2) continue;
        if (xrefs.size() > ChainThunkCap) continue;

        std::uint64_t kt = Gen64();
        std::uint64_t ct = Gen64();
        for (unsigned i = 0; i < xrefs.size(); ++i)
        {
            Function* t = CreateChainForwarderThunk(g, i);
            xrefs[i]->setCalledOperand(t);

            CloneRequest req;
            req.Original = t;
            req.Callsite = xrefs[i];
            req.Scheme = SchemeChain;
            req.TrailingArgs = TrailChainKey;
            req.Chain.KF = kt;
            req.Chain.CF = ct;
            requests.push_back(req);
        }
    }
}

CloneRegistry CloneAndRetarget(Module& m, const FunctionCatalog& cat, const CloneConfig& cfg)
{
    CloneCounter = 0;
    CloneRegistry registry;

    std::vector<CloneRequest> chainreqs;
    std::vector<CloneRequest> callerkeyreqs;
    std::vector<CloneRequest> tlsreqs;
    std::vector<CloneRequest> retreqs;
    PlanChain(m, cat, cfg, chainreqs);
    PlanCallerKey(m, cat, cfg, callerkeyreqs);
    PlanTlsKey(m, cat, cfg, tlsreqs);
    PlanRetKey(m, cat, cfg, retreqs);
    SalvageChainOverCap(m, cat, cfg, chainreqs);

    std::vector<CloneRequest> requests;
    requests.reserve(chainreqs.size() + callerkeyreqs.size() + tlsreqs.size() + retreqs.size());
    requests.insert(requests.end(), chainreqs.begin(), chainreqs.end());
    requests.insert(requests.end(), callerkeyreqs.begin(), callerkeyreqs.end());
    requests.insert(requests.end(), tlsreqs.begin(), tlsreqs.end());
    requests.insert(requests.end(), retreqs.begin(), retreqs.end());

    auto merged = MergeRequests(requests);
    ExecuteMerged(merged, registry);

    for (unsigned round = 1; round < cfg.CallerKeyCascadeCap; ++round)
    {
        struct ParentSnap
        {
            Function* Clone;
            std::uint64_t ParentKct;
            Function* Origin;
        };
        std::vector<ParentSnap> parents;
        parents.reserve(registry.Clones.size());
        for (const MergedClone& m2 : registry.Clones)
        {
            if (!(m2.Schemes & SchemeCallerKey)) continue;
            Function* parentclone = m2.Clone;
            if (!parentclone || parentclone->isDeclaration()) continue;

            std::uint64_t parentkct = 0;
            auto kit = registry.CallerKeyConsts.find(parentclone);
            if (kit != registry.CallerKeyConsts.end())
                for (const ConstArgRecord& r : kit->second)
                    parentkct += r.Value;

            Function* origin = registry.CloneOrigin.lookup(parentclone);
            parents.push_back({ parentclone, parentkct, origin });
        }

        std::vector<CloneRequest> cascadereqs;
        for (const ParentSnap& p : parents)
        {
            Function* parentclone = p.Clone;
            if (parentclone->isDeclaration()) continue;

            SmallVector<CallBase*, 32> callsitestoscan;
            for (BasicBlock& bb : *parentclone)
                for (Instruction& i : bb)
                    if (auto* cb = dyn_cast<CallBase>(&i))
                        callsitestoscan.push_back(cb);

            for (CallBase* cb : callsitestoscan)
            {
                if (!cb->getParent() || cb->isInlineAsm()) continue;
                if (isa<InvokeInst>(cb) || isa<CallBrInst>(cb)) continue;
                if (auto* ci = dyn_cast<CallInst>(cb))
                    if (ci->isMustTailCall()) continue;

                Function* callee = cb->getCalledFunction();
                if (!callee || callee->isDeclaration() || callee->isIntrinsic()) continue;
                if (IsOurHelperName(callee->getName())) continue;

                auto cit = cat.Profiles.find(callee);
                if (cit == cat.Profiles.end()) continue;
                if (!IsSchemeEligible(cit->second, SchemeCallerKey)) continue;
                if (callee == p.Origin) continue;

                unsigned trailingidx = callee->getFunctionType()->getNumParams();

                CloneRequest req;
                req.Original = callee;
                req.Callsite = cb;
                req.Scheme = SchemeCallerKey;
                req.TrailingArgs = TrailCallerKey;
                req.CallerKey.Cascade = true;
                req.CallerKey.ParentKct = p.ParentKct;
                req.CallerKey.ParentFn = parentclone;
                ConstArgRecord r;
                r.ParamIdx = trailingidx;
                r.BitWidth = 64;
                r.Value = p.ParentKct;
                req.CallerKey.Consts.push_back(r);
                cascadereqs.push_back(req);
            }
        }

        if (cascadereqs.empty()) break;
        auto cascademerged = MergeRequests(cascadereqs);
        ExecuteMerged(cascademerged, registry);
    }

    return registry;
}

static Function* MutateSignature(Function* f, bool addcallerkey, bool addchain, unsigned& calleridxout, unsigned& chainidxout)
{
    LLVMContext& ctx = f->getContext();
    FunctionType* oldft = f->getFunctionType();
    const unsigned oldnumparams = oldft->getNumParams();

    SmallVector<Type*, 8> newparams(oldft->params().begin(), oldft->params().end());

    calleridxout = (unsigned)-1;
    chainidxout = (unsigned)-1;
    unsigned nextinsert = oldnumparams;
    if (addcallerkey)
    {
        newparams.insert(newparams.begin() + nextinsert, Type::getInt64Ty(ctx));
        calleridxout = nextinsert++;
    }
    if (addchain)
    {
        newparams.insert(newparams.begin() + nextinsert, Type::getInt64Ty(ctx));
        chainidxout = nextinsert++;
    }

    FunctionType* newft = FunctionType::get(oldft->getReturnType(), newparams, oldft->isVarArg());

    Function* fnew = Function::Create(newft, f->getLinkage(), f->getAddressSpace(), f->getName() + ".sig", f->getParent());
    fnew->copyAttributesFrom(f);
    fnew->setCallingConv(f->getCallingConv());
    fnew->setUnnamedAddr(f->getUnnamedAddr());

    ValueToValueMapTy vmap;
    auto oit = f->arg_begin();
    auto nit = fnew->arg_begin();
    for (unsigned i = 0; i < oldnumparams; ++i, ++oit, ++nit)
    {
        nit->setName(oit->getName());
        vmap[&*oit] = &*nit;
    }
    if (addcallerkey) { nit->setName("__k_caller_in"); ++nit; }
    if (addchain) { nit->setName("__k_chain_in"); ++nit; }

    SmallVector<ReturnInst*, 4> returns;
    CloneFunctionInto(fnew, f, vmap, CloneFunctionChangeType::LocalChangesOnly, returns);

    fnew->addFnAttr(FaSigMutated);
    fnew->addFnAttr(Attribute::NoInline);
    fnew->addFnAttr(Attribute::NoMerge);
    fnew->addFnAttr("disable-tail-calls", "true");
    fnew->removeFnAttr(Attribute::AlwaysInline);
    fnew->removeFnAttr(Attribute::InlineHint);
    return fnew;
}

static CallInst* RewriteCallsite(CallBase* oldcb, Function* newfn, unsigned calleridx, unsigned chainidx, Value* callerval, Value* chainval)
{
    LLVMContext& ctx = oldcb->getContext();
    IRBuilder<> b(oldcb);
    FunctionType* newft = newfn->getFunctionType();

    SmallVector<Value*, 8> oldargs(oldcb->args().begin(), oldcb->args().end());
    AttributeList oldattrs = oldcb->getAttributes();

    const unsigned totalnewargs = (unsigned)oldargs.size() + (calleridx != (unsigned)-1 ? 1u : 0u) + (chainidx != (unsigned)-1 ? 1u : 0u);

    SmallVector<Value*, 8> finalargs;
    SmallVector<AttributeSet, 8> newparamattrs;
    finalargs.reserve(totalnewargs);
    newparamattrs.reserve(totalnewargs);

    unsigned oldpos = 0;
    for (unsigned finalpos = 0; finalpos < totalnewargs; ++finalpos)
    {
        if (calleridx != (unsigned)-1 && finalpos == calleridx)
        {
            finalargs.push_back(callerval);
            newparamattrs.push_back(AttributeSet());
            continue;
        }
        if (chainidx != (unsigned)-1 && finalpos == chainidx)
        {
            finalargs.push_back(chainval);
            newparamattrs.push_back(AttributeSet());
            continue;
        }
        if (oldpos >= oldargs.size()) break;
        finalargs.push_back(oldargs[oldpos]);
        newparamattrs.push_back(oldattrs.getParamAttrs(oldpos));
        ++oldpos;
    }

    CallInst* newci = b.CreateCall(newft, newfn, finalargs);
    newci->setCallingConv(oldcb->getCallingConv());
    if (auto* oldci = dyn_cast<CallInst>(oldcb))
        newci->setTailCallKind(oldci->getTailCallKind());

    AttributeList newattrlist = AttributeList::get(ctx, oldattrs.getFnAttrs(), oldattrs.getRetAttrs(), newparamattrs);
    newci->setAttributes(newattrlist);
    newci->setDebugLoc(oldcb->getDebugLoc());

    if (!oldcb->getType()->isVoidTy())
    {
        newci->takeName(oldcb);
        oldcb->replaceAllUsesWith(newci);
    }
    oldcb->eraseFromParent();
    return newci;
}

void MutateSignatures(Module& m, CloneRegistry& registry)
{
    for (MergedClone& mc : registry.Clones)
    {
        if (mc.TrailingArgs == TrailNone) continue;
        Function* oldclone = mc.Clone;
        if (!oldclone || oldclone->isDeclaration()) continue;
        if (!mc.Callsite || !mc.Callsite->getParent()) continue;
        if (mc.Callsite->getCalledOperand() != oldclone) continue;

        const bool addcallerkey = (mc.TrailingArgs & TrailCallerKey) != 0;
        const bool addchain = (mc.TrailingArgs & TrailChainKey) != 0;
        unsigned calleridx = (unsigned)-1;
        unsigned chainidx = (unsigned)-1;

        Function* newclone = MutateSignature(oldclone, addcallerkey, addchain, calleridx, chainidx);

        Type* i64 = Type::getInt64Ty(m.getContext());
        Value* callerval = nullptr;
        Value* chainval = nullptr;
        if (addcallerkey)
        {
            std::uint64_t bake = 0;
            auto cit = registry.CallerKeyConsts.find(oldclone);
            if (cit != registry.CallerKeyConsts.end())
                for (const ConstArgRecord& r : cit->second)
                    if (r.ParamIdx == calleridx) { bake = r.Value; break; }
            callerval = ConstantInt::get(i64, bake);
        }
        if (addchain)
        {
            std::uint64_t kf = registry.ChainK.lookup(oldclone);
            std::uint64_t cf = registry.ChainC.lookup(oldclone);
            chainval = ConstantInt::get(i64, kf ^ cf);
        }

        CallInst* newcb = RewriteCallsite(mc.Callsite, newclone, calleridx, chainidx, callerval, chainval);
        mc.Callsite = newcb;

        unsigned schemes = registry.CloneSchemes.lookup(oldclone);
        Function* origin = registry.CloneOrigin.lookup(oldclone);
        registry.CloneOrigin.erase(oldclone);
        registry.CloneSchemes.erase(oldclone);
        registry.CloneOrigin[newclone] = origin;
        registry.CloneSchemes[newclone] = schemes;

        if (schemes & SchemeChain)
        {
            std::uint64_t kf = registry.ChainK.lookup(oldclone);
            std::uint64_t cf = registry.ChainC.lookup(oldclone);
            registry.ChainK.erase(oldclone);
            registry.ChainC.erase(oldclone);
            registry.ChainK[newclone] = kf;
            registry.ChainC[newclone] = cf;
            if (chainidx != (unsigned)-1)
                registry.ChainKeyArgIdx[newclone] = chainidx;
        }
        if (schemes & SchemeCallerKey)
        {
            std::vector<ConstArgRecord> consts;
            auto cit = registry.CallerKeyConsts.find(oldclone);
            if (cit != registry.CallerKeyConsts.end()) consts = cit->second;
            registry.CallerKeyConsts.erase(oldclone);
            registry.CallerKeyConsts[newclone] = std::move(consts);
            if (calleridx != (unsigned)-1)
                registry.CallerKeyArgIdx[newclone] = calleridx;
        }
        if (schemes & SchemeTlsKey)
        {
            std::uint64_t kf = registry.TlsK.lookup(oldclone);
            registry.TlsK.erase(oldclone);
            registry.TlsK[newclone] = kf;
        }
        if (schemes & SchemeRetKey)
        {
            Constant* ba = registry.RetCallerBa.lookup(oldclone);
            registry.RetCallerBa.erase(oldclone);
            if (ba) registry.RetCallerBa[newclone] = ba;
        }

        // bug: body-copy strays still point at oldclone with the old arg count, rewrite them too
        SmallVector<CallBase*, 8> othercallers;
        for (User* u : oldclone->users())
        {
            auto* cb = dyn_cast<CallBase>(u);
            if (!cb) continue;
            if (cb->getCalledOperand() != oldclone) continue;
            if (cb == newcb) continue;
            othercallers.push_back(cb);
        }
        for (CallBase* cb : othercallers)
        {
            if (cb->isInlineAsm()) continue;
            if (auto* ci = dyn_cast<CallInst>(cb))
                if (ci->isMustTailCall()) continue;
            if (isa<InvokeInst>(cb) || isa<CallBrInst>(cb)) continue;
            RewriteCallsite(cb, newclone, calleridx, chainidx, callerval, chainval);
        }

        if (!oldclone->use_empty())
            oldclone->replaceAllUsesWith(newclone);
        oldclone->eraseFromParent();
        mc.Clone = newclone;
    }
}