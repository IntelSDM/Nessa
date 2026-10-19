#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/CommandLine.h"

#include "Classifier.h"
#include "Cleanup.h"
#include "Clones.h"
#include "Encryption.h"
#include "KeySources.h"
#include "Shared.h"

#include "llvm/IR/InlineAsm.h"

#include <ctime>
#include <cstdlib>

using namespace llvm;

struct DependencyMarkerPrepPass : PassInfoMixin<DependencyMarkerPrepPass>
{
    PreservedAnalyses run(Module& m, ModuleAnalysisManager&)
    {
        LLVMContext& c = m.getContext();
        FunctionType* asmty = FunctionType::get(Type::getVoidTy(c), {}, false);
        InlineAsm* barrier = InlineAsm::get(asmty, "", "~{memory}", true, false, InlineAsm::AD_Intel);

        bool anychange = false;
        for (Function& f : m)
        {
            if (f.isDeclaration()) continue;
            if (GetDepmarkerNameId(f.getName()) == 0) continue;

            f.addFnAttr(Attribute::NoInline);
            f.addFnAttr(Attribute::OptimizeNone);
            f.addFnAttr(Attribute::NoMerge);
            f.removeFnAttr(Attribute::AlwaysInline);
            f.removeFnAttr(Attribute::InlineHint);
            anychange = true;

            BasicBlock& entry = f.getEntryBlock();
            auto ipit = entry.getFirstInsertionPt();
            if (ipit == entry.end()) continue;

            bool alreadyprepped = false;
            if (auto* firstcall = dyn_cast<CallInst>(&*ipit))
            {
                if (firstcall->isInlineAsm())
                {
                    if (auto* ia = dyn_cast<InlineAsm>(firstcall->getCalledOperand()))
                    {
                        if (ia->hasSideEffects() && ia->getAsmString().empty())
                            alreadyprepped = true;
                    }
                }
            }
            if (!alreadyprepped)
            {
                IRBuilder<> b(&*ipit);
                b.CreateCall(barrier);
            }
        }
        return anychange ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }
};

static cl::opt<bool> ObfEnable("obfenable", cl::init(true), cl::desc("Master gate for the obfuscation pipeline."));

static cl::opt<bool> SchemeChainKeyOpt("obfchainkey", cl::init(true), cl::desc("ChainStageDecryption"));
static cl::opt<bool> SchemeCallerKeyOpt("obfcallerkey", cl::init(true), cl::desc("CallerConstKey"));
static cl::opt<bool> SchemeTlsKeyOpt("obftlskey", cl::init(true), cl::desc("TLSCrypt"));
static cl::opt<bool> SchemeRetKeyOpt("obfretkey", cl::init(true), cl::desc("RetCrypt"));
static cl::opt<bool> SchemeDepMarkerOpt("obfdepmarker", cl::init(true), cl::desc("DependencyMarker"));
static cl::opt<bool> SchemeEqualityGateOpt("obfequalitygate", cl::init(true), cl::desc("ConditionStomping"));

static cl::opt<bool> EncIntegers("obfencryptintegers", cl::init(true), cl::desc("Encrypt integer constant operand slots."));
static cl::opt<bool> EncInitializers("obfencryptinitializers", cl::init(true), cl::desc("Encrypt single reader internal global initializers."));
static cl::opt<bool> EncPhi("obfencryptphi", cl::init(true), cl::desc("Encrypt PHI operand constants."));
static cl::opt<bool> EncGep("obfencryptgep", cl::init(true), cl::desc("Encrypt GEP non structural indices."));
static cl::opt<bool> EncSwitch("obfencryptswitch", cl::init(true), cl::desc("Encrypt switch condition and case labels."));
static cl::opt<bool> IndirectCallsOpt("obfindirectcalls", cl::init(true), cl::desc("Call Encryption"));
static cl::opt<bool> IndirectBranchesOpt("obfindirectbranches", cl::init(true), cl::desc("Rewrite conditional and unconditional branches as indirect branch."));
static cl::opt<bool> DecryptStrings("obfdecryptstrings", cl::init(true), cl::desc("Stack String Encryption."));
static cl::opt<bool> LaunderKeysOpt("obflaunderkeys", cl::init(true), cl::desc("Launder composite key SSA values and fragment prologues."));

static cl::opt<bool> CleanupPass("obfcleanup", cl::init(true), cl::desc("Obfuscates Strings/Calls/Const I64/I32 That Isn't Covered By Pass"));
static cl::opt<bool> CleanupStrings("obfcleanupstrings", cl::init(true), cl::desc("Stack String Encryption"));
static cl::opt<bool> CleanupCalls("obfcleanupcalls", cl::init(true), cl::desc("Call Encryption, Makes Paths Harder To Follow"));
static cl::opt<bool> CleanupConsts("obfcleanupconsts", cl::init(true), cl::desc("I64/I32 Const Encryption"));

static cl::opt<unsigned> ChainCloneCapOpt("obfchainkeyclonecap", cl::init(16), cl::desc("Per function clone ceiling for ChainKey"));
static cl::opt<unsigned> TlsCloneCapOpt("obftlskeyclonecap", cl::init(10), cl::desc("Caller count cutoff for TLSCrypt cloning"));
static cl::opt<unsigned> RetCloneXrefCapOpt("obfretkeyxrefcap", cl::init(10), cl::desc("Caller count cutoff for RetCrypt cloning"));
static cl::opt<unsigned> CallerKeyCascadeCapOpt("obfcallerkeycascadecap", cl::init(8), cl::desc("Max cascade rounds(depth) for ChainKey propagation"));

struct ObfuscationPass : PassInfoMixin<ObfuscationPass>
{
    PreservedAnalyses run(Module& m, ModuleAnalysisManager&)
    {
        if (!ObfEnable) return PreservedAnalyses::all();

        ResetMaskStream();
        ArxInit();
        CollectAnchorPool(m);

        CreateExternalSymbolThunks(m);

        GateTable gatetable;
        if (SchemeEqualityGateOpt)
            gatetable = DetectEqualityGates(m);

        FunctionCatalog catalog = ClassifyFunctions(m);

        CloneConfig clonecfg;
        clonecfg.ChainCloneCap = ChainCloneCapOpt;
        clonecfg.TlsCloneCap = TlsCloneCapOpt;
        clonecfg.RetCloneXrefCap = RetCloneXrefCapOpt;
        clonecfg.CallerKeyCascadeCap = CallerKeyCascadeCapOpt;
        clonecfg.EnableChain = SchemeChainKeyOpt;
        clonecfg.EnableCallerKey = SchemeCallerKeyOpt;
        clonecfg.EnableTlsKey = SchemeTlsKeyOpt;
        clonecfg.EnableRetKey = SchemeRetKeyOpt;
        CloneRegistry registry = CloneAndRetarget(m, catalog, clonecfg);
        MutateSignatures(m, registry);

        KeyInstallConfig keycfg;
        keycfg.InstallChain = SchemeChainKeyOpt;
        keycfg.InstallCallerKey = SchemeCallerKeyOpt;
        keycfg.InstallTlsKey = SchemeTlsKeyOpt;
        keycfg.InstallRetKey = SchemeRetKeyOpt;
        keycfg.InstallEqualityGate = SchemeEqualityGateOpt;
        keycfg.InstallDepMarker = SchemeDepMarkerOpt;

        DenseMap<Function*, KeyContext> keyctxs;
        InstallKeySources(m, catalog, registry, gatetable, keyctxs, keycfg);
        DeriveCompositeKeys(m, keyctxs, gatetable);

        EncryptionConfig enccfg;
        enccfg.EncryptIntegers = EncIntegers;
        enccfg.EncryptInitializers = EncInitializers;
        enccfg.EncryptPhi = EncPhi;
        enccfg.EncryptGep = EncGep;
        enccfg.EncryptSwitch = EncSwitch;
        enccfg.IndirectCalls = IndirectCallsOpt;
        enccfg.IndirectBranches = IndirectBranchesOpt;
        enccfg.DecryptStringLiterals = DecryptStrings;
        enccfg.LaunderKeys = LaunderKeysOpt;
        RunEncryption(m, keyctxs, gatetable, enccfg);

        if (CleanupPass)
        {
            CleanupConfig cc;
            cc.StringLiterals = CleanupStrings;
            cc.DirectCalls = CleanupCalls;
            cc.IntegerConsts = CleanupConsts;
            SweepUnprotectedFunctions(m, keyctxs, cc);
        }

        return PreservedAnalyses::none();
    }
};

llvm::PassPluginLibraryInfo GetPassPluginInfo()
{
    return
    {
        LLVM_PLUGIN_API_VERSION,
        "Nessa",
        LLVM_VERSION_STRING,
        [](PassBuilder& pb)
        {
            pb.registerPipelineStartEPCallback([](ModulePassManager& pm, OptimizationLevel)
            {
                pm.addPass(DependencyMarkerPrepPass());
            });
            pb.registerOptimizerLastEPCallback([](ModulePassManager& pm, OptimizationLevel)
            {
                pm.addPass(ObfuscationPass());
            });
        }
    };
}

#ifndef LLVM_BYE_LINK_INTO_TOOLS
extern "C"
__declspec(dllexport) LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmgetpassplugininfo()
{
    srand(time(0));
    return GetPassPluginInfo();
}
#endif