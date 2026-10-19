#pragma once

#include "Classifier.h"
#include "Clones.h"
#include "Shared.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

#include <cstdint>
#include <vector>

struct RegionKeyLanes
{
    unsigned SiteId = 0;
    llvm::Value* KGateRt = nullptr;
    std::uint64_t KGateCtPlain = 0;
    std::uint64_t KRegionCtPlain = 0;
    llvm::Constant* KRegionCtCexpr = nullptr;
    llvm::Value* KRegionRt = nullptr;
    llvm::Value* KeyDiffRegionPlain = nullptr;
};

struct KeyContext
{
    llvm::Function* F = nullptr;
    unsigned Schemes = 0;

    std::uint64_t KChainCt = 0;
    std::uint64_t KCallerCt = 0;
    std::uint64_t KTlsCt = 0;
    std::uint64_t KDepmarkerCt = 0;
    llvm::Constant* KRetCtCexpr = nullptr;

    llvm::Value* KChainRt = nullptr;
    llvm::Value* KCallerRt = nullptr;
    llvm::Value* KTlsRt = nullptr;
    llvm::Value* KDepmarkerRt = nullptr;
    llvm::Value* KRetRt = nullptr;
    llvm::Value* KeyDiffRetRt = nullptr;

    std::uint64_t KFnCtPlain = 0;
    llvm::Constant* KFnCtCexpr = nullptr;
    llvm::Value* KFnRt = nullptr;
    llvm::Value* KFnRt32 = nullptr;
    llvm::Value* KFnRt16 = nullptr;
    llvm::Value* KFnRt8 = nullptr;
    llvm::Value* KeyDiffFnPlain = nullptr;
    bool HasRetKeyLayer = false;

    llvm::BasicBlock* PrologueBb = nullptr;
    llvm::BasicBlock* OrigEntryBb = nullptr;

    llvm::DenseMap<unsigned, RegionKeyLanes> Regions;

    llvm::DenseSet<llvm::Instruction*> Own;
};

struct KeyInstallConfig
{
    bool InstallChain = true;
    bool InstallCallerKey = true;
    bool InstallTlsKey = true;
    bool InstallRetKey = true;
    bool InstallEqualityGate = true;
    bool InstallDepMarker = true;
};

void InstallKeySources(llvm::Module& m, const FunctionCatalog& catalog, const CloneRegistry& registry, const GateTable& gatetable, llvm::DenseMap<llvm::Function*, KeyContext>& outctxs, const KeyInstallConfig& cfg);
void DeriveCompositeKeys(llvm::Module& m, llvm::DenseMap<llvm::Function*, KeyContext>& ctxs, const GateTable& gatetable);