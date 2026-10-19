#pragma once

#include "Classifier.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

#include <cstdint>
#include <vector>

enum SchemeId : unsigned
{
    SchemeChain = 1u << 0,
    SchemeCallerKey = 1u << 1,
    SchemeTlsKey = 1u << 2,
    SchemeRetKey = 1u << 3
};

enum TrailingArg : unsigned
{
    TrailNone = 0,
    TrailCallerKey = 1u << 0,
    TrailChainKey = 1u << 1
};

struct ChainPayload
{
    std::uint64_t CF = 0;
    std::uint64_t KF = 0;
};

struct ConstArgRecord
{
    unsigned ParamIdx = 0;
    unsigned BitWidth = 0;
    std::uint64_t Value = 0;
};

struct CallerKeyPayload
{
    std::vector<ConstArgRecord> Consts;
    bool Cascade = false;
    std::uint64_t ParentKct = 0;
    llvm::Function* ParentFn = nullptr;
};

struct TlsKeyPayload
{
    std::uint64_t KF = 0;
};

struct RetKeyPayload
{
    llvm::Constant* CallerBa = nullptr;
    bool BakedBa = false;
};

struct CloneRequest
{
    llvm::Function* Original = nullptr;
    llvm::CallBase* Callsite = nullptr;
    unsigned Scheme = 0;
    unsigned TrailingArgs = 0;
    ChainPayload Chain;
    CallerKeyPayload CallerKey;
    TlsKeyPayload TlsKey;
    RetKeyPayload RetKey;
};

struct MergedClone
{
    llvm::Function* Original = nullptr;
    llvm::CallBase* Callsite = nullptr;
    unsigned Schemes = 0;
    unsigned TrailingArgs = 0;
    ChainPayload Chain;
    CallerKeyPayload CallerKey;
    TlsKeyPayload TlsKey;
    RetKeyPayload RetKey;
    llvm::Function* Clone = nullptr;
};

struct CloneRegistry
{
    std::vector<MergedClone> Clones;
    llvm::DenseMap<llvm::Function*, llvm::Function*> CloneOrigin;
    llvm::DenseMap<llvm::Function*, unsigned> CloneSchemes;
    llvm::DenseMap<llvm::Function*, unsigned> CallerKeyArgIdx;
    llvm::DenseMap<llvm::Function*, unsigned> ChainKeyArgIdx;
    llvm::DenseMap<llvm::Function*, std::uint64_t> ChainK;
    llvm::DenseMap<llvm::Function*, std::uint64_t> ChainC;
    llvm::DenseMap<llvm::Function*, std::vector<ConstArgRecord>> CallerKeyConsts;
    llvm::DenseMap<llvm::Function*, std::uint64_t> TlsK;
    llvm::DenseMap<llvm::Function*, llvm::Constant*> RetCallerBa;
};

struct CloneConfig
{
    unsigned ChainCloneCap = 16;
    unsigned TlsCloneCap = 10;
    unsigned RetCloneXrefCap = 10;
    unsigned CallerKeyCascadeCap = 8;

    bool EnableChain = true;
    bool EnableCallerKey = true;
    bool EnableTlsKey = true;
    bool EnableRetKey = true;
};

void CreateExternalSymbolThunks(llvm::Module& m);
CloneRegistry CloneAndRetarget(llvm::Module& m, const FunctionCatalog& catalog, const CloneConfig& cfg);
void MutateSignatures(llvm::Module& m, CloneRegistry& registry);