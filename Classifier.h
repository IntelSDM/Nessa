#pragma once

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

#include <cstdint>
#include <vector>

enum class GateKind : unsigned
{
    IntEq,
    IntNe,
    FpEq,
    FpNe,
    Switch,
    String,
    WString,
    Compound
};

struct GateRegion
{
    unsigned SiteId = 0;
    llvm::Function* F = nullptr;
    llvm::Instruction* Term = nullptr;
    llvm::CmpInst* Cmp = nullptr;
    llvm::Value* V = nullptr;
    std::uint64_t CBits = 0;
    unsigned BitWidth = 0;
    unsigned GateSuccIdx = 0;
    GateKind Kind = GateKind::IntEq;
    llvm::BasicBlock* SplitBb = nullptr;
    llvm::Value* StringHashCall = nullptr;
    std::vector<llvm::BasicBlock*> Blocks;
};

struct GateTable
{
    std::vector<GateRegion> Regions;
    llvm::DenseMap<llvm::BasicBlock*, unsigned> BbToSite;
};

enum class SkipReason : unsigned
{
    NotSkipped = 0,
    Declaration,
    OurHelper,
    Naked,
    FuncletPadInst,
    FuncletCatchRet,
    FuncletCleanupRet,
    CrtSpecial,
    CompilerHelper,
    GlobalCtorDtor,
    MustTailReceiver,
    MustTailBody,
    NoObfusAnnot
};

struct SchemeVetoes
{
    bool NoObfus = false;
    bool NoChain = false;
    bool NoCallerKey = false;
    bool NoRetKey = false;
    bool NoTlsKey = false;
};

struct FunctionProfile
{
    SkipReason Reason = SkipReason::NotSkipped;
    unsigned DirectCallers = 0;
    unsigned CallInstCallers = 0;
    unsigned SizeInstrs = 0;
    bool AddressTaken = false;
    bool HasPersonality = false;
    bool HasInvokesInBody = false;
    bool IsVariadic = false;
    bool IsSelfRecursive = false;
    bool IsCrossModuleVisible = false;
    SchemeVetoes Vetoes;
};

struct FunctionCatalog
{
    llvm::DenseMap<llvm::Function*, FunctionProfile> Profiles;
    llvm::DenseSet<llvm::Function*> CtorDtorSet;
};

GateTable DetectEqualityGates(llvm::Module& m);
FunctionCatalog ClassifyFunctions(llvm::Module& m);