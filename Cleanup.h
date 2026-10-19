#pragma once

#include "KeySources.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"

struct CleanupConfig
{
    bool StringLiterals = true;
    bool DirectCalls = true;
    bool IntegerConsts = true;
};

void SweepUnprotectedFunctions(llvm::Module& m, const llvm::DenseMap<llvm::Function*, KeyContext>& ctxs, const CleanupConfig& cfg);