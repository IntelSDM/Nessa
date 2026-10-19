#pragma once

#include "Classifier.h"
#include "Clones.h"
#include "KeySources.h"
#include "Shared.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/IR/Module.h"

#include <cstdint>

struct EncryptionConfig
{
    bool EncryptIntegers = true;
    bool EncryptInitializers = true;
    bool EncryptPhi = true;
    bool EncryptGep = true;
    bool EncryptSwitch = true;
    bool IndirectCalls = true;
    bool IndirectBranches = true;
    bool DecryptStringLiterals = true;
    bool LaunderKeys = true;
};

void RunEncryption(llvm::Module& m, llvm::DenseMap<llvm::Function*, KeyContext>& ctxs, const GateTable& gatetable, const EncryptionConfig& cfg);
void LaunderKeySources(llvm::Module& m, llvm::DenseMap<llvm::Function*, KeyContext>& ctxs);