#pragma once

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/User.h"

#include <cstdint>
#include <vector>

inline constexpr const char* MdGateRegion = "obfus.gate_region";
inline constexpr const char* MdKeySource = "obfus.key_source";
inline constexpr const char* MdKeyComposite = "obfus.key_composite";
inline constexpr const char* MdDecrypt = "obfus.decrypt";
inline constexpr const char* MdKeyWrite = "obfus.key_write";

inline constexpr const char* FaSigMutated = "obfussigmutated";
inline constexpr const char* FaCallerKeyed = "obfuscallerkeyed";
inline constexpr const char* FaRetaddrKeyed = "obfusretaddrkeyed";
inline constexpr const char* FaExternalThunk = "obfusexternalthunk";
inline constexpr const char* FaPipelineHelper = "obfushelper";

inline constexpr const char* PrefixIndirection = "__obf_";
inline constexpr const char* PrefixDepmarker = "__dmp_";
inline constexpr const char* PrefixTlskey = "__tlskey_";
inline constexpr const char* PrefixRetkey = "__retkey_";
inline constexpr const char* PrefixGateHash = "__gate_hash_";
inline constexpr const char* PrefixChain = "__chain_";
inline constexpr const char* PrefixCallerkey = "__callerkey_";
inline constexpr const char* PrefixCleanup = "__cleanup_";

void MarkMetadata(llvm::Instruction* i, const char* tag);
bool HasMetadata(const llvm::Instruction* i, const char* tag);
void MarkGateRegion(llvm::Instruction* i, unsigned siteid);

bool IsOurHelperName(llvm::StringRef n);

std::uint64_t NextMask();
void ResetMaskStream();

struct ArxParams
{
    std::uint64_t KdfSalt;
    std::uint64_t HashSalt;
    int KdfVal1;
    int KdfVal2;
    int HashVal1;
    int HashVal2;
};

extern ArxParams Arx;

void ArxInit();

std::uint64_t Rotl64(std::uint64_t x, int n);
std::uint64_t Rotr64(std::uint64_t x, int n);

std::uint64_t ArxEncCt(std::uint64_t v, std::uint64_t k, int val1, int val2);
llvm::Value* ArxEncRt(llvm::IRBuilder<>& b, llvm::Value* v, llvm::Value* k, int val1, int val2, const llvm::Twine& tag);
llvm::Value* ArxDecRt(llvm::IRBuilder<>& b, llvm::Value* v, llvm::Value* k, int val1, int val2, const llvm::Twine& tag);
std::uint64_t CompileKdf(std::uint64_t v);

llvm::Value* OpaqueLaunder(llvm::Value* v, llvm::IRBuilder<>& b, const llvm::Twine& tag);

void CollectAnchorPool(llvm::Module& m);
llvm::Function* PickAnchor(llvm::Function* fallback);

llvm::Value* IndirectSlotAddr(llvm::IRBuilder<>& b, llvm::GlobalVariable* slot, llvm::Function* anchor, const llvm::Twine& tag);
llvm::Value* EmitInlineEncoded(llvm::IRBuilder<>& b, llvm::Function* anchor, std::uint64_t rawconst, const llvm::Twine& tag);

bool IsCrtSpecialName(llvm::StringRef n);
bool IsCompilerHelperName(llvm::StringRef n);
bool IsMsvcHelperCallee(llvm::StringRef n);
bool IsVtableGv(llvm::StringRef n);

void CollectGlobalCtorDtorFuncs(llvm::Module& m, llvm::DenseSet<llvm::Function*>& out);

bool DetectAddressTaken(llvm::Function& f);
bool IsRewritableConstOp(llvm::Instruction& i, unsigned opidx);

bool HasNoobfuscateAnnotation(llvm::Function& f);
bool HasRetcryptAnnotation(llvm::Function& f);
bool HasNoretcryptAnnotation(llvm::Function& f);
std::vector<unsigned> GetDepmarkerAnnotationIds(llvm::Function& f);
unsigned GetDepmarkerNameId(llvm::StringRef name);