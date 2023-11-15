#include <gflags/gflags.h>
#include <glog/logging.h>
#include <gtest/gtest.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <map>
#include <memory>
#include <sstream>
#include <string>

#include "remill/BC/IntrinsicTable.h"
#include "remill/BC/Lifter.h"
#include "remill/BC/Util.h"
#include "remill/Arch/Arch.h"
#include "remill/Arch/Instruction.h"
#include "remill/Arch/Runtime/Intrinsics.h"
#include "remill/Arch/Name.h"
#include "remill/OS/OS.h"
#include "remill/Arch/AArch64/Runtime/State.h"
#include "remill/Arch/Runtime/Runtime.h"
#include "binary/loader.h"

#ifdef __APPLE__
#  define SYMBOL_PREFIX "_"
#else
#  define SYMBOL_PREFIX ""
#endif

#define ARY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define AARCH_OP_SIZE 4

class DisasmFunc {
  public:
    DisasmFunc(std::string __func_name, uintptr_t __vma, uint64_t __func_size): func_name(__func_name), vma(__vma), func_size(__func_size) {}
    DisasmFunc() {}

    std::string func_name;
    uintptr_t vma;
    uint64_t func_size;
};

class AArch64TraceManager : public remill::TraceManager {
  public:
  
    virtual ~AArch64TraceManager(void) = default;
    AArch64TraceManager(std::string target_elf_file_name): elf_obj(BinaryLoader::ELFObject(target_elf_file_name)), unique_i64(0) {
      panic_plt_jmp_fun_name = "__remill_panic_plt_jmp";
    }

    void SetLiftedTraceDefinition(uint64_t addr, llvm::Function *lifted_func);
    llvm::Function *GetLiftedTraceDeclaration(uint64_t addr);
    llvm::Function *GetLiftedTraceDefinition(uint64_t addr);
    bool TryReadExecutableByte(uint64_t addr, uint8_t *byte);
    std::string TraceName(uint64_t addr);
    /* same for TraceManager::TraceName */
    static std::string Sub_FuncName(uint64_t addr);
    inline std::string GetUniqueLiftedFuncName(std::string func_name);

    void SetELFData();

    BinaryLoader::ELFObject elf_obj;
    std::unordered_map<uintptr_t, uint8_t> memory;
    std::unordered_map<uintptr_t, llvm::Function *> traces;
    std::unordered_map<uintptr_t, DisasmFunc> disasm_funcs;
    std::unordered_map<uintptr_t, bool> prerefered_func_addrs;
    std::string entry_func_lifted_name;
    std::string panic_plt_jmp_fun_name;
    uintptr_t entry_point;

  private:
    uint64_t unique_i64;
    
};
