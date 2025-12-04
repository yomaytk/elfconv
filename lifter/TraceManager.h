#pragma once
#include "Binary/Loader.h"

#include <algorithm>
#include <bfd.h>
#include <cstdint>
#include <fstream>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <map>
#include <memory>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Instruction.h>
#include <remill/Arch/Name.h>
#include <remill/Arch/Runtime/Intrinsics.h>
#include <remill/Arch/Runtime/Runtime.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Lifter.h>
#include <remill/BC/Util.h>
#include <remill/OS/OS.h>
#include <sstream>
#include <string>

class DisasmFunc {
 public:
  DisasmFunc(std::string __func_name, uintptr_t __vma, uint64_t __func_size)
      : func_name(__func_name),
        vma(__vma),
        func_size(__func_size) {}
  DisasmFunc() {}

  std::string func_name;
  uintptr_t vma;
  uint64_t func_size;
};

class AArch64TraceManager : public remill::TraceManager {
 public:
  virtual ~AArch64TraceManager(void) = default;
  AArch64TraceManager(std::string target_elf_file_name)
      : elf_obj(BinaryLoader::ELFObject(target_elf_file_name)),
        unique_i64(0) {}

  void SetLiftedTraceDefinition(uint64_t addr, llvm::Function *lifted_func);
  std::string AddRestDisasmFunc(uint64_t addr);

  llvm::Function *GetLiftedTraceDeclaration(uint64_t addr);
  llvm::Function *GetLiftedTraceDefinition(uint64_t addr);
  bool TryReadExecutableByte(uint64_t addr, uint8_t *byte);
  std::string GetLiftedFuncName(uint64_t addr);
  std::string GetUniqueLiftedFuncName(std::string func_name, uint64_t vma_s);
  bool isFunctionEntry(uint64_t addr);
  uint64_t GetFuncVMA_E(uint64_t vma_s);
  uint64_t GetFuncNums();

  void SetELFData();

  void SetCommonVariousData();

  BinaryLoader::ELFObject elf_obj;
  std::unordered_map<uintptr_t, uint8_t> memory;
  std::unordered_map<uintptr_t, llvm::Function *> traces;
  std::map<uintptr_t, DisasmFunc> disasm_funcs;
  std::map<uintptr_t, DisasmFunc> rest_disasm_funcs;

  std::unordered_map<asection *, std::map<uint64_t, BinaryLoader::ELFSymbol>> sec_symbol_mp;

  std::string entry_func_lifted_name;
  std::string panic_plt_jmp_fun_name;

  uintptr_t entry_point;
  std::string target_arch;

 private:
  uint64_t unique_i64;
};
