/*
 * Copyright (c) 2018 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "remill/Arch/Arch.h"
#include "remill/Arch/Instruction.h"
#include "remill/Arch/Name.h"
#include "remill/BC/InstructionLifter.h"
#include "remill/BC/IntrinsicTable.h"
#include "remill/BC/Lifter.h"
#include "remill/BC/Util.h"
#include "remill/OS/OS.h"
#include "tests/AArch64/Test.h"

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <map>
#include <memory>
#include <sstream>
#include <string>

#ifdef __APPLE__
#  define SYMBOL_PREFIX "_"
#else
#  define SYMBOL_PREFIX ""
#endif

DEFINE_string(bc_out, "", "Name of the file in which to place the generated bitcode.");

DEFINE_string(os, REMILL_OS,
              "Operating system name of the code being "
              "translated. Valid OSes: linux, macos, windows, solaris.");
DEFINE_string(arch, REMILL_ARCH,
              "Architecture of the code being translated. "
              "Valid architectures: x86, amd64 (with or without "
              "`_avx` or `_avx512` appended), aarch64, aarch32");

namespace {

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

class AArch64TestTraceManager : public remill::TraceManager {
 public:
  virtual ~AArch64TestTraceManager(void) = default;

  void SetLiftedTraceDefinition(uint64_t addr, llvm::Function *lifted_func) override {
    traces[addr] = lifted_func;
  }

  llvm::Function *GetLiftedTraceDeclaration(uint64_t addr) override {
    auto trace_it = traces.find(addr);
    if (trace_it != traces.end()) {
      return trace_it->second;
    } else {
      return nullptr;
    }
  }

  llvm::Function *GetLiftedTraceDefinition(uint64_t addr) override {
    return GetLiftedTraceDeclaration(addr);
  }

  bool TryReadExecutableByte(uint64_t addr, uint8_t *byte) override {
    auto byte_it = memory.find(addr);
    if (byte_it != memory.end()) {
      *byte = byte_it->second;
      return true;
    } else {
      return false;
    }
  }

  std::string GetLiftedFuncName(uint64_t addr) override {
    if (disasm_funcs.count(addr) == 1) {
      return disasm_funcs[addr].func_name;
    } else {
      abort();
    }
  }

  bool isFunctionEntry(uint64_t addr) override {
    return disasm_funcs.count(addr) == 1;
  }

  std::string GetUniqueLiftedFuncName(std::string func_name, uint64_t vma_s) {
    std::__throw_runtime_error(
        "[ERROR] GetUniqueLiftedFuncName is not implemented in AArch64TestTraceManager.");
  }

  uint64_t GetFuncVMA_E(uint64_t vma_s) override {
    if (disasm_funcs.count(vma_s) == 1) {
      return vma_s + disasm_funcs[vma_s].func_size;
    } else {
      abort();
    }
  }

  uint64_t GetFuncNums() override {
    return disasm_funcs.size();
  }

  std::string AddRestDisasmFunc(uint64_t addr) override {
    std::__throw_runtime_error("This function is no implemented at AArch64TestTraceManager.\n");
  }

 public:
  std::unordered_map<uint64_t, uint8_t> memory;
  std::unordered_map<uint64_t, llvm::Function *> traces;
  std::unordered_map<uintptr_t, DisasmFunc> disasm_funcs;
};

}  // namespace

remill::ArchName remill::EcvReg::target_elf_arch;

extern "C" int main(int argc, char *argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);

  DLOG(INFO) << "Generating tests.";

  std::vector<const test::TestInfo *> tests;
  for (auto i = 0U;; ++i) {
    const auto &test = test::__aarch64_test_table_begin[i];
    if (&test >= &(test::__aarch64_test_table_end[0])) {
      break;
    }
    tests.push_back(&test);
  }

  AArch64TestTraceManager manager;

  // Add all code byts from the test cases to the memory.
  for (auto test : tests) {
    for (auto addr = test->test_begin; addr < test->test_end; ++addr) {
      manager.memory[addr] = *reinterpret_cast<uint8_t *>(addr);
    }
    // Make all disasmbled functions.
    std::stringstream ss;
    ss << SYMBOL_PREFIX << test->test_name << "_lifted";
    manager.disasm_funcs.emplace(test->test_begin, DisasmFunc(ss.str(), test->test_begin,
                                                              test->test_end - test->test_begin));
  }

  llvm::LLVMContext context;
  auto os_name = remill::GetOSName(REMILL_OS);
  auto arch_name = remill::GetArchName(FLAGS_arch);
  auto arch = remill::Arch::Build(&context, os_name, arch_name);
  auto module = remill::LoadArchSemantics(arch.get());

  auto lift_config = remill::LiftConfig(false, true, remill::kArchAArch64LittleEndian, false);
  remill::EcvReg::target_elf_arch = lift_config.target_elf_arch;

  remill::IntrinsicTable intrinsics(module.get());
  remill::TraceLifter trace_lifter(arch.get(), manager, lift_config);
  trace_lifter.impl->norm_mode = true;
  trace_lifter.impl->vrp_opt_mode = false;

  for (auto test : tests) {
    if (!trace_lifter.Lift(test->test_begin)) {
      LOG(ERROR) << "Unable to lift test " << test->test_name;
      continue;
    }

    // Make sure the trace for the test has the right name.
    std::stringstream ss;
    ss << SYMBOL_PREFIX << test->test_name << "_lifted";

    auto lifted_trace = manager.GetLiftedTraceDefinition(test->test_begin);
    lifted_trace->setName(ss.str());
  }

  DLOG(INFO) << "Serializing bitcode to " << FLAGS_bc_out;
  auto host_arch = remill::Arch::Build(&context, os_name, remill::GetArchName(REMILL_ARCH));
  host_arch->PrepareModule(module.get());
  remill::StoreModuleToFile(module.get(), FLAGS_bc_out);

  DLOG(INFO) << "Done.";
  return 0;
}
