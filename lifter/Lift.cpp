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

#include "remill/BC/TraceLifter.h"
#include "remill/BC/Util.h"

#include <cstdint>
#if defined(__linux__)
#  include <signal.h>
#  include <utils/Util.h>
#  include <utils/elfconv.h>
#endif

#include "Lift.h"
#include "MainLifter.h"
#include "TraceManager.h"

#include <llvm/IR/LegacyPassManager.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <remill/BC/HelperMacro.h>
#include <remill/BC/InstructionLifter.h>
#include <remill/BC/Lifter.h>
#include <remill/BC/Optimizer.h>
#include <utils/Util.h>

DEFINE_string(bc_out, "", "Name of the file in which to place the generated bitcode.");

DEFINE_string(os, REMILL_OS,
              "Operating system name of the code being "
              "translated. Valid OSes: linux, macos, windows, solaris.");
DEFINE_string(arch, REMILL_ARCH,
              "Architecture of the code being translated. "
              "Valid architectures: x86, amd64 (with or without "
              "`_avx` or `_avx512` appended), aarch64, aarch32");
DEFINE_string(target_elf, "DUMMY_ELF", "Name of the target ELF binary");
DEFINE_string(dbg_fun_cfg, "", "Function Name of the debug target");
DEFINE_string(bitcode_path, "", "Function Name of the debug target");
DEFINE_string(target_arch, "", "Target Architecture for conversion");
DEFINE_string(float_exception, "0", "Whether the floating-point exception status is set or not");
DEFINE_string(
    norm_mode, "0",
    "Whether the test mode is on or off");  // We use `test_mode` for not only test mode but also `no VRP` mode.
DEFINE_string(fork_emulation_pthread, "",
              "enable the function of emulating fork syscall using pthread.");

ArchName remill::EcvReg::target_elf_arch;

extern "C" void debug_stream_out_sigaction(int sig, siginfo_t *info, void *ctx) {
  std::cout << remill::ECV_DEBUG_STREAM.str();
  std::cout << "(Custom) Segmantation Fault." << std::endl;
  exit(EXIT_FAILURE);
}

void lift_set_sigaction() {
#if defined(__linux__)
  struct sigaction segv_action;
  segv_action.sa_flags = SA_SIGINFO;
  segv_action.sa_sigaction = debug_stream_out_sigaction;
  if (sigaction(SIGSEGV, &segv_action, NULL) < 0) {
    elfconv_runtime_error("sigaction for SIGSEGV failed.\n");
  }
#endif
}

int main(int argc, char *argv[]) {
  // set custom signal handler for SIGSEGV.
  lift_set_sigaction();
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);

  AArch64TraceManager manager(FLAGS_target_elf);
  manager.SetELFData();
  manager.target_arch = FLAGS_target_arch;

  llvm::LLVMContext context;
  auto os_name = remill::GetOSName(REMILL_OS);
  auto arch_name = remill::GetArchName(FLAGS_arch);
  auto arch = remill::Arch::Build(&context, os_name,
                                  arch_name);  // e.g., arch = std::unique_ptr<AArch64Arch>
  auto module = FLAGS_bitcode_path.empty()
                    ? remill::LoadArchSemantics(arch.get())
                    : remill::LoadArchSemantics(arch.get(), {FLAGS_bitcode_path.c_str()});

  // Set wasm32-unknown-wasi and wasm32 data layout if necessary.
  if (manager.target_arch == "wasi32") {
    auto wasm32_dl =
        llvm::DataLayout("e-m:e-p:32:32-p10:8:8-p20:8:8-i64:64-n32:64-S128-ni:1:10:20");
    module->setDataLayout(wasm32_dl.getStringRepresentation());
    llvm::Triple wasm32_triple;
    wasm32_triple.setArch(llvm::Triple::wasm32);
    wasm32_triple.setVendor(llvm::Triple::UnknownVendor);
    wasm32_triple.setOS(llvm::Triple::WASI);
    module->setTargetTriple(wasm32_triple.str());
  }

  // Set various lifting config.
  auto lift_config = LiftConfig(FLAGS_float_exception == "1",
                                FLAGS_norm_mode == "1" || FLAGS_fork_emulation_pthread == "1",
                                arch_name, FLAGS_fork_emulation_pthread == "1");

  remill::EcvReg::target_elf_arch = arch_name;
  remill::IntrinsicTable intrinsics(module.get());
  MainLifter main_lifter(arch.get(), &manager, lift_config);

  // Set various common metadata not depending on whether the ELF binary is not stripped or not.
  // entry point, program header, every data sections, etc.
  main_lifter.SetCommonMetaData(lift_config);

  // Lift every function.
  std::unordered_map<uint64_t, const char *> addr_fun_name_map;
  std::set<uint64_t> fin_addrs;

  do {
    manager.rest_disasm_funcs.clear();
    for (const auto &[addr, dasm_func] : manager.disasm_funcs) {
      if (fin_addrs.contains(addr)) {
        continue;
      }
      addr_fun_name_map[addr] = dasm_func.func_name.c_str();
      auto &lifted_fun_name = addr_fun_name_map[addr];
      if (!main_lifter.Lift(dasm_func.vma, lifted_fun_name)) {
        elfconv_runtime_error("[ERROR] Failed to Lift \"%s\"\n", lifted_fun_name);
      }
      // Set function name
      auto lifted_fn = manager.GetLiftedTraceDefinition(dasm_func.vma);
      lifted_fn->setName(lifted_fun_name);
      fin_addrs.insert(addr);
    }
    for (auto &[rest_addr, disasm_func] : manager.rest_disasm_funcs) {
      manager.disasm_funcs.insert({rest_addr, disasm_func});
    }
  } while (!manager.rest_disasm_funcs.empty());

  // If we lift with `test_mode`, we should disable `able_vrp_opt`.
  manager.elf_obj.able_vrp_opt = !lift_config.norm_mode;

  // Subsequence process of lifting.
  if (manager.elf_obj.able_vrp_opt) {
    main_lifter.SubseqOfLifting(addr_fun_name_map);
  } else {
    main_lifter.SubseqForNoOptLifting(addr_fun_name_map);
    printf("[\x1b[32mINFO\x1b[0m] detected funcs num: %ld\n", addr_fun_name_map.size());
/* Debug functions */
// Insert `debug_state_machine` to the every instruction.
#if defined(OPT_REAL_REGS_DEBUG)
    for (auto lifted_func : main_lifter.impl->lifted_funcs) {
      auto &entry_bb_start_inst = *lifted_func->getEntryBlock().begin();
      auto debug_state_machine_fun = module->getFunction("debug_state_machine");
      llvm::CallInst::Create(debug_state_machine_fun, {}, "", &entry_bb_start_inst);
    }
#endif
// Insert `debug_string (func_name)` for the every function start.
#if defined(CALLED_FUNC_NAME)
    for (auto lifted_func : main_lifter.impl->lifted_funcs) {
      auto &entry_bb_start_inst = *lifted_func->getEntryBlock().begin();
      auto debug_string_fn = module->getFunction("debug_string");
      // define func name byte arrays global variable.
      auto fun_name_val =
          llvm::ConstantDataArray::getString(context, lifted_func->getName().str(), true);
      auto fun_name_gvar = new llvm::GlobalVariable(
          *module, fun_name_val->getType(), true, llvm::GlobalVariable::ExternalLinkage,
          fun_name_val, lifted_func->getName().str() + "debug_name");
      llvm::CallInst::Create(debug_string_fn, {fun_name_gvar}, "", &entry_bb_start_inst);
    }
#endif
  }

  // Prepare and validate the LLVM Module.
  auto host_arch = remill::Arch::Build(&context, os_name, remill::GetArchName(REMILL_ARCH));
  host_arch->PrepareModule(module.get());
  // Make LLVM bitcode file.
  remill::StoreModuleToFile(module.get(), FLAGS_bc_out);

  return 0;
}
