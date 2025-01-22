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

#include "remill/BC/Util.h"
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

ArchName TARGET_ELF_ARCH;

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

  llvm::LLVMContext context;
  auto os_name = remill::GetOSName(REMILL_OS);
  auto arch_name = remill::GetArchName(FLAGS_arch);
  TARGET_ELF_ARCH = arch_name;
  auto arch =
      remill::Arch::Build(&context, os_name, arch_name);  // arch = std::unique_ptr<AArch64Arch>
  auto module = FLAGS_bitcode_path.empty()
                    ? remill::LoadArchSemantics(arch.get())
                    : remill::LoadArchSemantics(arch.get(), {FLAGS_bitcode_path.c_str()});

  remill::IntrinsicTable intrinsics(module.get());
  MainLifter main_lifter(arch.get(), &manager);
  main_lifter.SetRuntimeManagerClass();

  std::unordered_map<uint64_t, const char *> addr_fn_map;

  /* declare debug function */
  main_lifter.DeclareDebugFunction();
  /* declare helper function for lifted LLVM bitcode */
  main_lifter.DeclareHelperFunction();
  // set global register names
  main_lifter.SetRegisterNames();

  /* lift every disassembled function */
  for (const auto &[addr, dasm_func] : manager.disasm_funcs) {
    if (!main_lifter.Lift(dasm_func.vma, dasm_func.func_name.c_str()))
      elfconv_runtime_error("[ERROR] Failed to Lift \"%s\"\n", dasm_func.func_name.c_str());
    addr_fn_map[addr] = dasm_func.func_name.c_str();
    /* set function attributes */
    auto lifted_fn = manager.GetLiftedTraceDefinition(dasm_func.vma);
    lifted_fn->setName(dasm_func.func_name.c_str());
  }

  // Optimize the generated LLVM IR.
  main_lifter.Optimize();

  /* set entry function of lifted function */
  if (manager.entry_func_lifted_name.empty())
    elfconv_runtime_error("[ERROR] We couldn't find entry function.\n");
  else
    main_lifter.SetEntryPoint(manager.entry_func_lifted_name);
  /* set ELF header info */
  main_lifter.SetELFPhdr(manager.elf_obj.e_phent, manager.elf_obj.e_phnum, manager.elf_obj.e_ph);
  /* set lifted function pointer table (necessary for indirect call) */
  main_lifter.SetLiftedFunPtrTable(addr_fn_map);
#if defined(LIFT_CALLSTACK_DEBUG)
  /* debug call stack */
  main_lifter.SetFuncSymbolNameTable(addr_fn_map);
#endif
  /* set Platform name (FIXME) */
  main_lifter.SetPlatform("aarch64");
  /* set entry point */
  main_lifter.SetEntryPC(manager.entry_point);
  /* set data section */
  main_lifter.SetDataSections(manager.elf_obj.sections);
  /* set block address data */
  main_lifter.SetBlockAddressData(
      manager.g_block_address_ptrs_array, manager.g_block_address_vmas_array,
      manager.g_block_address_size_array, manager.g_block_address_fn_vma_array);

  /* generate LLVM bitcode file */
  auto host_arch = remill::Arch::Build(&context, os_name, remill::GetArchName(REMILL_ARCH));
  host_arch->PrepareModule(module.get());

  // Set wasm32-unknown-wasi and wasm32 data layout if necessary.
  if (FLAGS_target_arch == "wasi32") {
    auto wasm32_dl =
        llvm::DataLayout("e-m:e-p:32:32-p10:8:8-p20:8:8-i64:64-n32:64-S128-ni:1:10:20");
    module->setDataLayout(wasm32_dl.getStringRepresentation());
    llvm::Triple wasm32_triple;
    wasm32_triple.setArch(llvm::Triple::wasm32);
    wasm32_triple.setVendor(llvm::Triple::UnknownVendor);
    wasm32_triple.setOS(llvm::Triple::WASI);
    module->setTargetTriple(wasm32_triple.str());
  }

  remill::StoreModuleToFile(module.get(), FLAGS_bc_out);

  return 0;
}
