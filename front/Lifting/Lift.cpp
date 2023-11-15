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

#include "remill/BC/Lifter.h"
#include "Lift.h"
#include "remill/BC/Util.h"

DEFINE_string(bc_out, "",
              "Name of the file in which to place the generated bitcode.");

DEFINE_string(os, REMILL_OS,
              "Operating system name of the code being "
              "translated. Valid OSes: linux, macos, windows, solaris.");
DEFINE_string(arch, REMILL_ARCH,
              "Architecture of the code being translated. "
              "Valid architectures: x86, amd64 (with or without "
              "`_avx` or `_avx512` appended), aarch64, aarch32");
DEFINE_string(target_elf, "DUMMY_ELF",
              "Name of the target ELF binary");
DEFINE_string(dbg_fun_cfg, "",
              "Function Name of the debug target");

void AArch64TraceManager::SetLiftedTraceDefinition(uint64_t addr, llvm::Function *lifted_func) {
  traces[addr] = lifted_func;
}

llvm::Function *AArch64TraceManager::GetLiftedTraceDeclaration(uint64_t addr) {
  auto trace_it = traces.find(addr);
  if (trace_it != traces.end()) {
    return trace_it->second;
  } else {
    return nullptr;
  }
}

llvm::Function *AArch64TraceManager::GetLiftedTraceDefinition(uint64_t addr) {
  return GetLiftedTraceDeclaration(addr);
}

bool AArch64TraceManager::TryReadExecutableByte(uint64_t addr, uint8_t *byte) {
  
  auto byte_it = memory.find(addr);
  if (byte_it != memory.end()) {
    *byte = byte_it->second;
    return true;
  } else {
    return false;
  }

}

std::string AArch64TraceManager::Sub_FuncName(uint64_t addr) {
  std::stringstream ss;
  ss << "sub_" << std::hex << addr;
  return ss.str();
}

std::string AArch64TraceManager::TraceName(uint64_t addr) {
  auto fun_name = Sub_FuncName(addr);
  prerefered_func_addrs[addr] = true;
  return fun_name;
}

std::string AArch64TraceManager::GetUniqueLiftedFuncName(std::string func_name) {
  return func_name + "_" + to_string(unique_i64++) + "__Lifted";
}

void AArch64TraceManager::SetELFData() {

  elf_obj.LoadELF();
  entry_point = elf_obj.entry;
  /* set text section */
  elf_obj.SetCodeSection();
  /* set symbol table (WARNING: only when the ELF binary is not stripped) */
  auto func_entrys = elf_obj.GetFuncEntry();
  std::sort(func_entrys.rbegin(), func_entrys.rend());
  /* set instructions of every symbol in the table */
  size_t i = 0;
  while (i < func_entrys.size()) {
    uint64_t fun_bytes_size;
    uintptr_t fun_end_addr;
    uintptr_t sec_addr;
    uintptr_t n_fun_end_addr;
    uint8_t *bytes;
    int sec_included_cnt = 0;
    /* specify included section */
    for (auto &[_, code_sec] : elf_obj.code_sections) {
      if (code_sec.vma <= func_entrys[i].entry && func_entrys[i].entry < code_sec.vma + code_sec.size) {
        sec_addr = code_sec.vma;
        fun_end_addr = code_sec.vma + code_sec.size;
        fun_bytes_size = (code_sec.vma + code_sec.size) - func_entrys[i].entry;
        bytes = code_sec.bytes;
        sec_included_cnt++;
      }
    }
    if (sec_included_cnt != 1) {
      printf("[ERROR] \"%s\" is not included in one code section.\n", func_entrys[i].func_name.c_str());
      exit(EXIT_FAILURE);
    }
    n_fun_end_addr = UINTPTR_MAX;
    while (sec_addr < n_fun_end_addr) {
      /* assign every insn to the manager */
      auto lifted_func_name = GetUniqueLiftedFuncName(func_entrys[i].func_name);
      /* program entry point */
      if (entry_point == func_entrys[i].entry) {
        if (!entry_func_lifted_name.empty()) {
          printf("[ERROR] multiple entrypoints are found.\n");
          exit(EXIT_FAILURE);
        }
        entry_func_lifted_name = lifted_func_name;
      }
      for (uintptr_t addr = func_entrys[i].entry;addr < fun_end_addr; addr++) {
        memory[addr] = bytes[addr - sec_addr];
      }
      disasm_funcs.emplace(func_entrys[i].entry, DisasmFunc(lifted_func_name, func_entrys[i].entry, fun_bytes_size));
      n_fun_end_addr = func_entrys[i].entry;
      i++;
    }
  }
  /* set instructions of every block of .plt section (FIXME) */
  auto plt_section = elf_obj.code_sections[".plt"];
  if (plt_section.sec_name.empty()) {
    printf("[WARNING] .plt section is not found.\n");
  } else {
    int plt_i = 0;
    while(plt_i < plt_section.size) {
      auto b_entry = plt_section.vma + plt_i;
      for(;plt_i < plt_section.size;) {
        auto ins_s = plt_i;
        memory[plt_section.vma + ins_s] = plt_section.bytes[ins_s];
        memory[plt_section.vma + ins_s + 1] = plt_section.bytes[ins_s + 1];
        memory[plt_section.vma + ins_s + 2] = plt_section.bytes[ins_s + 2];
        memory[plt_section.vma + ins_s + 3] = plt_section.bytes[ins_s + 3];
        plt_i += sizeof(uint32_t); /* 4bytes fixed instruction */
        // uint8_t* bts = &plt_section.bytes[ins_s];
        // printf("0x%x, 0x%x, 0x%x, 0x%x\n", bts[ins_s], bts[ins_s + 1], bts[ins_s + 2], bts[ins_s + 3]);
        if (plt_section.bytes[ins_s] == 0x20 && plt_section.bytes[ins_s + 1] == 0x02 && plt_section.bytes[ins_s + 2] == 0x1f && plt_section.bytes[ins_s + 3] == 0xd6) { /* bl instruction (FIXME) */
          break;
        }
      }
      std::stringstream fn_name;
      fn_name << "fn_plt_" << std::hex << b_entry;
      disasm_funcs.emplace(b_entry, DisasmFunc(fn_name.str(), b_entry, plt_i - b_entry));
    }
  }
}

extern "C" int main(int argc, char *argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);

  AArch64TraceManager manager(FLAGS_target_elf);
  manager.SetELFData();

  llvm::LLVMContext context;
  auto os_name = remill::GetOSName(REMILL_OS);
  auto arch_name = remill::GetArchName(FLAGS_arch);
  auto arch = remill::Arch::Build(&context, os_name, arch_name);
  auto module = remill::LoadArchSemantics(arch.get());

  remill::IntrinsicTable intrinsics(module.get());
  remill::TraceLifter trace_lifter(arch.get(), manager);

  std::unordered_map<uint64_t, const char*> addr_fn_map;

  /* debug */
#if defined(LIFT_DEBUG)
  /* debug function control flow */
  std::unordered_map<uint64_t, bool> control_flow_debug_list = {};
  if (!FLAGS_dbg_fun_cfg.empty()) {
    for (auto &[fn_addr, dasm_func] : manager.disasm_funcs) {
      /* append the address of necesarry debug function */
      if (strncmp(dasm_func.func_name.c_str(), FLAGS_dbg_fun_cfg.c_str(), FLAGS_dbg_fun_cfg.length()) == 0) {
        control_flow_debug_list[fn_addr] = true;
        printf("entry!\n");
        break;
      }
    }
    trace_lifter.SetControlFlowDebugList(control_flow_debug_list);
  }
  /* declare debug function */
  trace_lifter.DeclareDebugStateMachine();
  trace_lifter.DeclareDebugPC();
#endif

  /* lift every disassembled function */
  for (const auto &[addr, dasm_func] : manager.disasm_funcs) {
    if (!trace_lifter.Lift(dasm_func.vma, dasm_func.func_name.c_str())) {
      printf("[ERROR] Failed to Lift \"%s\"\n", dasm_func.func_name.c_str());
      exit(EXIT_FAILURE);
    }
    addr_fn_map[addr] = dasm_func.func_name.c_str();
    /* set function name */
    auto lifted_fn = manager.GetLiftedTraceDefinition(dasm_func.vma);
    lifted_fn->setName(dasm_func.func_name.c_str());
  }
  /* set entry function of lifted function */
  if (manager.entry_func_lifted_name.empty()) {
    printf("[ERROR] We couldn't find entry function.\n");
    exit(EXIT_FAILURE);
  } else {
    trace_lifter.SetEntryPoint(manager.entry_func_lifted_name);
  }
  /* set ELF header info */
  trace_lifter.SetELFPhdr(manager.elf_obj.e_phent, manager.elf_obj.e_phnum, manager.elf_obj.e_ph);
  /* set lifted function pointer table (necessary for indirect call) */
  trace_lifter.SetLiftedFunPtrTable(addr_fn_map);
  /* set Platform name (FIXME) */
  trace_lifter.SetPlatform("unknown");
  /* set entry point */
  trace_lifter.SetEntryPC(manager.entry_point);
  /* set data section */
  trace_lifter.SetDataSections(manager.elf_obj.sections);
  /* define prerefered functions */
  for (auto [addr, pre_refered] : manager.prerefered_func_addrs) {
    if (!pre_refered) {
      continue;
    }
    auto lifted_func_name = manager.disasm_funcs[addr].func_name;
    trace_lifter.DefinePreReferedFunction(
      manager.Sub_FuncName(addr), 
      lifted_func_name, 
      remill::LLVMFunTypeIdent::NULL_FUN_TY
    );
  }
  
  /* generate LLVM bitcode file */
  auto host_arch =
      remill::Arch::Build(&context, os_name, remill::GetArchName(REMILL_ARCH));
  host_arch->PrepareModule(module.get());
  remill::StoreModuleToFile(module.get(), FLAGS_bc_out);

  printf("[INFO] Lift Done\n");
  return 0;
}
