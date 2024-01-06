#include "TraceManager.h"

#include "Lift.h"
#include "Util.h"

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

std::string AArch64TraceManager::GetLiftedFuncName(uint64_t addr) {
  if (disasm_funcs.count(addr) == 1)
    return disasm_funcs[addr].func_name;
  else
    elfconv_runtime_error("[ERROR] addr (0x%lx) doesn't indicate the entry of function.\n", addr);
}

bool AArch64TraceManager::isFunctionEntry(uint64_t addr) {
  return disasm_funcs.count(addr) == 1;
}

std::string AArch64TraceManager::GetUniqueLiftedFuncName(std::string func_name, uint64_t vma_s) {
  std::stringstream lifted_fn_name;
  lifted_fn_name << func_name << "_" << to_string(unique_i64++) << "_" << std::hex << vma_s;
  return lifted_fn_name.str();
}

bool AArch64TraceManager::isWithinFunction(uint64_t trace_addr, uint64_t target_addr) {
  if (disasm_funcs.count(trace_addr) == 1) {
    if (trace_addr <= target_addr &&
        target_addr < trace_addr + disasm_funcs[trace_addr].func_size) {
      return true;
    } else {
      return false;
    }
  } else {
    elfconv_runtime_error(
        "[ERROR] trace_addr (0x%lx) is not the entry address of function. (at %s)\n", trace_addr,
        __func__);
  }
}

uint64_t AArch64TraceManager::GetFuncVMA_E(uint64_t vma_s) {
  if (disasm_funcs.count(vma_s) == 1) {
    return vma_s + disasm_funcs[vma_s].func_size;
  } else {
    elfconv_runtime_error("[ERROR] vma_s (%ld) is not a start address of function.\n", vma_s);
  }
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
  for (size_t i = 0; i < func_entrys.size();) {
    uintptr_t fun_end_addr;
    uintptr_t sec_addr;
    uint8_t *bytes;
    int sec_included_cnt = 0;
    /* specify included section */
    for (auto &[_, code_sec] : elf_obj.code_sections) {
      if (code_sec.vma <= func_entrys[i].entry &&
          func_entrys[i].entry < code_sec.vma + code_sec.size) {
        sec_addr = code_sec.vma;
        fun_end_addr = code_sec.vma + code_sec.size;
        bytes = code_sec.bytes;
        sec_included_cnt++;
      }
    }
    if (sec_included_cnt != 1)
      elfconv_runtime_error("[ERROR] \"%s\" is included in multiple sections.\n",
                            func_entrys[i].func_name.c_str());
    while (sec_addr < fun_end_addr) {
      /* assign every insn to the manager */
      auto lifted_func_name =
          GetUniqueLiftedFuncName(func_entrys[i].func_name, func_entrys[i].entry);
      /* program entry point */
      if (entry_point == func_entrys[i].entry) {
        if (!entry_func_lifted_name.empty())
          elfconv_runtime_error("[ERROR] multiple entrypoints are found.\n");
        entry_func_lifted_name = lifted_func_name;
      }
      for (uintptr_t addr = func_entrys[i].entry; addr < fun_end_addr; addr++) {
        memory[addr] = bytes[addr - sec_addr];
      }
      disasm_funcs.emplace(func_entrys[i].entry, DisasmFunc(lifted_func_name, func_entrys[i].entry,
                                                            fun_end_addr - func_entrys[i].entry));
      /* next loop */
      fun_end_addr = func_entrys[i].entry;
      i++;
    }
  }
  /* set instructions of every block of .plt section (FIXME) */
  auto plt_section = elf_obj.code_sections[".plt"];
  if (plt_section.sec_name.empty()) {
    printf("[WARNING] .plt section is not found.\n");
  } else {
    uint64_t ins_i = 0;
    while (ins_i < plt_section.size) {
      auto b_entry = plt_section.vma + ins_i;
      for (; ins_i < plt_section.size;) {
        memory[plt_section.vma + ins_i] = plt_section.bytes[ins_i];
        memory[plt_section.vma + ins_i + 1] = plt_section.bytes[ins_i + 1];
        memory[plt_section.vma + ins_i + 2] = plt_section.bytes[ins_i + 2];
        memory[plt_section.vma + ins_i + 3] = plt_section.bytes[ins_i + 3];
        uint8_t *bts = plt_section.bytes + ins_i;
        ins_i += AARCH64_OP_SIZE;
        if ((bts[0] & 0x1f) == 0x00 && (bts[1] & 0xfc) == 0x00 && bts[2] == 0x1f &&
            bts[3] == 0xd6) { /* br instruction (FIXME) */
          break;
        }
      }
      std::stringstream fn_name;
      fn_name << "fn_plt_" << std::hex << b_entry;
      disasm_funcs.emplace(b_entry,
                           DisasmFunc(fn_name.str(), b_entry, (plt_section.vma + ins_i) - b_entry));
    }
  }
  /* 
    define __wrap_main function (FIXME)
    __libc_start_call_main BLR jump to the instructions as following in _start.
    `nop`
    `b main`
    `nop`
  */
  if (disasm_funcs.count(entry_point) == 1) {
    auto _start_disasm_fn = disasm_funcs[entry_point];
    auto __wrap_main_size = AARCH64_OP_SIZE * 3;
    auto &text_section = elf_obj.code_sections[".text"];
    auto _s_fn_bytes = &text_section.bytes[_start_disasm_fn.vma - text_section.vma];
    uint64_t __wrap_main_diff = UINT64_MAX;
    for (uint64_t i = 0; i + __wrap_main_size <= _start_disasm_fn.func_size; i += 4) {
      if (/* nop */ _s_fn_bytes[i] == 0x1f && _s_fn_bytes[i + 1] == 0x20 &&
          _s_fn_bytes[i + 2] == 0x03 && _s_fn_bytes[i + 3] == 0xd5 &&
          /* b main */ (_s_fn_bytes[i + 7] & 0xfc) == 0x14 &&
          /* nop */ _s_fn_bytes[i + 8] == 0x1f && _s_fn_bytes[i + 9] == 0x20 &&
          _s_fn_bytes[i + 10] == 0x03 && _s_fn_bytes[i + 11] == 0xd5) {
        __wrap_main_diff = _start_disasm_fn.vma + i;
        disasm_funcs.emplace(__wrap_main_diff,
                             DisasmFunc("__wrap_main", __wrap_main_diff, __wrap_main_size));
        break;
      }
    }
    if (UINT64_MAX == __wrap_main_diff) {
      printf("[WARNING] __wrap_main cannot be found.\n");
    }
  } else {
    elfconv_runtime_error("[ERROR] Entry function is not defined.\n");
  }
}