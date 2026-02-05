#include "TraceManager.h"

#include "Lift.h"
#include "lifter/Binary/Loader.h"
#if defined(ELFCONV_X86_BUILD) && ELFCONV_X86_BUILD == 1
#  include "remill/Arch/Runtime/RemillTypes.h"
#elif defined(ELFCONV_AARCH64_BUILD) && ELFCONV_AARCH64_BUILD == 1
#  include "remill/Arch/Runtime/Types.h"
#endif

#include <algorithm>
#include <bfd.h>
#include <cstdint>
#include <functional>
#include <utils/Util.h>

void AArch64TraceManager::SetLiftedTraceDefinition(uint64_t addr, llvm::Function *lifted_func) {
  traces[addr] = lifted_func;
}

std::string AArch64TraceManager::AddRestDisasmFunc(uint64_t addr) {
  auto rest_fun_name = GetUniqueLiftedFuncName("_ecv_rest_fun", addr);
  auto upper_addr_1 = disasm_funcs.upper_bound(addr);
  auto upper_addr_2 = rest_disasm_funcs.upper_bound(addr);
  uint64_t end_addr;
  if (upper_addr_1 != disasm_funcs.end() && upper_addr_2 != rest_disasm_funcs.end()) {
    end_addr = (uint64_t) std::min(upper_addr_1->first, upper_addr_2->first);
  } else if (upper_addr_1 != disasm_funcs.end()) {
    end_addr = upper_addr_1->first;
  } else if (upper_addr_2 != rest_disasm_funcs.end()) {
    end_addr = upper_addr_2->first;
  } else {
    LOG(FATAL) << "[Bug] does not handle the pattern of having last rest_disasm_func.";
  }
  rest_disasm_funcs.insert({addr, DisasmFunc(rest_fun_name, addr, end_addr - addr)});
  return rest_fun_name;
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
  if (disasm_funcs.count(addr) == 1) {
    return disasm_funcs[addr].func_name;
  } else if (rest_disasm_funcs.count(addr) == 1) {
    return rest_disasm_funcs[addr].func_name;
  } else {
    elfconv_runtime_error("[ERROR] addr (0x%lx) doesn't indicate the entry of function.\n", addr);
  }
}

bool AArch64TraceManager::isFunctionEntry(uint64_t addr) {
  return disasm_funcs.count(addr) == 1 || rest_disasm_funcs.count(addr) == 1;
}

std::string AArch64TraceManager::GetUniqueLiftedFuncName(std::string func_name, uint64_t vma_s) {
  std::stringstream lifted_fn_name;
  lifted_fn_name << func_name << "_____" << to_string(unique_i64++) << "_" << std::hex << vma_s;
  return lifted_fn_name.str();
}

uint64_t AArch64TraceManager::GetFuncVMA_E(uint64_t vma_s) {
  if (disasm_funcs.count(vma_s) == 1) {
    return vma_s + disasm_funcs[vma_s].func_size;
  } else if (rest_disasm_funcs.count(vma_s) == 1) {
    return vma_s + rest_disasm_funcs[vma_s].func_size;
  } else {
    elfconv_runtime_error("[ERROR] vma_s (%ld) is not a start address of function.\n", vma_s);
  }
}

uint64_t AArch64TraceManager::GetFuncNums() {
  return disasm_funcs.size() || rest_disasm_funcs.size();
}

void AArch64TraceManager::SetELFData() {

  elf_obj.LoadELF();
  entry_point = elf_obj.entry;

  // Set text section
  elf_obj.SetCodeSection();

  // Set memory of all code section bytes.
  for (auto &[_, code_sec] : elf_obj.code_sections) {
    for (addr_t addr = code_sec.vma; addr < code_sec.vma + code_sec.size; addr++) {
      memory[addr] = code_sec.bytes[addr - code_sec.vma];
    }
  }

  // Make all disasmbled functions data depending on optimization mode.
  if (elf_obj.able_vrp_opt) {

    auto &func_symbols = elf_obj.func_symbols;

    for (size_t i = 0; i < func_symbols.size() - 1; i++) {
      auto lifted_func_name =
          GetUniqueLiftedFuncName(func_symbols[i].sym_name, func_symbols[i].addr);

      // Set program entry point function if applicapable.
      if (entry_point == func_symbols[i].addr) {
        entry_func_lifted_name = lifted_func_name;
      }

      uint64_t func_size = 0;
      // Prefer symbol table size if available
      if (func_symbols[i].size > 0) {
        func_size = func_symbols[i].size;
      } else if (func_symbols[i].in_section == func_symbols[i + 1].in_section) {
        func_size = func_symbols[i + 1].addr - func_symbols[i].addr;
      } else {
        func_size = (bfd_section_vma(func_symbols[i].in_section) +
                     bfd_section_size(func_symbols[i].in_section)) -
                    func_symbols[i].addr;
      }

      disasm_funcs.emplace(func_symbols[i].addr,
                           DisasmFunc(lifted_func_name, func_symbols[i].addr, func_size));
    }

    // Last function.
    auto last_func_symbol = func_symbols.back();
    auto lifted_func_name =
        GetUniqueLiftedFuncName(last_func_symbol.sym_name, last_func_symbol.addr);
    uint64_t func_size = 0;
    // Prefer symbol table size if available
    if (last_func_symbol.size > 0) {
      func_size = last_func_symbol.size;
    } else {
      func_size = (bfd_section_vma(last_func_symbol.in_section) +
                   bfd_section_size(last_func_symbol.in_section)) -
                  last_func_symbol.addr;
    }
    disasm_funcs.emplace(last_func_symbol.addr,
                         DisasmFunc(lifted_func_name, last_func_symbol.addr, func_size));

  } else {
    elfconv_runtime_error("Now not supported for ELF with no eh_frame section.\n");
  }

  if (entry_func_lifted_name.empty()) {
    elfconv_runtime_error("[ERROR] entry_function is not found.\n");
  }

  // define functions in .plt section (FIXME)
  auto plt_section = elf_obj.code_sections[".plt"];
  if (plt_section.sec_name.empty())
    plt_section = elf_obj.code_sections[".iplt"];
  if (!plt_section.sec_name.empty()) {
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
    std::vector<uint64_t> s_t_addrs = {entry_point, 0x40fe74};
    uint64_t __wrap_main_size = AARCH64_OP_SIZE * 3;
    auto &text_section = elf_obj.code_sections[".text"];
    bool __wrap_main_found = false;
    uint64_t extra_search_size = 100;
    for (size_t j = 0; j < s_t_addrs.size(); j++) {
      auto func_size = disasm_funcs.contains(s_t_addrs[j]) ? disasm_funcs[s_t_addrs[j]].func_size
                                                           : __wrap_main_size;
      auto _s_fn_bytes = &text_section.bytes[s_t_addrs[j] - text_section.vma];
      for (uint64_t i = 0; i + __wrap_main_size <= func_size + extra_search_size; i += 4) {
        if (/* nop */ _s_fn_bytes[i] == 0x1f && _s_fn_bytes[i + 1] == 0x20 &&
            _s_fn_bytes[i + 2] == 0x03 && _s_fn_bytes[i + 3] == 0xd5 &&
            /* b <label> */ (_s_fn_bytes[i + 7] & 0xfc) == 0x14 &&
            /* nop */ _s_fn_bytes[i + 8] == 0x1f && _s_fn_bytes[i + 9] == 0x20 &&
            _s_fn_bytes[i + 10] == 0x03 && _s_fn_bytes[i + 11] == 0xd5) {
          uint64_t __wrap_main_vma = s_t_addrs[j] + i;
          disasm_funcs.emplace(__wrap_main_vma,
                               DisasmFunc("__wrap_main", __wrap_main_vma, __wrap_main_size));
          __wrap_main_found = true;
          goto found_entry;
        }
      }
    }
  found_entry:
    if (!__wrap_main_found) {
      elfconv_runtime_error("[ERROR] __wrap_main code block is not found. entry_point: 0x%lx\n",
                            entry_point);
    }
  } else {
    elfconv_runtime_error("[ERROR] Entry function is not defined.\n");
  }
}