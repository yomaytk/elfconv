#include "TraceManager.h"

#include "Lift.h"
#include "lifter/Binary/Loader.h"
#include "remill/Arch/Runtime/Types.h"

#include <algorithm>
#include <bfd.h>
#include <cstdint>
#include <utils/Util.h>

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

void AArch64TraceManager::SetLiftedOptFuncTraceDefinition(uint64_t addr,
                                                          llvm::Function *lifted_func) {
  opt_fun_traces[addr] = lifted_func;
}

llvm::Function *AArch64TraceManager::GetLiftedOptFuncTraceDeclaration(uint64_t addr) {
  auto trace_it = opt_fun_traces.find(addr);
  if (trace_it != traces.end()) {
    return trace_it->second;
  } else {
    return nullptr;
  }
}

llvm::Function *AArch64TraceManager::GetLiftedOptFuncTraceDefinition(uint64_t addr) {
  return GetLiftedOptFuncTraceDeclaration(addr);
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

std::string AArch64TraceManager::GetLiftedFuncName(uint64_t addr, bool vrp_opt_mode) {
  if (disasm_funcs.count(addr) == 1) {
    return disasm_funcs[addr].func_name;
  } else {
    elfconv_runtime_error("[ERROR] addr (0x%lx) doesn't indicate the entry of function.\n", addr);
  }
}

bool AArch64TraceManager::isFunctionEntry(uint64_t addr) {
  return disasm_funcs.count(addr) == 1;
}

std::string AArch64TraceManager::GetUniqueLiftedFuncName(std::string func_name, uint64_t vma_s) {
  std::stringstream lifted_fn_name;
  lifted_fn_name << func_name << "_____" << to_string(unique_i64++) << "_" << std::hex << vma_s;
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

uint64_t AArch64TraceManager::GetFuncNums() {
  return disasm_funcs.size();
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
    std::sort(func_symbols.begin(), func_symbols.end(),
              [](auto const &lhs, auto const &rhs) { return lhs.addr < rhs.addr; });

    for (size_t i = 0; i < func_symbols.size() - 1; i++) {
      auto lifted_func_name =
          GetUniqueLiftedFuncName(func_symbols[i].sym_name, func_symbols[i].addr);

      // Set program entry point function if applicapable.
      if (entry_point == func_symbols[i].addr) {
        entry_func_lifted_name = lifted_func_name;
      }

      if (func_symbols[i].in_section == func_symbols[i + 1].in_section) {
        disasm_funcs.emplace(func_symbols[i].addr,
                             DisasmFunc(lifted_func_name, func_symbols[i].addr,
                                        func_symbols[i + 1].addr - func_symbols[i].addr));
      } else {
        disasm_funcs.emplace(func_symbols[i].addr,
                             DisasmFunc(lifted_func_name, func_symbols[i].addr,
                                        (bfd_section_vma(func_symbols[i].in_section) +
                                         bfd_section_size(func_symbols[i].in_section)) -
                                            func_symbols[i].addr));
      }
    }

    // Last function.
    auto last_func_symbol = func_symbols.back();
    auto lifted_func_name =
        GetUniqueLiftedFuncName(last_func_symbol.sym_name, last_func_symbol.addr);
    disasm_funcs.emplace(last_func_symbol.addr,
                         DisasmFunc(lifted_func_name, last_func_symbol.addr,
                                    (bfd_section_vma(last_func_symbol.in_section) +
                                     bfd_section_size(last_func_symbol.in_section)) -
                                        last_func_symbol.addr));

  } else {

    for (auto fun_symbol : elf_obj.func_symbols) {
      if (sec_symbol_mp.contains(fun_symbol.in_section)) {
        sec_symbol_mp[fun_symbol.in_section].insert({fun_symbol.addr, fun_symbol});
      } else {
        sec_symbol_mp[fun_symbol.in_section] = {{fun_symbol.addr, fun_symbol}};
      }
    }

    // Make DisasmFunc for the every detected function entry and empty segment spaces.
    for (auto &[code_sec, func_symbol_mp] : sec_symbol_mp) {

      bfd_vma sec_vma = bfd_section_vma(code_sec);
      bfd_size_type sec_size = bfd_section_size(code_sec);

      auto sym_it = func_symbol_mp.begin();

      // Add the head of the section as one function.
      if (sym_it->first != sec_vma) {
        auto head_lifted_func_name = GetUniqueLiftedFuncName("_ecv_firstsec_", sec_vma);
        disasm_funcs.emplace(sec_vma,
                             DisasmFunc(head_lifted_func_name, sec_vma, sym_it->first - sec_vma));
      }

      // Add the every function of the code section.
      while (sym_it != func_symbol_mp.end()) {
        // Detected function by r2.
        auto symbol = sym_it->second;
        auto addr_end = sym_it == std::prev(func_symbol_mp.end()) ? sec_vma + sec_size
                                                                  : std::next(sym_it)->second.addr;
        auto lifted_func_name = GetUniqueLiftedFuncName(symbol.sym_name, symbol.addr);
        disasm_funcs.emplace(symbol.addr,
                             DisasmFunc(lifted_func_name, symbol.addr, addr_end - symbol.addr));

        // Set program entry point function if applicapable.
        if (entry_point == symbol.addr) {
          if (!entry_func_lifted_name.empty()) {
            elfconv_runtime_error("[ERROR] multiple entrypoints are found.\n");
          }
          entry_func_lifted_name = lifted_func_name;
        }
        sym_it++;
      }
    }
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
  } else {
    elfconv_runtime_error("[ERROR] Entry function is not defined.\n");
  }
}