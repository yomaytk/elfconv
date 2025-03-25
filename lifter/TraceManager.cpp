#include "TraceManager.h"

#include "Lift.h"
#include "lifter/Binary/Loader.h"
#include "remill/Arch/Runtime/Types.h"

#include <algorithm>
#include <bfd.h>
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
    if (vrp_opt_mode) {
      return disasm_funcs[addr].func_name;
    } else {
      return disasm_funcs[addr].func_name + "_noopt";
    }
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

void AArch64TraceManager::SetELFData() {

  elf_obj.LoadELF();
  entry_point = elf_obj.entry;

  std::unordered_map<asection *, std::vector<BinaryLoader::ELFSymbol>> code_sec_func_mp;

  // Set text section
  elf_obj.SetCodeSection();

  // Set memory of code section bytes.
  for (auto &[_, code_sec] : elf_obj.code_sections) {
    for (addr_t addr = code_sec.vma; addr < code_sec.vma + code_sec.size; addr++) {
      memory[addr] = code_sec.bytes[addr - code_sec.vma];
    }
  }

  if (elf_obj.stripped) {

    for (auto fun_symbol : elf_obj.func_symbols) {
      if (code_sec_func_mp.contains(fun_symbol.in_section)) {
        code_sec_func_mp[fun_symbol.in_section].push_back(fun_symbol);
      } else {
        code_sec_func_mp[fun_symbol.in_section] = {fun_symbol};
      }
    }

    // Make DisasmFunc for the every section.
    // If there is an empty segment between functions, we lift the empty segment as one function.
    for (auto &[code_sec, func_symbols] : code_sec_func_mp) {
      std::sort(func_symbols.rbegin(), func_symbols.rend(),
                [](auto const &lhs, auto const &rhs) { return lhs.addr < rhs.addr; });
      bfd_vma sec_vma = bfd_section_vma(code_sec);
      bfd_size_type sec_size = bfd_section_size(code_sec);
      addr_t entry = sec_vma;
      for (size_t i = 0; i < func_symbols.size(); i++) {
        // Empty segment function.
        if (entry < func_symbols[i].addr) {
          auto empty_seg_fun_name = GetUniqueLiftedFuncName("empty_segment_func", entry);
          disasm_funcs.emplace(entry,
                               DisasmFunc(empty_seg_fun_name, entry, func_symbols[i].addr - entry));
        }
        // Detected function.
        auto lifted_func_name =
            GetUniqueLiftedFuncName(func_symbols[i].sym_name, func_symbols[i].addr);
        disasm_funcs.emplace(
            func_symbols[i].addr,
            DisasmFunc(lifted_func_name, func_symbols[i].addr, func_symbols[i].sym_size));
        // Set program entry point function if applicapable.
        if (entry_point == func_symbols[i].addr) {
          if (!entry_func_lifted_name.empty()) {
            elfconv_runtime_error("[ERROR] multiple entrypoints are found.\n");
          }
          entry_func_lifted_name = lifted_func_name;
        }
      }
      if (auto last_entry = func_symbols.back().addr + func_symbols.back().sym_size;
          last_entry < sec_vma + sec_size) {
        // Last empty segment function.
        auto last_empty_seg_fun_name = GetUniqueLiftedFuncName("empty_segment_func", last_entry);
        disasm_funcs.emplace(last_entry, DisasmFunc(last_empty_seg_fun_name, last_entry,
                                                    (sec_vma + sec_size) - last_entry));
      }
    }
  } else {

    auto &func_symbols = elf_obj.func_symbols;
    std::sort(func_symbols.begin(), func_symbols.end(),
              [](auto const &lhs, auto const &rhs) { return lhs.addr < rhs.addr; });

    for (size_t i = 0; i < func_symbols.size() - 1; i++) {
      auto lifted_func_name =
          GetUniqueLiftedFuncName(func_symbols[i].sym_name, func_symbols[i].addr);

      // (FIXME) tmp patch for `_IO_file_xsputn` function.
      if (strncmp(lifted_func_name.c_str(), "_IO_file_xsputn____", 19) == 0) {
        _io_file_xsputn_vma = func_symbols[i].addr;
      }

      // Set program entry point function if applicapable.
      if (entry_point == func_symbols[i].addr) {
        if (!entry_func_lifted_name.empty()) {
          elfconv_runtime_error("[ERROR] multiple entrypoints are found.\n");
        }
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