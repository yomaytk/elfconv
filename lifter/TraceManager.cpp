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
    /*
      No function starts after `addr`, so there is no next-function boundary to size this one
      with. That is a reachable state rather than a bug: it happens whenever control reaches
      the LAST unclaimed region of a code section, which on amd64 occurs on the first real
      binary because `.plt`-style regions and `.text` tails are not all named by symbols.

      Bound it by the end of the section that contains `addr` — the same rule the symbol walk
      in SetELFObject already applies to the last function it finds, so this is the existing
      convention rather than a new one.

      The FATAL is kept for the case it was actually written for: an address that lies in no
      code section at all, which really would be a bug and must not be silently given a size.
    */
    end_addr = 0;
    for (auto &[sec_name, sec] : elf_obj.code_sections) {
      (void) sec_name;
      if (sec.vma <= addr && addr < sec.vma + sec.size) {
        end_addr = sec.vma + sec.size;
        break;
      }
    }
    if (0 == end_addr) {
      LOG(FATAL) << "[Bug] rest_disasm_func at 0x" << std::hex << addr
                 << " lies outside every code section.";
    }
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
  lifted_fn_name << func_name << "_____" << std::to_string(unique_i64++) << "_" << std::hex
                 << vma_s;
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
#if defined(ELFCONV_X86_BUILD) && ELFCONV_X86_BUILD == 1
    /*
      amd64: PLT entries are FIXED-SIZE, so they are split by size rather than by scanning for
      a terminator.

      The AArch64 branch below walks 4 bytes at a time looking for a `br` to end each entry.
      On amd64 that scan can never terminate an entry — the bytes it matches are AArch64
      encodings — so it ran to the end of the section and emitted ONE function spanning the
      whole `.plt`. Measured consequence: `fn_plt_401020` covering all 384 bytes of a 24-entry
      table, which the lifter then decoded as a single straight-line function, walked off the
      end of one stub into the next, and eventually produced a branch to 0x927371 — an address
      in no section of the image.

      Every amd64 PLT entry is 16 bytes by ABI, whether it is the classic
      `push`/`jmp *GOT(%rip)` pair or the IBT form that begins `endbr64`. The section's own
      `sh_entsize` says so too, but it is not relied on here: it is 0 on some linkers, so the
      constant is used and the section size is required to be a multiple of it before the
      split is trusted.
    */
    constexpr uint64_t kAmd64PltEntrySize = 16;
    if (plt_section.size % kAmd64PltEntrySize == 0) {
      for (uint64_t off = 0; off < plt_section.size; off += kAmd64PltEntrySize) {
        for (uint64_t b = 0; b < kAmd64PltEntrySize; b++) {
          memory[plt_section.vma + off + b] = plt_section.bytes[off + b];
        }
        auto b_entry = plt_section.vma + off;
        std::stringstream fn_name;
        fn_name << "fn_plt_" << std::hex << b_entry;
        disasm_funcs.emplace(b_entry, DisasmFunc(fn_name.str(), b_entry, kAmd64PltEntrySize));
      }
    } else {
      /* Not a table of 16-byte entries. Copying the bytes without claiming a function shape
         is strictly better than inventing one: the lifter can still read them, and nothing
         downstream is told a boundary that was guessed. */
      for (uint64_t off = 0; off < plt_section.size; off++) {
        memory[plt_section.vma + off] = plt_section.bytes[off];
      }
    }
#else
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
#endif
  }

  if (disasm_funcs.count(entry_point) != 1) {
    elfconv_runtime_error("[ERROR] Entry function is not defined.\n");
  }

#if defined(ELFCONV_AARCH64_BUILD) && ELFCONV_AARCH64_BUILD == 1

  /*
    define __wrap_main function (FIXME)
    __libc_start_call_main BLR jump to the instructions as following in _start.
    `nop`
    `b main`
    `nop`
  */
  {
    std::vector<uint64_t> s_t_addrs = {entry_point};
    uint64_t __wrap_main_size = AARCH64_OP_SIZE * 3;
    auto &text_section = elf_obj.code_sections[".text"];
    bool __wrap_main_found = false;
    uint64_t extra_search_size = 100;
    for (size_t j = 0; j < s_t_addrs.size(); j++) {
      auto func_size = disasm_funcs.contains(s_t_addrs[j]) ? disasm_funcs[s_t_addrs[j]].func_size
                                                           : __wrap_main_size;
      auto _s_fn_bytes = &text_section.bytes[s_t_addrs[j] - text_section.vma];
      for (uint64_t i = 0; i + __wrap_main_size <= func_size + extra_search_size; i += 4) {
        if (/* nop or bti c */ ((_s_fn_bytes[i] == 0x1f && _s_fn_bytes[i + 1] == 0x20) ||
                                (_s_fn_bytes[i] == 0x5f && _s_fn_bytes[i + 1] == 0x24)) &&
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
  }

#elif defined(ELFCONV_X86_BUILD) && ELFCONV_X86_BUILD == 1

  /*
    amd64: recover `main` from `_start`, which is a different problem from the AArch64 one
    above and must not be solved with the same code.

    The AArch64 branch exists because `__libc_start_call_main` reaches `main` through a
    trampoline — `nop` / `b main` / `nop` — that carries NO SYMBOL, so the lifter would have
    no function at the indirect-branch target unless one is synthesised. It matches those
    three instructions literally and steps 4 bytes at a time because every AArch64
    instruction is 4 bytes.

    Neither premise holds on amd64. Instructions are variable-length, so a fixed stride is
    meaningless; and there is no trampoline — the System V ABI passes `main` as the FIRST
    argument to `__libc_start_main`, so `_start` materialises its address into `%rdi` and
    `main` is an ordinary function that the symbol table and `.eh_frame` already name. Running
    the AArch64 scan here cannot match anything (those bytes are AArch64 encodings) and
    reaches `elfconv_runtime_error`, which is the abort this branch replaces.

    So the work here is not to synthesise a function. It is to READ the address out of
    `_start` and make sure a function exists at it — which, for a binary whose `main` is
    named, is already true and this loop simply confirms. The recovery matters for the case
    where it is not: `main` is `LOCAL` or absent while `.eh_frame` gave the range no name.

    Two encodings materialise the pointer, and both are emitted in practice:

      48 c7 c7 <imm32>    mov  $imm32, %rdi      non-PIE; imm32 is sign-extended to 64 bits
      48 8d 3d <rel32>    lea  rel32(%rip), %rdi PIE/static-PIE; target = end-of-insn + rel32

    A third, `bf <imm32>` (`mov $imm32, %edi`), writes the 32-bit register and is accepted for
    the same reason: on a non-PIE image the upper half is zero anyway.

    The scan is deliberately NARROW — it walks `_start` only, it accepts only these three
    opcodes, and it requires the recovered address to land inside a known code section. A
    byte-pattern search that ranges further would find `%rdi` loads that have nothing to do
    with `main`. If nothing is found, that is NOT fatal here: unlike AArch64 there is no
    missing function to synthesise, so lifting proceeds on the symbols that already exist.
  */
  {
    auto &text_section = elf_obj.code_sections[".text"];
    const uint64_t start_size = disasm_funcs[entry_point].func_size;
    const uint8_t *start_bytes = &text_section.bytes[entry_point - text_section.vma];
    uint64_t main_vma = 0;

    for (uint64_t i = 0; i + 7 <= start_size; i++) {
      if (start_bytes[i] == 0x48 && start_bytes[i + 1] == 0xc7 && start_bytes[i + 2] == 0xc7) {
        /* mov $imm32, %rdi — sign-extended, so read it as a signed 32-bit value. */
        int32_t imm = static_cast<int32_t>(start_bytes[i + 3] | (start_bytes[i + 4] << 8) |
                                           (start_bytes[i + 5] << 16) | (start_bytes[i + 6] << 24));
        main_vma = static_cast<uint64_t>(static_cast<int64_t>(imm));
        break;
      }
      if (start_bytes[i] == 0x48 && start_bytes[i + 1] == 0x8d && start_bytes[i + 2] == 0x3d) {
        /* lea rel32(%rip), %rdi — %rip is the address of the NEXT instruction, i.e. +7. */
        int32_t rel = static_cast<int32_t>(start_bytes[i + 3] | (start_bytes[i + 4] << 8) |
                                           (start_bytes[i + 5] << 16) | (start_bytes[i + 6] << 24));
        main_vma = entry_point + i + 7 + static_cast<int64_t>(rel);
        break;
      }
      if (start_bytes[i] == 0xbf) {
        /* mov $imm32, %edi — zero-extended by the hardware. */
        main_vma = static_cast<uint64_t>(start_bytes[i + 1] | (start_bytes[i + 2] << 8) |
                                         (start_bytes[i + 3] << 16) | (start_bytes[i + 4] << 24));
        break;
      }
    }

    if (main_vma != 0 && !disasm_funcs.contains(main_vma)) {
      /* Only reached when the address is real but unnamed. Bounded by the section that
         contains it, so the synthesised function never runs off the end of the image. */
      for (auto &[sec_name, sec] : elf_obj.code_sections) {
        (void) sec_name;
        if (sec.vma <= main_vma && main_vma < sec.vma + sec.size) {
          disasm_funcs.emplace(
              main_vma, DisasmFunc("__wrap_main", main_vma, (sec.vma + sec.size) - main_vma));
          break;
        }
      }
    }
  }

#endif
}