#include "Memory.h"
#include "Runtime.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <map>
#include <remill/Arch/Runtime/Intrinsics.h>
#include <remill/BC/HelperMacro.h>
#include <stdio.h>

State CPUState = State();

// memory_arena_ptr is used in the lifted LLVM IR for calculating the correct memory address (e.g. __remill_read_memory_macro* function).
extern "C" uint8_t *memory_arena_ptr = nullptr;

int main(int argc, char *argv[]) {

  std::vector<MappedMemory *> mapped_memorys;

  //  Allocate memorys.
  auto memory_arena = MappedMemory::MemoryArenaInit(argc, argv, CPUState);
  memory_arena_ptr = memory_arena->bytes;
  for (size_t i = 0; i < _ecv_data_sec_num; i++) {
    // remove covered section
    if (strncmp(reinterpret_cast<const char *>(_ecv_data_sec_name_ptr_array[i]), ".tbss", 5) == 0) {
      continue;
    }
    // copy every data secation to the memory arena.
    memcpy(memory_arena->bytes + _ecv_data_sec_vma_array[i], _ecv_data_sec_bytes_ptr_array[i],
           static_cast<size_t>(_ecv_data_sec_size_array[i]));
  }
#if defined(ELF_IS_AARCH64)
  //  set program counter
  CPUState.gpr.pc = {.qword = _ecv_entry_pc};
  // set system register (FIXME)
  CPUState.sr.tpidr_el0 = {.qword = 0};
  CPUState.sr.midr_el1 = {.qword = 0xf0510};
  CPUState.sr.ctr_el0 = {.qword = 0x80038003};
  CPUState.sr.dczid_el0 = {.qword = 0x4};
#endif
  auto runtime_manager = new RuntimeManager(mapped_memorys, memory_arena);

  // Set lifted function pointer table
  for (size_t i = 0; _ecv_fun_vmas[i] && _ecv_fun_ptrs[i]; i++) {
    runtime_manager->addr_funptr_srt_list.push_back({_ecv_fun_vmas[i], _ecv_fun_ptrs[i]});
  }
  std::sort(runtime_manager->addr_funptr_srt_list.begin(),
            runtime_manager->addr_funptr_srt_list.end());

#if defined(LIFT_CALLSTACK_DEBUG)
  //  Set lifted function symbol table (for debug)
  for (int i = 0; __g_fn_vmas_second[i] && __g_fn_symbol_table[i]; i++) {
    runtime_manager->addr_fn_symbol_map[__g_fn_vmas_second[i]] =
        (const char *) __g_fn_symbol_table[i];
  }
#endif

  //  Set global block address data array
  for (size_t i = 0; i < _ecv_block_address_array_size; i++) {
    auto bb_num = _ecv_block_address_size_array[i];
    std::map<uint64_t, uint64_t *> vma_bb_map;
    for (size_t j = 0; j < bb_num; j++) {
      vma_bb_map.insert({_ecv_block_address_vmas_array[i][j], _ecv_block_address_ptrs_array[i][j]});
    }
    runtime_manager->fun_bb_addr_map.insert({_ecv_block_address_fn_vma_array[i], vma_bb_map});
  }

  //  Go to the entry function (__g_entry_func is injected by lifted LLVM IR)
  _ecv_entry_func(&CPUState, _ecv_entry_pc, runtime_manager);

  delete (runtime_manager);

  return 0;
}
