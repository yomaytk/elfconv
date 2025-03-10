#include "Memory.h"
#include "Runtime.h"

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

  /* allocate every sections */
  auto memory_arena = MappedMemory::MemoryArenaInit(argc, argv, CPUState);
  memory_arena_ptr = memory_arena->bytes;
  for (int i = 0; i < __g_data_sec_num; i++) {
    // remove covered section
    if (strncmp(reinterpret_cast<const char *>(__g_data_sec_name_ptr_array[i]), ".tbss", 5) == 0) {
      continue;
    }
    // copy every data secation to the memory arena.
    memcpy(memory_arena->bytes + __g_data_sec_vma_array[i], __g_data_sec_bytes_ptr_array[i],
           static_cast<size_t>(__g_data_sec_size_array[i]));
  }
#if defined(ELF_IS_AARCH64)
  /* set program counter */
  CPUState.gpr.pc = {.qword = __g_entry_pc};
  /* set system register (FIXME) */
  CPUState.sr.tpidr_el0 = {.qword = 0};
  CPUState.sr.midr_el1 = {.qword = 0xf0510};
  CPUState.sr.ctr_el0 = {.qword = 0x80038003};
  CPUState.sr.dczid_el0 = {.qword = 0x4};
#endif
  /* set RuntimeManager */
  auto runtime_manager = new RuntimeManager(mapped_memorys, nullptr, nullptr, memory_arena);
  /* set lifted function pointer table */
  for (int i = 0; __g_fn_vmas[i] && __g_fn_ptr_table[i]; i++) {
    runtime_manager->addr_fn_map[__g_fn_vmas[i]] = __g_fn_ptr_table[i];
  }
#if defined(LIFT_CALLSTACK_DEBUG)
  /* set lifted function symbol table (for debug) */
  for (int i = 0; __g_fn_vmas_second[i] && __g_fn_symbol_table[i]; i++) {
    runtime_manager->addr_fn_symbol_map[__g_fn_vmas_second[i]] =
        (const char *) __g_fn_symbol_table[i];
  }
#endif
  /* set global block address data array */
  for (int i = 0; i < __g_block_address_array_size; i++) {
    auto bb_num = __g_block_address_size_array[i];
    std::map<uint64_t, uint64_t *> vma_bb_map;
    auto t_block_address_ptrs = __g_block_address_ptrs_array[i];
    auto t_block_address_vmas = __g_block_address_vmas_array[i];
    for (int j = 0; j < bb_num; j++)
      vma_bb_map[t_block_address_vmas[j]] = t_block_address_ptrs[j];
    runtime_manager->addr_block_addrs_map[__g_block_address_fn_vma_array[i]] = vma_bb_map;
  }
  /* go to the entry function (entry function is injected by lifted LLVM IR) */
  __g_entry_func(&CPUState, __g_entry_pc, runtime_manager);

  delete (runtime_manager);

  return 0;
}
