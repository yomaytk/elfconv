#include "Memory.h"
#include "Runtime.h"
#include "runtime/syscalls/SysTable.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <map>
#include <remill/Arch/Runtime/Intrinsics.h>
#include <remill/BC/HelperMacro.h>
#include <stdio.h>

// MemoryArenaPtr is used in the lifted LLVM IR for calculating the correct memory address (e.g. __remill_read_memory_macro* function).
uint8_t *MemoryArenaPtr = nullptr;
State *CPUState;

// Emscripten main fiber data for `fork` emulation.
#if defined(__EMSCRIPTEN__)
#  define MAIN_ASTACK_SIZE 64 * 1024
emscripten_fiber_t MainFB;
char MainAstack[MAIN_ASTACK_SIZE];
#endif

#if defined(__wasm__)
int main(int argc, char *argv[]) {
#else
int main(int argc, char *argv[], char *envp[]) {
#endif

  State *cpu_state = new State();
  MemoryArena *memory_arena;

  CPUState = cpu_state;
  cpu_state->inst_count = 0;


#if defined(__wasm__)
  memory_arena = MemoryArena::MemoryArenaInit(argc, argv, NULL, cpu_state);
#else
  memory_arena = MemoryArena::MemoryArenaInit(argc, argv, envp, cpu_state);
#endif

  MemoryArenaPtr = memory_arena->bytes;

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
  cpu_state->gpr.pc = {.qword = _ecv_entry_pc};
  // set system register (FIXME)
  cpu_state->sr.tpidr_el0 = {.qword = THREAD_PTR};
  cpu_state->sr.midr_el1 = {.qword = 0xf0510};
  cpu_state->sr.ctr_el0 = {.qword = 0x80038003};
  cpu_state->sr.dczid_el0 = {.qword = 0x4};
#  if defined(DEBUG_WITH_QEMU)
  // QEMU seems to init PSTATE as the Z flag is raised.
  CPUState.ecv_nzcv = 0x40000000;
#  endif
#endif

  EcvProcess *main_ecv_process;

#if defined(__EMSCRIPTEN__)
  main_ecv_process = new EcvProcess(memory_arena, cpu_state, {});
#else
  main_ecv_process = new EcvProcess(memory_arena, cpu_state);
#endif

  auto runtime_manager = new RuntimeManager(main_ecv_process);

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

#if defined(__EMSCRIPTEN__)
  // register current cotext to the main fiber.
  emscripten_fiber_init_from_current_context(&MainFB, MainAstack, MAIN_ASTACK_SIZE);
  main_ecv_process->fb_t = &MainFB;
  main_ecv_process->astack = MainAstack;
  runtime_manager->cur_ecv_process->call_history.emplace(_ecv_entry_pc, _ecv_entry_pc);
#endif

  runtime_manager->cur_ecv_process->cpu_state->has_fibers = 0;

  //  Go to the entry function (__g_entry_func is injected by lifted LLVM IR)
  _ecv_entry_func(CPUState, _ecv_entry_pc, runtime_manager);

  delete (runtime_manager);

  return 0;
}
