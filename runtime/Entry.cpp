#include "Memory.h"
#include "Runtime.h"
#include "remill/Arch/Runtime/Types.h"
#include "runtime/syscalls/SysTable.h"
#include "utils/Util.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <map>
#include <remill/Arch/Runtime/Intrinsics.h>
#include <remill/BC/HelperMacro.h>
#include <stdio.h>

// MemoryArenaPtr is used in the lifted LLVM IR for calculating the correct memory address (e.g. __remill_read_memory_macro* function).
State *CPUState;

#if defined(ELF_IS_AMD64)
uint8_t *MemoryArenaPtr = nullptr;
#endif

#if defined(__wasm__)
int main(int argc, char *argv[]) {
#else
int main(int argc, char *argv[], char *envp[]) {
#endif

  State *cpu_state = new State();
  MemoryArena *memory_arena;

  // set the global data of CPU state.
  CPUState = cpu_state;

#if defined(__wasm__)
  memory_arena = MemoryArena::MemoryArenaInit(argc, argv, NULL, cpu_state);
#else
  memory_arena = MemoryArena::MemoryArenaInit(argc, argv, envp, cpu_state);
#endif

#if defined(ELF_IS_AMD64)
  // set the global data of memory arena pointer.
  MemoryArenaPtr = memory_arena->bytes;
#endif

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
#endif

  EcvProcess *main_ecv_pr;

  main_ecv_pr = new EcvProcess(42, memory_arena, cpu_state, {});

  auto rt_m = new RuntimeManager(main_ecv_pr);

  // Set lifted function pointer table
  for (size_t i = 0; _ecv_fun_vmas[i] && _ecv_fun_ptrs[i]; i++) {
    rt_m->addr_funptr_srt_list.push_back({_ecv_fun_vmas[i], _ecv_fun_ptrs[i]});
  }
  std::sort(rt_m->addr_funptr_srt_list.begin(), rt_m->addr_funptr_srt_list.end());

#if defined(LIFT_CALLSTACK_DEBUG)
  //  Set lifted function symbol table (for debug)
  for (int i = 0; __g_fn_vmas_second[i] && __g_fn_symbol_table[i]; i++) {
    rt_m->addr_fn_symbol_map[__g_fn_vmas_second[i]] = (const char *) __g_fn_symbol_table[i];
  }
#endif

  //  Set global block address data array
  for (size_t i = 0; i < _ecv_block_address_array_size; i++) {
    auto bb_num = _ecv_block_address_size_array[i];
    std::map<uint64_t, uint64_t *> vma_bb_map;
    for (size_t j = 0; j < bb_num; j++) {
      vma_bb_map.insert({_ecv_block_address_vmas_array[i][j], _ecv_block_address_ptrs_array[i][j]});
    }
    rt_m->fun_bb_addr_map.insert({_ecv_block_address_fn_vma_array[i], vma_bb_map});
  }

  //  Go to the entry function (_ecv_entry_func is injected by lifted LLVM IR)
  _ecv_entry_func(memory_arena->bytes, CPUState, _ecv_entry_pc, rt_m);

  delete (rt_m);

  return 0;
}

#if defined(__EMSCRIPTEN__) && defined(_FORK_EMULATION_)
#  include <emscripten/emscripten.h>

/// code for fork emulation on emscripten and browser

uint8_t *MemoryBytes;
uint8_t *SharedData;

/// SharedDataArray content:
/// [ CPUState (sizeof(CPUState) byte); memory_arena_type: (4 byte); vma (4 byte); len (4 byte);
///   heap_cur (4 byte); t_func_addr (4 byte); t_next_pc (4 byte);
///   parent_call_history_len (4 byte); [ t_func_addr_1, t_func_next_pc_1, ..., t_func_addr_n, t_func_next_pc_n ] (8 * parent_call_history_len byte); ]
uint32_t SharedDataArray[2];

extern "C" EMSCRIPTEN_KEEPALIVE uint32_t get_shared_data_p() {
  printf("get_shared_data_p enter!");
  MemoryBytes = (uint8_t *) malloc(MEMORY_ARENA_SIZE);
  SharedData = (uint8_t *) malloc(2000);
  SharedDataArray[0] = (uint32_t) MemoryBytes;
  SharedDataArray[1] = (uint32_t) SharedData;
  printf("MemoryBytes: %p, SharedData: %p\n", MemoryBytes, SharedData);
  return (uint32_t) SharedDataArray;
}

// entry function when this program starts as forked process.
extern "C" EMSCRIPTEN_KEEPALIVE void fork_main() {

  printf("enter fork_main!");

  auto cpu_state = new State();
  auto memory_arena = new MemoryArena();

  CPUState = cpu_state;

  /// decodes shared process state using shared_data.
  // CPUState
  memcpy(cpu_state, SharedData, sizeof(State));

  // Memory Arena
  uint32_t *memory_arena_src_p = (uint32_t *) (SharedData + sizeof(State));
  memory_arena->memory_area_type = (MemoryAreaType) memory_arena_src_p[0];
  memory_arena->vma = memory_arena_src_p[1];
  memory_arena->len = memory_arena_src_p[2];
  memory_arena->bytes = MemoryBytes;
  memory_arena->heap_cur = memory_arena_src_p[3];

  // next address info
  uint32_t *next_addr_p = memory_arena_src_p + 4;
  uint32_t t_func_addr = next_addr_p[0];
  uint32_t t_next_pc = next_addr_p[1];

  // call history
  std::stack<std::pair</* func addr */ uint64_t, /* return addresss */ uint64_t>> par_call_history;
  uint32_t *history_p = next_addr_p + 2;
  uint32_t history_size = history_p[0];
  for (int i = 2 * (history_size - 1); i >= 0; i -= 2) {
    par_call_history.push({history_p[1 + i], history_p[1 + i + 1]});
  }

  // simple log
  printf("shared_t_func_addr: %u\n", t_func_addr);
  printf("shared_t_next_pc: %u\n", t_next_pc);
  printf("cpu_state pc: %llu\n", cpu_state->gpr.pc.qword);
  printf("memory arena vma: %llu\n", memory_arena->vma);

  // auto cp_history = par_call_history;
  // while (!cp_history.empty()) {
  //   auto t = cp_history.top();
  //   printf("history: %lu, %lu", t.first, t.second);
  //   cp_history.pop();
  // }

  /// same settings as normal main before jumping to entry lifted function (t_func_addr & t_next_pc).
  // EcvProcess
  auto main_ecv_pr = new EcvProcess(42, memory_arena, cpu_state, par_call_history);
  // RuntimeManager
  auto rt_m = new RuntimeManager(main_ecv_pr);

  // Set lifted function pointer table
  for (size_t i = 0; _ecv_fun_vmas[i] && _ecv_fun_ptrs[i]; i++) {
    rt_m->addr_funptr_srt_list.push_back({_ecv_fun_vmas[i], _ecv_fun_ptrs[i]});
  }
  std::sort(rt_m->addr_funptr_srt_list.begin(), rt_m->addr_funptr_srt_list.end());

  //  Set global block address data array
  for (size_t i = 0; i < _ecv_block_address_array_size; i++) {
    auto bb_num = _ecv_block_address_size_array[i];
    std::map<uint64_t, uint64_t *> vma_bb_map;
    for (size_t j = 0; j < bb_num; j++) {
      vma_bb_map.insert({_ecv_block_address_vmas_array[i][j], _ecv_block_address_ptrs_array[i][j]});
    }
    rt_m->fun_bb_addr_map.insert({_ecv_block_address_fn_vma_array[i], vma_bb_map});
  }

  /// execute functions.
  LiftedFunc t_func;

  auto t_func_it = std::lower_bound(
      rt_m->addr_funptr_srt_list.begin(), rt_m->addr_funptr_srt_list.end(), t_func_addr,
      [](auto const &lhs, addr_t value) { return lhs.first < value; });

  t_func = t_func_it->second;

  if (!t_func) {
    elfconv_runtime_error("The function corresponding to t_func_addr (0x%lx) is not found.\n",
                          t_func_addr);
  }

  // jump to the forked function.
  t_func(memory_arena->bytes, cpu_state, t_next_pc, rt_m);

  // execution loop consuming `parent_call_history`.
  for (;;) {
    if (cpu_state->func_depth == 0) {
      LiftedFunc tn_func;

      if (main_ecv_pr->parent_call_history.empty()) {
        elfconv_runtime_error("parent_call_history must not be empty.\n");
      }

      auto [tn_func_addr, tn_func_next_pc] = main_ecv_pr->parent_call_history.top();
      main_ecv_pr->parent_call_history.pop();

      auto tn_func_it = std::lower_bound(
          rt_m->addr_funptr_srt_list.begin(), rt_m->addr_funptr_srt_list.end(), tn_func_addr,
          [](auto const &lhs, addr_t value) { return lhs.first < value; });
      tn_func = tn_func_it->second;

      cpu_state->gpr.pc.qword = tn_func_next_pc;
      cpu_state->func_depth = 1;
      main_ecv_pr->call_history.pop();

      // jump to the function the top of history.
      tn_func(main_ecv_pr->memory_arena->bytes, CPUState, tn_func_next_pc, rt_m);
    } else {
      elfconv_runtime_error(
          "function depth must be 0 after the normal function call finishing. function_depth: %ld\n",
          CPUState->func_depth);
    }
  }

  elfconv_runtime_error("This point must be reached.");
}
#endif