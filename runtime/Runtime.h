#pragma once

#include "Memory.h"
#include "remill/Arch/Runtime/Types.h"
#include "runtime/syscalls/SysTable.h"

#include <queue>
#include <unordered_map>

#define FIBER_STACK_SIZE 32 * 1024

struct em_fiber_data {
  emscripten_fiber_t *fb_t;
  void *cstack;
  void *astack;
};

struct FiberArgs {
  State &state;
  addr_t addr;
  RuntimeManager *run_mgr;
};

class RuntimeManager {
 public:
  RuntimeManager(ECV_PROCESS __ecv_process)
      : ecv_processes({__ecv_process}),
        cur_ecv_process(__ecv_process) {}
  RuntimeManager() {}

  // translates vma_addr to the address of the memory arena
  void *TranslateVMA(addr_t vma_addr) {
    return cur_memory_arena.bytes + (vma_addr - MEMORY_ARENA_VMA);
  };

  // Linux system calls emulation
  void SVCBrowserCall();  // for browser
  void SVCWasiCall();  // for wasi
  void SVCNativeCall();  // for native
  // unimplemented syscall
  void UnImplementedBrowserSyscall();
  void UnImplementedWasiSyscall();
  void UnImplementedNativeSyscall();

  // elfconv psuedo-process
  std::unordered_map<uint64_t, ECV_PROCESS> ecv_processes;
  ECV_PROCESS cur_ecv_process;
  MemoryArena cur_memory_arena;
  std::queue<uint64_t> ecv_pid_queue;
  std::vector<em_fiber_data> unused_fiberts;

  std::vector<std::pair<addr_t, LiftedFunc>> addr_funptr_srt_list;
  std::unordered_map<addr_t, const char *> addr_fun_symbol_map;
  std::map<addr_t, std::map<uint64_t, uint64_t *>> fun_bb_addr_map;
  std::vector<addr_t> call_stacks;

  int cnt = 0;
  std::unordered_map<std::string, uint64_t> sec_map;
};
