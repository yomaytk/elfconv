#pragma once

#include "Memory.h"
#include "remill/Arch/Runtime/Types.h"
#include "runtime/syscalls/SysTable.h"

#include <queue>
#include <unordered_map>

#define FIBER_STACK_SIZE 32 * 1024

#if defined(__EMSCRIPTEN__)
struct EcvFiberData {
  emscripten_fiber_t *fb_t;
  void *cstack;
  void *astack;

  EcvFiberData(emscripten_fiber_t *__fb_t, void *__cstack, void *__astack)
      : fb_t(__fb_t),
        cstack(__cstack),
        astack(__astack) {}
};

struct FiberArgs {
  LiftedFunc lifted_func;
  State *state;
  addr_t addr;
  RuntimeManager *run_mgr;

  FiberArgs(LiftedFunc __lifted_func, State *__state, addr_t __addr, RuntimeManager *__run_mgr)
      : lifted_func(__lifted_func),
        state(__state),
        addr(__addr),
        run_mgr(__run_mgr) {}
};
#endif

#if defined(__EMSCRIPTEN__)
class RuntimeManager {
 public:
  RuntimeManager(ECV_PROCESS *__ecv_process)
      : main_ecv_pid(__ecv_process->ecv_pid),
        ecv_processes({{__ecv_process->ecv_pid, __ecv_process}}),
        cur_ecv_process(__ecv_process),
        cur_memory_arena(__ecv_process->memory_arena) {}

  // translates vma_addr to the address of the memory arena
  void *TranslateVMA(addr_t vma_addr) {
    return cur_memory_arena->bytes + (vma_addr - MEMORY_ARENA_VMA);
  };

  // Linux system calls emulation
  void SVCBrowserCall();  // for browser
  void SVCWasiCall();  // for wasi
  void SVCNativeCall();  // for native
  // unimplemented syscall
  void UnImplementedBrowserSyscall();
  void UnImplementedWasiSyscall();
  void UnImplementedNativeSyscall();

  // fiber
  void GcUnusedFibers() {
    for (auto unused_fiber : unused_fibers) {
      free(unused_fiber.fb_t);
      free(unused_fiber.astack);
      free(unused_fiber.cstack);
    }
    unused_fibers.clear();
  }

  // elfconv psuedo-process
  uint64_t main_ecv_pid;
  std::unordered_map<uint64_t, ECV_PROCESS *> ecv_processes;
  ECV_PROCESS *cur_ecv_process;
  MemoryArena *cur_memory_arena;
  std::queue<uint64_t> ecv_pid_queue;
  std::vector<EcvFiberData> unused_fibers;

  std::vector<std::pair<addr_t, LiftedFunc>> addr_funptr_srt_list;
  std::unordered_map<addr_t, const char *> addr_fun_symbol_map;
  std::map<addr_t, std::map<uint64_t, uint64_t *>> fun_bb_addr_map;
  std::vector<addr_t> call_stacks;

  int cnt = 0;
  std::unordered_map<std::string, uint64_t> sec_map;
};
#else
class RuntimeManager {
 public:
  RuntimeManager(ECV_PROCESS *__ecv_process)
      : ecv_processes({{42, __ecv_process}}),
        cur_ecv_process(__ecv_process),
        cur_memory_arena(__ecv_process->memory_arena) {}

  // translates vma_addr to the address of the memory arena
  void *TranslateVMA(addr_t vma_addr) {
    return cur_memory_arena->bytes + (vma_addr - MEMORY_ARENA_VMA);
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
  std::unordered_map<uint64_t, ECV_PROCESS *> ecv_processes;
  ECV_PROCESS *cur_ecv_process;
  MemoryArena *cur_memory_arena;

  std::vector<std::pair<addr_t, LiftedFunc>> addr_funptr_srt_list;
  std::unordered_map<addr_t, const char *> addr_fun_symbol_map;
  std::map<addr_t, std::map<uint64_t, uint64_t *>> fun_bb_addr_map;
  std::vector<addr_t> call_stacks;

  int cnt = 0;
  std::unordered_map<std::string, uint64_t> sec_map;
};
#endif