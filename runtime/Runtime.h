#pragma once

#include "Memory.h"
#include "utils/Util.h"
#if defined(ELF_IS_AARCH64)
#  include "remill/Arch/Runtime/Types.h"
#else
#  include "remill/Arch/Runtime/RemillTypes.h"
#endif
#include "runtime/syscalls/SysTable.h"

#include <cassert>
#include <mutex>
#include <queue>
#include <unordered_map>

#define FIBER_STACK_SIZE 32 * 1024

//  State machine which represents all CPU registers */
#if defined(__FORK_PTHREAD__)
thread_local extern "C" State *CPUState;
thread_local extern "C" uint64_t CurEcvPid;
#else
extern State *CPUState;
#endif

#if defined(ELF_IS_AMD64)
extern "C" uint8_t *MemoryArenaPtr;
#endif

extern void *ManageNewForkPthread(void *arg);

#if defined(__EMSCRIPTEN_FORK_FIBER__)
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
  RuntimeManager *rt_m;

  FiberArgs(LiftedFunc __lifted_func, State *__state, addr_t __addr, RuntimeManager *__rt_m)
      : lifted_func(__lifted_func),
        state(__state),
        addr(__addr),
        rt_m(__rt_m) {}
};
class RuntimeManager {
 public:
  RuntimeManager(EcvProcess *__ecv_process)
      : main_ecv_pid(__ecv_process->ecv_pid),
        ecv_processes({{__ecv_process->ecv_pid, __ecv_process}}),
        cur_ecv_process(__ecv_process),
        cur_memory_arena(__ecv_process->memory_arena) {}

  // translates vma_addr to the address of the memory arena
  void *TranslateVMA(uint8_t *arena_ptr, addr_t vma_addr) {
    return arena_ptr + (vma_addr - MEMORY_ARENA_VMA);
  };

  // Linux system calls emulation
  void SVCBrowserCall(uint8_t *arena_ptr);  // for browser
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

  void SwitchEcvProcessContext(EcvProcess *cur_ecv_pr, EcvProcess *next_ecv_pr) {
    assert(cur_ecv_pr == cur_ecv_process);
    cur_ecv_process = next_ecv_pr;
    cur_memory_arena = next_ecv_pr->memory_arena;
    CPUState = next_ecv_pr->cpu_state;
    // MemoryArenaPtr = next_ecv_pr->memory_arena->bytes; // MemoryArenPtr is used for only x86-64 binary, so disable this line.
  }

  void InitFiberForEcvProcess(EcvProcess *t_ecv_pr, addr_t t_fiber_func_addr, addr_t t_next_pc) {

    LiftedFunc t_func;

    auto t_func_it = std::lower_bound(
        addr_funptr_srt_list.begin(), addr_funptr_srt_list.end(), t_fiber_func_addr,
        [](auto const &lhs, addr_t value) { return lhs.first < value; });
    t_func = t_func_it->second;

    auto fiber_args = FiberArgs(t_func, t_ecv_pr->cpu_state,
                                t_next_pc,  // assumes that `next_pc` is saved to cpu_state.pc
                                this);

    t_ecv_pr->fb_t = reinterpret_cast<emscripten_fiber_t *>(
        malloc(sizeof(emscripten_fiber_t)));  // new fiber context.
    t_ecv_pr->cstack = malloc(FIBER_STACK_SIZE);
    t_ecv_pr->astack = malloc(FIBER_STACK_SIZE);

    emscripten_fiber_init(t_ecv_pr->fb_t, _ecv_fiber_init_wrapper, &fiber_args, t_ecv_pr->cstack,
                          FIBER_STACK_SIZE, t_ecv_pr->astack, FIBER_STACK_SIZE);
  }

  // elfconv psuedo-process
  uint64_t main_ecv_pid;
  std::unordered_map<uint64_t, EcvProcess *> ecv_processes;
  EcvProcess *cur_ecv_process;
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
#elif defined(__FORK_PTHREAD__)
class RuntimeManager {
 public:
  RuntimeManager(EcvProcess *__ecv_process) : main_ecv_pid(__ecv_process->ecv_pid) {}

  // translates vma_addr to the address of the memory arena
  void *TranslateVMA(uint8_t *arena_ptr, addr_t vma_addr) {
    return arena_ptr + (vma_addr - MEMORY_ARENA_VMA);
  };

  // Linux system calls emulation
  void SVCBrowserCall(uint8_t *arena_ptr);  // for browser
  void SVCWasiCall(uint8_t *arena_ptr);  // for wasi
  void SVCNativeCall(uint8_t *arena_ptr);  // for native
  // unimplemented syscall
  void UnImplementedBrowserSyscall();
  void UnImplementedWasiSyscall();
  void UnImplementedNativeSyscall();

  uint64_t GetNewEcvPID() {
    std::lock_guard<std::mutex> lock(mtx_);
    ecv_pthread_pid++;
    return ecv_pthread_pid;
  }

  inline static uint64_t ecv_pthread_pid = 42;
  inline static EcvProcess *ecv_prs[100];

  // elfconv psuedo-process
  uint64_t main_ecv_pid;
  std::mutex mtx_;

  std::vector<std::pair<addr_t, LiftedFunc>> addr_funptr_srt_list;
  std::unordered_map<addr_t, const char *> addr_fun_symbol_map;
  std::map<addr_t, std::map<uint64_t, uint64_t *>> fun_bb_addr_map;
  std::vector<addr_t> call_stacks;

  std::unordered_map<std::string, uint64_t> sec_map;
};

struct EcvPthreadArg {
  EcvProcess *ecv_pr;
  RuntimeManager *rt_m;
  LiftedFunc t_func;
  uint64_t next_pc;

  EcvPthreadArg(EcvProcess *_ecv_pr, RuntimeManager *_rt_m, LiftedFunc _t_func, uint64_t _next_pc)
      : ecv_pr(_ecv_pr),
        rt_m(_rt_m),
        t_func(_t_func),
        next_pc(_next_pc) {}
};

#else
class RuntimeManager {
 public:
  RuntimeManager(EcvProcess *__ecv_process)
      : ecv_processes({{42, __ecv_process}}),
        cur_ecv_process(__ecv_process),
        cur_memory_arena(__ecv_process->memory_arena) {}

  // translates vma_addr to the address of the memory arena
  void *TranslateVMA(uint8_t *arena_ptr, addr_t vma_addr) {
    return arena_ptr + (vma_addr - MEMORY_ARENA_VMA);
  };

  // Linux system calls emulation
  void SVCBrowserCall(uint8_t *arena_ptr);  // for browser
  void SVCWasiCall(uint8_t *arena_ptr);  // for wasi
  void SVCNativeCall(uint8_t *arena_ptr);  // for native
  // unimplemented syscall
  void UnImplementedBrowserSyscall();
  void UnImplementedWasiSyscall();
  void UnImplementedNativeSyscall();

  // elfconv psuedo-process
  std::unordered_map<uint64_t, EcvProcess *> ecv_processes;
  EcvProcess *cur_ecv_process;
  MemoryArena *cur_memory_arena;

  std::vector<std::pair<addr_t, LiftedFunc>> addr_funptr_srt_list;
  std::unordered_map<addr_t, const char *> addr_fun_symbol_map;
  std::map<addr_t, std::map<uint64_t, uint64_t *>> fun_bb_addr_map;
  std::vector<addr_t> call_stacks;

  int cnt = 0;
  std::unordered_map<std::string, uint64_t> sec_map;
};
#endif
