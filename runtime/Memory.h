#pragma once

#include <cassert>
#include <cstring>
#include <map>
#include <mutex>
#include <pthread.h>
#include <queue>
#include <set>
#include <stack>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#if defined(ELF_IS_AARCH64)
#  include <remill/Arch/AArch64/Runtime/State.h>
#  include <remill/Arch/Runtime/Types.h>
#elif defined(ELF_IS_AMD64)
#  include <remill/Arch/Runtime/RemillTypes.h>
#  include <remill/Arch/X86/Runtime/State.h>
#endif

const size_t MEMORY_ARENA_SIZE = 512 * 1024 * 1024; /* 512 MiB */
const addr_t MEMORY_ARENA_VMA = 0;
const size_t STACK_SIZE = 8 * 1024 * 1024; /* 8 MiB */
const addr_t STACK_LOWEST_VMA = MEMORY_ARENA_VMA + MEMORY_ARENA_SIZE - STACK_SIZE;
const size_t HEAP_UNIT_SIZE = 252 * 1024 * 1024; /* 252 MiB */
const addr_t HEAPS_START_VMA = 256 * 1024 * 1024;
const addr_t THREAD_PTR = 244 * 1024 * 1024;

typedef uint32_t _ecv_reg_t;
typedef uint64_t _ecv_reg64_t;

//  Lifted entry function pointer
extern "C" const LiftedFunc _ecv_entry_func;
//  Entry point of the ELF
extern "C" const addr_t _ecv_entry_pc;
//  Data of data sections of the ELF
extern "C" const uint8_t *_ecv_data_sec_name_ptr_array[];
extern "C" const uint64_t _ecv_data_sec_vma_array[];
extern "C" const uint64_t _ecv_data_sec_size_array[];
extern "C" const uint8_t *_ecv_data_sec_bytes_ptr_array[];
extern "C" const uint64_t _ecv_data_sec_num;
//  Program header data of the ELF
extern "C" _ecv_reg_t _ecv_e_phent;
extern "C" _ecv_reg_t _ecv_e_phnum;
extern "C" uint8_t _ecv_e_ph[];
//  Platform name of the target architecture
extern "C" uint8_t *_ecv_platform_name;
//  Lifted function pointer table
extern "C" uint64_t _ecv_fun_vmas[];
extern "C" LiftedFunc _ecv_fun_ptrs[];
//  Lifted function symbol table (for debug)
extern "C" const uint8_t *_ecv_fn_symbol_table[];
extern "C" uint64_t _ecv_fn_vmas_second[];
//  Basic block address arrays of the lifted function for indirect jump
extern "C" uint64_t **_ecv_block_address_ptrs_array[];
extern "C" const uint64_t *_ecv_block_address_vmas_array[];
extern "C" const uint64_t _ecv_block_address_size_array[];
extern "C" const uint64_t _ecv_block_address_fn_vma_array[];
extern "C" const uint64_t _ecv_block_address_array_size;

enum class MemoryAreaType : uint8_t {
  STACK,
  HEAP,
  DATA,
  RODATA,
  ARENA,
  OTHER,
};

class MemoryArena {

 public:
  MemoryArena(MemoryAreaType __memory_area_type, std::string __name, addr_t __vma, uint64_t __len,
              uint8_t *__bytes, addr_t __heap_cur, uint64_t __stack_init_diff)
      : memory_area_type(__memory_area_type),
        name(__name),
        vma(__vma),
        len(__len),
        bytes(__bytes),
        heap_cur(__heap_cur),
        stack_init_diff(__stack_init_diff) {}
  MemoryArena() {}
  ~MemoryArena() {
    free(bytes);
  }

  static MemoryArena *MemoryArenaInit(int argc, char *argv[], char *envp[],
                                      State *state /* start stack pointer */);

  MemoryAreaType memory_area_type;
  std::string name;
  addr_t vma;
  uint64_t len;
  uint8_t *bytes;
  uint64_t heap_cur; /* for Heap */
  uint64_t stack_init_diff;
};

#if defined(__FORK_PTHREAD__)
class EcvProcess {
 public:
  EcvProcess(MemoryArena *__memory_arena, State *__cpu_state,
             std::stack<std::pair<uint64_t, uint64_t>> __call_history)
      : memory_arena(__memory_arena),
        cpu_state(__cpu_state),
        ecv_pid(GetNewEcvPid()),
        call_history(__call_history),
        parent_call_history(__call_history) {}

  ~EcvProcess() {
    delete (memory_arena);
    free(cpu_state);
  }

  EcvProcess *EcvProcessCopied();

  static uint32_t GetNewEcvPid() {
    std::lock_guard<std::mutex> lock(ecv_pr_mtx);
    return ecv_order_pid++;
  }

  MemoryArena *memory_arena;
  State *cpu_state;

  // fork emulation
  static inline uint32_t ecv_order_pid = 42;
  static inline std::mutex ecv_pr_mtx;
  uint32_t ecv_pid;
  std::stack<std::pair</* func addr */ uint64_t, /* return addresss */ uint64_t>> call_history;
  std::stack<std::pair</* func addr */ uint64_t, /* return addresss */ uint64_t>>
      parent_call_history;
  uint32_t par_ecv_pid;
  std::set<uint32_t> childs;

  // wait emulation
  std::queue<uint32_t> child_wait_queue;
  pthread_mutex_t wait_queue_mtx_;
};
#else
class EcvProcess {
 public:
  EcvProcess(MemoryArena *__memory_arena, State *__cpu_state)
      : memory_arena(__memory_arena),
        cpu_state(__cpu_state) {}

  MemoryArena *memory_arena;
  State *cpu_state;
};
#endif
