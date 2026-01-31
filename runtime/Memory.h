#pragma once

#include <cassert>
#include <cstring>
#include <pthread.h>
#include <stack>
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <unistd.h>

#if defined(ELF_IS_AARCH64)
#  include <remill/Arch/AArch64/Runtime/State.h>
#  include <remill/Arch/Runtime/Types.h>
#elif defined(ELF_IS_AMD64)
#  include <remill/Arch/Runtime/RemillTypes.h>
#  include <remill/Arch/X86/Runtime/State.h>
#endif

/*
 * Runtime virtual memory layout (256 MiB arena)
 *
 * 0x00000000                                                 0x10000000
 * |------------------------------ 256 MiB ------------------------------|
 *
 * 0x00000000..0x00010000  NULL guard (unmapped/reserved, 64 KiB)
 * 0x00010000..0x04000000  Low region: static/loader/TLS/etc.
 * 0x04000000..0x0A000000  brk heap region (96 MiB)
 * 0x0A000000..0x0F000000  mmap region (80 MiB)
 * 0x0F000000..0x0F001000  stack guard (4 KiB)
 * 0x0F001000..0x10000000  stack (usable: 16 MiB - 4 KiB)
 */

const size_t MEMORY_ARENA_VMA = 0x00000000ULL;
const size_t MEMORY_ARENA_SIZE = 256ULL * 1024 * 1024; /* 256 MiB */
const size_t NULL_GUARD_SIZE = 0x00010000ULL; /* 64 KiB */
const addr_t MEMORY_ARENA_USABLE_VMA = MEMORY_ARENA_VMA + NULL_GUARD_SIZE;
const size_t MEMORY_ARENA_USABLE_SIZE = MEMORY_ARENA_SIZE - NULL_GUARD_SIZE;

const addr_t LOW_REGION_VMA = MEMORY_ARENA_VMA + NULL_GUARD_SIZE; /* 0x00010000 */
const size_t LOW_REGION_SIZE = 0x04000000ULL - LOW_REGION_VMA; /* up to BRK_START */

/* brk (traditional heap) */
const addr_t BRK_START_VMA = 0x04000000ULL; /* 64 MiB */
const size_t BRK_REGION_SIZE = 96ULL * 1024 * 1024; /* 96 MiB: 0x04000000..0x0A000000 */
const addr_t BRK_END_VMA = BRK_START_VMA + BRK_REGION_SIZE;

/* mmap (anonymous mappings, arenas, large allocs, etc.) */
const addr_t MMAP_START_VMA = BRK_END_VMA; /* 0x0A000000ULL */
const size_t MMAP_REGION_SIZE = 80ULL * 1024 * 1024; /* 80 MiB: 0x0A000000..0x0F000000 */
const addr_t MMAP_END_VMA = MMAP_START_VMA + MMAP_REGION_SIZE;

/* stack guard */
const size_t STACK_GUARD_SIZE = 4ULL * 1024; /* 4 KiB: 0x0F000000..0x0F001000 */

/* stack */
const size_t STACK_REGION_SIZE = 16ULL * 1024 * 1024; /* 16 MiB */
const addr_t STACK_REGION_USABLE_VMA = MMAP_END_VMA + STACK_GUARD_SIZE; /* 0x0F001000 */
const addr_t STACK_TOP_VMA = MEMORY_ARENA_VMA + MEMORY_ARENA_SIZE; /* 0x10000000 */

/* Thread pointer / TLS base */
const addr_t THREAD_PTR = 0x00100000ULL; /* 1 MiB (inside low region) */

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
extern "C" uint64_t _ecv_fn_debug_vmas[];
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
              uint8_t *__bytes, addr_t __brk_cur, addr_t __mmap_cur)
      : memory_area_type(__memory_area_type),
        name(__name),
        vma(__vma),
        len(__len),
        bytes(__bytes),
        brk_cur(__brk_cur),
        mmap_cur(__mmap_cur) {}
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
  uint64_t brk_cur;
  uint64_t mmap_cur;
};

class EcvProcess {
 public:
  EcvProcess(uint32_t __ecv_pid, uint32_t __par_ecv_pid, uint32_t __ecv_pgid,
             MemoryArena *__memory_arena, State *__cpu_state,
             std::stack<std::pair<uint64_t, uint64_t>> __call_history)
      : ecv_pid(__ecv_pid),
        par_ecv_pid(__par_ecv_pid),
        ecv_pgid(__ecv_pgid),  // unused for now
        ecv_uid(0),
        ecv_euid(0),
        ecv_gid(0),
        ecv_egid(0),
        ecv_ttid(__ecv_pid),
        memory_arena(__memory_arena),
        cpu_state(__cpu_state),
        call_history(__call_history),
        parent_call_history(__call_history) {}

  uint32_t ecv_pid;
  uint32_t par_ecv_pid;
  uint32_t ecv_pgid;
  uint32_t ecv_uid;
  uint32_t ecv_euid;
  uint32_t ecv_gid;
  uint32_t ecv_egid;
  uint32_t ecv_ttid;
  MemoryArena *memory_arena;
  State *cpu_state;

  // for multi process.
  std::stack<std::pair</* func addr */ uint64_t, /* return addresss */ uint64_t>> call_history;
  std::stack<std::pair</* func addr */ uint64_t, /* return addresss */ uint64_t>>
      parent_call_history;
};
