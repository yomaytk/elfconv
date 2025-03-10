#pragma once

#include <cstring>
#include <map>
#include <remill/Arch/Runtime/Types.h>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#if defined(ELF_IS_AARCH64)
#  include <remill/Arch/AArch64/Runtime/State.h>
#elif defined(ELF_IS_AMD64)
#  include <remill/Arch/X86/Runtime/State.h>
#else
#  include <remill/Arch/AArch64/Runtime/State.h>  // default
#endif

const size_t MEMORY_ARENA_SIZE = 512 * 1024 * 1024; /* 512 MiB */
const addr_t MEMORY_ARENA_VMA = 0;
const size_t STACK_SIZE = 4 * 1024 * 1024; /* 4 MiB */
const addr_t STACK_START_VMA = MEMORY_ARENA_VMA + MEMORY_ARENA_SIZE - STACK_SIZE;
const size_t HEAP_UNIT_SIZE = 252 * 1024 * 1024; /* 252 MiB */
const addr_t HEAPS_START_VMA = 256 * 1024 * 1024;

typedef uint32_t _ecv_reg_t;
typedef uint64_t _ecv_reg64_t;

extern "C" {
/* State machine which represents all CPU registers */
extern State CPUState;
/* Lifted entry function address */
extern const LiftedFunc __g_entry_func;
/* entry point of the original ELF */
extern const addr_t __g_entry_pc;
extern const uint8_t *__g_data_sec_name_ptr_array[];
extern const uint64_t __g_data_sec_vma_array[];
extern uint64_t __g_data_sec_size_array[];
extern uint8_t *__g_data_sec_bytes_ptr_array[];
extern const uint64_t __g_data_sec_num;
/* e_phentsize */
extern _ecv_reg_t __g_e_phent;
/* e_phnum */
extern _ecv_reg_t __g_e_phnum;
/* every program header bytes */
extern uint8_t __g_e_ph[];
/* lifted function pointer table */
extern uint64_t __g_fn_vmas[];
extern LiftedFunc __g_fn_ptr_table[];
/* platform name */
extern const char __g_platform_name[];
/* lifted function symbol table (for debug) */
extern const uint8_t *__g_fn_symbol_table[];
extern uint64_t __g_fn_vmas_second[];
/* block addres arrays of the lifted function which includes BR instruction */
extern uint64_t **__g_block_address_ptrs_array[];
extern const uint64_t *__g_block_address_vmas_array[];
extern const uint64_t __g_block_address_size_array[];
extern const uint64_t __g_block_address_fn_vma_array[];
extern const uint64_t __g_block_address_array_size;
}

enum class MemoryAreaType : uint8_t {
  STACK,
  HEAP,
  DATA,
  RODATA,
  ARENA,
  OTHER,
};

class MappedMemory {

 public:
  MappedMemory(MemoryAreaType __memory_area_type, std::string __name, addr_t __vma, uint64_t __len,
               uint8_t *__bytes, addr_t __heap_cur)
      : memory_area_type(__memory_area_type),
        name(__name),
        vma(__vma),
        len(__len),
        bytes(__bytes),
        heap_cur(__heap_cur) {}
  MappedMemory() {}
  ~MappedMemory() {
    free(bytes);
  }

  static MappedMemory *MemoryArenaInit(int argc, char *argv[],
                                       State &state /* start stack pointer */);

  MemoryAreaType memory_area_type;
  std::string name;
  addr_t vma;
  uint64_t len;
  uint8_t *bytes;
  uint64_t heap_cur; /* for Heap */
};
