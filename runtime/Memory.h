#pragma once

#include <cstring>
#include <map>
#include <remill/Arch/AArch64/Runtime/State.h>
#include <remill/Arch/Runtime/Types.h>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <vector>

const addr_t STACK_START_VMA = 0x0fff'ff00'0000'0000; /* 65535 TiB FIXME! */
const size_t STACK_SIZE = 1 * 1024 * 1024; /* 4 MiB */
const addr_t HEAPS_START_VMA = 0x4000'0000'0000; /* 64 TiB FIXME! */
const uint64_t HEAP_UNIT_SIZE = 1 * 1024 * 1024 * 1024; /* 1 GiB */

typedef uint32_t _ecv_reg_t;
typedef uint64_t _ecv_reg64_t;

extern "C" {
/* State machine which represents all CPU registers */
extern State g_state;
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

/* get mapped memory address of vma */
template <typename T>
T *getMemoryAddr(addr_t vma_addr) {
  return reinterpret_cast<T *>(_ecv_translate_ptr(vma_addr));
}

enum class MemoryAreaType : uint8_t {
  STACK,
  HEAP,
  DATA,
  RODATA,
  OTHER,
};

class MappedMemory {

 public:
  MappedMemory(MemoryAreaType __memory_area_type, std::string __name, addr_t __vma,
               addr_t __vma_end, uint64_t __len, uint8_t *__bytes, uint8_t *__upper_bytes,
               bool __bytes_on_heap)
      : memory_area_type(__memory_area_type),
        name(__name),
        vma(__vma),
        vma_end(__vma_end),
        len(__len),
        bytes(__bytes),
        upper_bytes(__upper_bytes),
        bytes_on_heap(__bytes_on_heap) {}
  MappedMemory() {}
  ~MappedMemory() {
    if (bytes_on_heap)
      free(bytes);
  }

  static MappedMemory *VMAStackEntryInit(int argc, char *argv[],
                                         State *state /* start stack pointer */);
  static MappedMemory *VMAHeapEntryInit();
  void DebugEmulatedMemory();

  MemoryAreaType memory_area_type;
  std::string name;
  addr_t vma;
  addr_t vma_end;
  uint64_t len;
  uint8_t *bytes;
  uint8_t *upper_bytes;
  bool bytes_on_heap;  // whether or not bytes is allocated on the heap memory
  uint64_t heap_cur; /* for Heap */
};
