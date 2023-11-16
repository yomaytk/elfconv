#pragma once

#include <string>
#include <cstring>
#include <unistd.h>
#include <vector>
#include <unordered_map>
#include "remill/Arch/AArch64/Runtime/State.h"
#include "remill/Arch/Runtime/Types.h"

const addr_t STACK_START_VMA = 0x0fff'ff00'0000'0000; /* 65535 TiB FIXME! */
const size_t STACK_SIZE = 1 * 1024 * 1024; /* 4 MiB */
const addr_t HEAPS_START_VMA = 0x4000'0000'0000; /* 64 TiB FIXME! */
const uint64_t HEAP_SIZE = 1 * 1024 * 1024;  /* 1 MiB */

typedef uint32_t _ecv_reg_t;
typedef uint64_t _ecv_reg64_t;
class EmulatedMemory;
class RuntimeManager;

extern RuntimeManager *g_run_mgr;

/* own implementation of syscall emulation */
extern void __svc_call();
/* translate the address of the original ELF to the actual address of emulated space */
extern void *_ecv_translate_ptr(addr_t vma_addr);
/* debug function */
extern "C" void debug_state_machine();
extern "C" void debug_pc();

/* get emulated memory address of vma */
template <typename T>
T *getMemoryAddr(addr_t vma_addr) {
  auto pma_addr = reinterpret_cast<T*>(_ecv_translate_ptr(vma_addr));
  return pma_addr;
}

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
  extern const char *__g_platform_name;
}

enum class MemoryAreaType : uint8_t {
  STACK,
  HEAP,
  DATA,
  RODATA,
  OTHER,
};

class EmulatedMemory {

  public:
    EmulatedMemory(MemoryAreaType __memory_area_type, std::string __name, addr_t __vma, uint64_t __len, uint8_t *__bytes, uint8_t* __upper_bytes, bool __bytes_on_heap)
      : memory_area_type(__memory_area_type), name(__name), vma(__vma), len(__len), bytes(__bytes), bytes_on_heap(__bytes_on_heap), upper_bytes(__upper_bytes) {}
    ~EmulatedMemory() {
      if (bytes_on_heap)  free(bytes);
    }

    static EmulatedMemory *VMAStackEntryInit(int argc, char *argv[], State *state /* start stack pointer */);
    static EmulatedMemory *VMAHeapEntryInit();
    void DebugEmulatedMemory();

    MemoryAreaType memory_area_type;
    std::string name;
    addr_t vma;
    uint64_t len;
    uint8_t *bytes;
    uint8_t *upper_bytes;
    bool bytes_on_heap; // whether or not bytes is allocated on the heap memory
    uint64_t heap_cur; /* for Heap */
  
};

class RuntimeManager {
  public:
    RuntimeManager(std::vector<EmulatedMemory*> __emulated_memorys) : emulated_memorys(__emulated_memorys), addr_fn_map({}) {}
    RuntimeManager() {}
    ~RuntimeManager() {
      for (auto memory : emulated_memorys)
          delete(memory);
    }
    
    void *TranslateVMA(addr_t vma_addr);
    void DebugEmulatedMemorys() {
      for (auto memory : emulated_memorys)
          memory->DebugEmulatedMemory();
    }

    std::vector<EmulatedMemory*> emulated_memorys;
    /* heap area manage */
    addr_t heaps_end_addr;
    uint64_t heap_num;
    std::unordered_map<addr_t, LiftedFunc> addr_fn_map;
};
