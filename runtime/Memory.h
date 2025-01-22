#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>

#include <remill/Arch/Runtime/Types.h>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#if defined(ELF_IS_AARCH64)
#  include <remill/Arch/AArch64/Runtime/State.h>
#elif defined(ELF_IS_AMD64)
#  include <remill/Arch/X86/Runtime/State.h>
#endif

const addr_t STACK_START_VMA = 0x0fff'ff00'0000'0000; /* 65535 TiB FIXME! */
const size_t STACK_SIZE = 1 * 1024 * 1024; /* 4 MiB */
const addr_t HEAPS_START_VMA = 0x4000'0000'0000; /* 64 TiB FIXME! */
const uint64_t HEAP_UNIT_SIZE = 1 * 1024 * 1024 * 1024; /* 1 GiB */

typedef uint32_t _ecv_reg_t;
typedef uint64_t _ecv_reg64_t;
class MappedMemory;
class RuntimeManager;

// /* own implementation of syscall emulation */
// extern void __svc_native_call();
// extern void __svc_browser_call();
// extern void __svc_wasi_call();
// /* translate the address of the original ELF to the actual address of mapped space */
// // extern void *_ecv_translate_ptr(addr_t vma_addr);
// extern "C" uint64_t *__g_get_indirectbr_block_address(uint64_t fun_vma, uint64_t bb_vma);

// /* get mapped memory address of vma */
// template <typename T>
// T *getMemoryAddr(addr_t vma_addr) {
//   return reinterpret_cast<T *>(_ecv_translate_ptr(vma_addr));
// }

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
  OTHER,
};
struct XMemory {
  virtual ~XMemory();
  virtual uint8_t get(uint64_t x) = 0;
  virtual void set(uint64_t x, uint8_t y) = 0;
  template <typename T>
  void read(uint64_t p, T *b, size_t c = 1) {
    uint8_t buf[sizeof(T) * c];
    for (size_t a = 0; a < sizeof(T) * c; a++)
      buf[a] = get(p + a);
    memcpy((void *) b, (const void *) buf, sizeof(T) * c);
  }
  template <typename T>
  void write(uint64_t p, const T *b, size_t c = 1) {
    uint8_t buf[sizeof(T) * c];
    memcpy((void *) buf, (const void *) b, sizeof(T) * c);
    for (size_t a = 0; a < sizeof(T) * c; a++)
      set(p + a, buf[a]);
  }
  inline std::string cstr(uint64_t x) {
    std::string a;
    while (get(x)) {
      a.push_back((char) get(x));
      x++;
    }
    return a;
  }
};
template <typename M>
struct MapXMemory : XMemory {
  M map;
  MapXMemory(M map) : map(map) {}
  uint8_t get(uint64_t x) override {
    return map[x];
  }
  void set(uint64_t x, uint8_t y) override {
    map[x] = y;
  };
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
                                         State &state /* start stack pointer */);
  static MappedMemory *VMAHeapEntryInit();
  void DebugEmulatedMemory();

  MemoryAreaType memory_area_type;
  std::shared_ptr<XMemory> other_memory;
  std::string name;
  addr_t vma;
  addr_t vma_end;
  uint64_t len;
  uint8_t *bytes;
  uint8_t *upper_bytes;
  bool bytes_on_heap;  // whether or not bytes is allocated on the heap memory
  uint64_t heap_cur; /* for Heap */
};

class RuntimeManager : public XMemory {
 public:
  RuntimeManager(std::vector<MappedMemory *> __mapped_memorys, MappedMemory *__mapped_stack,
                 MappedMemory *__mapped_heap)
      : mapped_memorys(__mapped_memorys),
        stack_memory(__mapped_stack),
        heap_memory(__mapped_heap),
        addr_fn_map({}) {}
  RuntimeManager() {}
  ~RuntimeManager() {
    for (auto memory : mapped_memorys)
      delete (memory);
  }
  /* translate vma address to the actual mapped memory address */
  // void *TranslateVMA(addr_t vma_addr);
  void DebugEmulatedMemorys() {
    for (auto memory : mapped_memorys)
      memory->DebugEmulatedMemory();
  }

  std::vector<MappedMemory *> mapped_memorys;
  MappedMemory *stack_memory;
  MappedMemory *heap_memory;
  /* heap area manage */
  addr_t heaps_end_addr;
  std::unordered_map<addr_t, LiftedFunc> addr_fn_map;
  std::unordered_map<addr_t, const char *> addr_fn_symbol_map;
  std::map<addr_t, std::map<uint64_t, uint64_t *>> addr_block_addrs_map;
  std::vector<addr_t> call_stacks;

  int cnt = 0;
  std::unordered_map<std::string, uint64_t> sec_map;
  uint8_t get(uint64_t x) override;
  void set(uint64_t x, uint8_t y) override;
};

// extern RuntimeManager *g_run_mgr;
