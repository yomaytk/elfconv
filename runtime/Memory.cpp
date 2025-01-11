#include "Memory.h"

#include <iomanip>
#include <iostream>
#include <utils/Util.h>
#include <utils/elfconv.h>

#if defined(ELF_IS_AARCH64)
#  define SPREG state.gpr.sp.qword
#elif defined(ELF_IS_AMD64)
#  define SPREG state.gpr.rsp.qword
#endif

/*
  MappedMemory
*/
MappedMemory *MappedMemory::VMAStackEntryInit(int argc, char *argv[],
                                              State &state /* start stack pointer */) {
  _ecv_reg64_t sp;
  addr_t vma = STACK_START_VMA;
  uint64_t len = STACK_SIZE;
  auto bytes = reinterpret_cast<uint8_t *>(malloc(len));
  memset(bytes, 0, len);

  /* Initialize the stack */
  sp = vma + len;

  /* Initialize AT_RANDOM */
  /* FIXME: this shouldn't be on the stack? */
  sp -= 16;
  // getentropy(bytes + (sp - vma), 16);
  memset(bytes + (sp - vma), 1, 16);
  _ecv_reg64_t randomp = sp;

  /* Initialize AT_PHDR */
  /* FIXME: this shouldn't be on the stack? */
  auto e_ph_size = __g_e_phent * __g_e_phnum;
  sp -= e_ph_size;
  memcpy(bytes + (sp - vma), __g_e_ph, e_ph_size);
  _ecv_reg64_t phdr = sp;

  /* auxv */
  struct {
    _ecv_reg64_t _ecv_a_type;
    union {
      _ecv_reg64_t _ecv_a_val;
    } _ecv_a_un;
  } _ecv_auxv64[] = {
#if defined(TARGET_IS_WASI)
    {3 /* AT_PHDR */, phdr},
    {4 /* AT_PHENT */, __g_e_phent},
    {5 /* AT_PHNUM */, __g_e_phnum},
    {6 /* AT_PAGESZ */, 4096},
    {9 /* AT_ENTRY */, __g_entry_pc},
    {11 /* AT_UID */, 42},
    {12 /* AT_EUID */, 42},
    {13 /* AT_GID */, 42},
    {14 /* AT_EGID */, 42},
    {23 /* AT_SECURE */, 0},
    {25 /* AT_RANDOM */, randomp},
    {0 /* AT_NULL */, 0},
#else
    {3 /* AT_PHDR */, phdr},
    {4 /* AT_PHENT */, __g_e_phent},
    {5 /* AT_PHNUM */, __g_e_phnum},
    {6 /* AT_PAGESZ */, 4096},
    {9 /* AT_ENTRY */, __g_entry_pc},
    {11 /* AT_UID */, getuid()},
    {12 /* AT_EUID */, geteuid()},
    {13 /* AT_GID */, getgid()},
    {14 /* AT_EGID */, getegid()},
    {23 /* AT_SECURE */, 0},
    {25 /* AT_RANDOM */, randomp},
    {0 /* AT_NULL */, 0},
#endif
  };
  sp -= sizeof(_ecv_auxv64);
  memcpy(bytes + (sp - vma), _ecv_auxv64, sizeof(_ecv_auxv64));

  /* TODO envp */
  sp -= sizeof(_ecv_reg64_t);
  /* TODO argv */
  // auto arg = argv;
  // while(*arg)
  //   arg++;
  // sp -= (arg - argv) + sizeof(addr_t);
  // memcpy(bytes + (sp - vma), (uint8_t*)argv, arg - argv);
  sp -= sizeof(_ecv_reg64_t) * (argc + 1);
  /* argc */
  sp -= sizeof(_ecv_reg64_t);
  auto argc64 = (_ecv_reg64_t) argc;
  memcpy(bytes + (sp - vma), &argc64, sizeof(_ecv_reg64_t));
  SPREG = sp;
  return new MappedMemory(MemoryAreaType::STACK, "Stack", vma, vma + len, len, bytes, bytes + len,
                          true);
}

MappedMemory *MappedMemory::VMAHeapEntryInit() {
  auto bytes = reinterpret_cast<uint8_t *>(malloc(HEAP_UNIT_SIZE));
  auto upper_bytes = bytes + HEAP_UNIT_SIZE;
  auto heap =
      new MappedMemory(MemoryAreaType::HEAP, "Heap", HEAPS_START_VMA,
                       HEAPS_START_VMA + HEAP_UNIT_SIZE, HEAP_UNIT_SIZE, bytes, upper_bytes, true);
  heap->heap_cur = HEAPS_START_VMA;
  return heap;
}

void MappedMemory::DebugEmulatedMemory() {
  std::cout << "memory_area_type: ";
  switch (memory_area_type) {
    case MemoryAreaType::STACK: std::cout << "STACK, "; break;
    case MemoryAreaType::HEAP: std::cout << "HEAP, "; break;
    case MemoryAreaType::DATA: std::cout << "DATA, "; break;
    case MemoryAreaType::RODATA: std::cout << "RODATA, "; break;
    case MemoryAreaType::OTHER: std::cout << "OTHER, "; break;
    default: elfconv_runtime_error("[ERROR] unknown memory area type, "); break;
  }
  std::cout << "name: " << name.c_str() << ", vma: 0x" << std::hex << std::setw(16)
            << std::setfill('0') << vma << ", len: " << std::dec << len << std::hex << std::setw(16)
            << std::setfill('0') << ", bytes: 0x" << (addr_t) bytes << ", upper_bytes: 0x"
            << (addr_t) upper_bytes << ", bytes_on_heap" << (bytes_on_heap ? "true" : "false")
            << std::endl;
}
