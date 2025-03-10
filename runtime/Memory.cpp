#include "Memory.h"

#include <iomanip>
#include <iostream>
#include <utils/Util.h>
#include <utils/elfconv.h>

#if defined(ELF_IS_AARCH64)
#  define SPREG state.gpr.sp.qword
#elif defined(ELF_IS_AMD64)
#  define SPREG state.gpr.rsp.qword
#else
#  define SPREG state.gpr.sp.qword
#endif

MappedMemory *MappedMemory::MemoryArenaInit(int argc, char *argv[],
                                            State &state /* start stack pointer */) {
  // init stack
  _ecv_reg64_t sp;
  auto bytes = reinterpret_cast<uint8_t *>(malloc(MEMORY_ARENA_SIZE));
  memset(bytes, 0, MEMORY_ARENA_SIZE);

  // Initialize stack
  sp = STACK_START_VMA + STACK_SIZE;

  // Initialize AT_RANDOM
  /* FIXME: this shouldn't be on the stack? */
  sp -= 16;
  // getentropy(bytes + (sp - vma), 16);
  memset(bytes + (sp - MEMORY_ARENA_VMA), 1, 16);
  _ecv_reg64_t randomp = sp;

  /* Initialize AT_PHDR */
  /* FIXME: this shouldn't be on the stack? */
  auto e_ph_size = __g_e_phent * __g_e_phnum;
  sp -= e_ph_size;
  memcpy(bytes + (sp - MEMORY_ARENA_VMA), __g_e_ph, e_ph_size);
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
  memcpy(bytes + (sp - MEMORY_ARENA_VMA), _ecv_auxv64, sizeof(_ecv_auxv64));

  /* envp (FIXME) */
  sp -= sizeof(_ecv_reg64_t);

  /* argv (FIXME) */
  // auto arg = argv;
  // while(*arg)
  //   arg++;
  // sp -= (arg - argv) + sizeof(addr_t);
  // memcpy(bytes + (sp - vma), (uint8_t*)argv, arg - argv);
  sp -= sizeof(_ecv_reg64_t) * (argc + 1);

  /* argc */
  sp -= sizeof(_ecv_reg64_t);
  auto argc64 = (_ecv_reg64_t) argc;
  memcpy(bytes + (sp - MEMORY_ARENA_VMA), &argc64, sizeof(_ecv_reg64_t));

  SPREG = sp;

  return new MappedMemory(MemoryAreaType::OTHER, "MemoryArena", MEMORY_ARENA_VMA, MEMORY_ARENA_SIZE,
                          bytes, HEAPS_START_VMA);
}
