#include "Memory.h"

#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <utils/Util.h>
#include <utils/elfconv.h>

#if defined(ELF_IS_AARCH64)
#  define SP_REG state.gpr.sp.qword
#elif defined(ELF_IS_AMD64)
#  define SP_REG state.gpr.rsp.qword
#else
#  define SP_REG state.gpr.sp.qword
#endif

#define SP_REAL_ADDR bytes + (sp - MEMORY_ARENA_VMA)

MappedMemory *MappedMemory::MemoryArenaInit(int argc, char *argv[], char *envp[], State &state) {

  char *env_ptr[1000];
#if defined(__wasm__)
  env_ptr[0] = NULL;
#else
  for (size_t i = 0; envp[i]; i++) {
    env_ptr[i] = envp[i];
  }
#endif
  /* Initialize Stack */
  _ecv_reg64_t sp;
  auto bytes = reinterpret_cast<uint8_t *>(malloc(MEMORY_ARENA_SIZE));
  memset(bytes, 0, MEMORY_ARENA_SIZE);
  sp = STACK_LOWEST_VMA + STACK_SIZE;

  // AT_RANDOM and AT_PHDR are not placed in the stack for the original execution of ELF binary.
  // Therefore, we handle the end point of the AT_PHDR as the stack bottom (actually, a little different by 16 bit alignment).
  /* Initialize AT_RANDOM */
  _ecv_reg64_t randomp;
  sp -= 16;
  // getentropy(bytes + (sp - vma), 16);
  memset(SP_REAL_ADDR, 1, 16);
  randomp = sp;

  /* Initialize AT_PHDR */
  _ecv_reg64_t phdr;
  auto e_ph_size = _ecv_e_phent * _ecv_e_phnum;
  sp -= e_ph_size;
  memcpy(SP_REAL_ADDR, _ecv_e_ph, e_ph_size);
  phdr = sp;

  sp -= sp & 0xf;  // This sp points to the stack bottom (16 bit align).

  // end marker
  sp -= sizeof(_ecv_reg64_t);
  *(_ecv_reg64_t *) (SP_REAL_ADDR) = (_ecv_reg64_t) NULL;

  /* Initialize env and argv contents */
  size_t envc = 0, envp_size = 0, argv_size = 0;
  size_t env_0_sp, argv_0_sp;
  size_t env_i_sp, argv_i_sp;

  for (size_t i = 0; env_ptr[i]; i++) {
    envc++;
    envp_size += strlen(env_ptr[i]) + 1;
  }
  for (size_t i = 0; i < (size_t) argc; i++) {
    argv_size += strlen(argv[i]) + 1;
  }

  env_0_sp = sp - envp_size;
  argv_0_sp = env_0_sp - argv_size;

  sp -= envp_size + argv_size;

  // env contents settings
  env_i_sp = env_0_sp;
  for (size_t i = 0; i < envc; i++) {
    memcpy(bytes + (env_i_sp - MEMORY_ARENA_VMA), env_ptr[i], strlen(env_ptr[i]) + 1);
    env_i_sp += strlen(env_ptr[i]) + 1;
  }

  // argv contents settings
  argv_i_sp = argv_0_sp;
  for (size_t i = 0; i < (size_t) argc; i++) {
    memcpy(bytes + (argv_i_sp - MEMORY_ARENA_VMA), argv[i], strlen(argv[i]) + 1);
    argv_i_sp += strlen(argv[i]) + 1;
  }

  // padding
  sp -= sp & 0xf;  // 16 bit align.

  /* Initialize auxv */
  struct {
    _ecv_reg64_t _ecv_a_type;
    union {
      _ecv_reg64_t _ecv_a_val;
    } _ecv_a_un;
  } _ecv_auxv64[] = {
#if defined(TARGET_IS_WASI)
    {3 /* AT_PHDR */, phdr},
    {4 /* AT_PHENT */, _ecv_e_phent},
    {5 /* AT_PHNUM */, _ecv_e_phnum},
    {6 /* AT_PAGESZ */, 4096},
    {9 /* AT_ENTRY */, _ecv_entry_pc},
    {11 /* AT_UID */, 42},
    {12 /* AT_EUID */, 42},
    {13 /* AT_GID */, 42},
    {14 /* AT_EGID */, 42},
    {23 /* AT_SECURE */, 0},
    {25 /* AT_RANDOM */, randomp},
    {0 /* AT_NULL */, 0},
#else
    {3 /* AT_PHDR */, {phdr}},
    {4 /* AT_PHENT */, {_ecv_e_phent}},
    {5 /* AT_PHNUM */, {_ecv_e_phnum}},
    {6 /* AT_PAGESZ */, {4096}},
    {9 /* AT_ENTRY */, {_ecv_entry_pc}},
    {11 /* AT_UID */, {getuid()}},
    {12 /* AT_EUID */, {geteuid()}},
    {13 /* AT_GID */, {getgid()}},
    {14 /* AT_EGID */, {getegid()}},
    {23 /* AT_SECURE */, {0}},
    {25 /* AT_RANDOM */, {randomp}},
    {0 /* AT_NULL */, {0}},
#endif
  };
  sp -= sizeof(_ecv_auxv64);
  memcpy(SP_REAL_ADDR, _ecv_auxv64, sizeof(_ecv_auxv64));

  /* Initialize env_ptr and argv pointers */
  sp -= sizeof(_ecv_reg64_t) * (envc + 1);
  env_i_sp = env_0_sp;
  for (size_t i = 0; i < envc; i++) {
    *(_ecv_reg64_t *) (SP_REAL_ADDR + sizeof(_ecv_reg64_t) * i) = env_i_sp;
    env_i_sp += strlen(env_ptr[i]) + 1;
  }
  // NULL for the head of env_ptr
  *(_ecv_reg64_t *) (SP_REAL_ADDR + sizeof(_ecv_reg64_t) * envc) = (_ecv_reg64_t) NULL;

  // argv poiner settings
  sp -= sizeof(_ecv_reg64_t) * (argc + 1);
  argv_i_sp = argv_0_sp;
  for (size_t i = 0; i < (size_t) argc; i++) {
    *(_ecv_reg64_t *) (SP_REAL_ADDR + sizeof(_ecv_reg64_t) * i) = argv_i_sp;
    argv_i_sp += strlen(argv[i]) + 1;
  }
  // NULL for the head of argv
  *(_ecv_reg64_t *) (SP_REAL_ADDR + sizeof(_ecv_reg64_t) * argc) = (_ecv_reg64_t) NULL;

  // argc settings
  sp -= sizeof(_ecv_reg64_t);
  *(_ecv_reg64_t *) (SP_REAL_ADDR) = argc;

  // starting stack pointer indicates the pointer of `argc`.
  SP_REG = sp;

  return new MappedMemory(MemoryAreaType::OTHER, "MemoryArena", MEMORY_ARENA_VMA, MEMORY_ARENA_SIZE,
                          bytes, HEAPS_START_VMA);
}
