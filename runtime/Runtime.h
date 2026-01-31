#pragma once

#include "Memory.h"
#include "utils/Util.h"

#include <pthread.h>
#if defined(ELF_IS_AARCH64)
#  include "remill/Arch/Runtime/Types.h"
#else
#  include "remill/Arch/Runtime/RemillTypes.h"
#endif

#include <cassert>
#include <map>
#include <unordered_map>
#include <vector>

extern State *CPUState;
// for debug
extern bool INVALID_ADDR_ACCESS;

#if defined(ELF_IS_AMD64)
extern "C" uint8_t *MemoryArenaPtr;
#endif

extern void *ManageNewForkPthread(void *arg);

class RuntimeManager {
 public:
  RuntimeManager(EcvProcess *__ecv_pr)
      : main_ecv_pr(__ecv_pr),
        main_memory_arena(__ecv_pr->memory_arena) {}

  // Linux system calls emulation
  void SVCBrowserCall(uint8_t *arena_ptr);  // for browser
  void SVCWasiCall(uint8_t *arena_ptr);  // for wasi
  void SVCNativeCall(uint8_t *arena_ptr);  // for native
  // unimplemented syscall
  void UnImplementedBrowserSyscall();
  void UnImplementedWasiSyscall();
  void UnImplementedNativeSyscall();

  // elfconv psuedo-process
  EcvProcess *main_ecv_pr;
  MemoryArena *main_memory_arena;

  std::vector<std::pair<addr_t, LiftedFunc>> addr_funptr_srt_list;
  std::map<addr_t, std::map<uint64_t, uint64_t *>> fun_bb_addr_map;
  std::vector<addr_t> call_stacks;

  // debug
  std::unordered_map<addr_t, const char *> addr_fun_symbol_map;
  std::unordered_map<uint64_t, int> func_cnt_map;
  uint64_t func_calling_cnt = 0;
};
