#pragma once

#include "Memory.h"
#include "remill/Arch/Runtime/Types.h"
#include "runtime/syscalls/SysTable.h"

class RuntimeManager {
 public:
  RuntimeManager(ECV_PROCESS __ecv_process) : ecv_processes({__ecv_process}), cur_id(0) {}
  RuntimeManager() {}

  // translates vma_addr to the address of the memory arena
  void *TranslateVMA(addr_t vma_addr) {
    return ecv_processes[cur_id].memory_arena.bytes + (vma_addr - MEMORY_ARENA_VMA);
  };

  // Linux system calls emulation
  void SVCBrowserCall();  // for browser
  void SVCWasiCall();  // for wasi
  void SVCNativeCall();  // for native
  // unimplemented syscall
  void UnImplementedBrowserSyscall();
  void UnImplementedWasiSyscall();
  void UnImplementedNativeSyscall();

  // elfconv psuedo-process
  std::vector<ECV_PROCESS> ecv_processes;
  uint64_t cur_id;
  emscripten_fiber_t cur_fb;

  std::vector<std::pair<addr_t, LiftedFunc>> addr_funptr_srt_list;
  std::unordered_map<addr_t, const char *> addr_fun_symbol_map;
  std::map<addr_t, std::map<uint64_t, uint64_t *>> fun_bb_addr_map;
  std::vector<addr_t> call_stacks;

  int cnt = 0;
  std::unordered_map<std::string, uint64_t> sec_map;
};
