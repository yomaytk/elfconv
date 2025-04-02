#pragma once

#include "Memory.h"
#include "remill/Arch/Runtime/Types.h"

class RuntimeManager {
 public:
  RuntimeManager(std::vector<MappedMemory *> __mapped_memorys, MappedMemory *__memory_arena)
      : mapped_memorys(__mapped_memorys),
        memory_arena(__memory_arena) {}
  RuntimeManager() {}
  ~RuntimeManager() {
    for (auto memory : mapped_memorys)
      delete (memory);
  }

  // translates vma_addr to the address of the memory arena
  void *TranslateVMA(addr_t vma_addr) {
    return memory_arena->bytes + vma_addr;
  };

  // Linux system calls emulation
  void SVCBrowserCall();  // for browser
  void SVCWasiCall();  // for wasi
  void SVCNativeCall();  // for native

  std::vector<MappedMemory *> mapped_memorys;
  MappedMemory *memory_arena;
  std::vector<std::pair<addr_t, LiftedFunc>> addr_funptr_srt_list;
  std::unordered_map<addr_t, const char *> addr_fun_symbol_map;
  std::map<addr_t, std::map<uint64_t, uint64_t *>> fun_bb_addr_map;
  std::vector<addr_t> call_stacks;

  int cnt = 0;
  std::unordered_map<std::string, uint64_t> sec_map;
};