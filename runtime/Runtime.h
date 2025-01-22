#pragma once

#include "Memory.h"

class RuntimeManager {
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
  void *TranslateVMA(addr_t vma_addr);

  void DebugEmulatedMemorys() {
    for (auto memory : mapped_memorys)
      memory->DebugEmulatedMemory();
  }

  // Linux system calls emulation
  void SVCBrowserCall();  // for browser
  void SVCWasiCall();  // for wasi
  void SVCNativeCall();  // for native

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
};