#pragma once

#include "Memory.h"

class RuntimeManager {
 public:
  RuntimeManager(std::vector<MappedMemory *> __mapped_memorys, MappedMemory *__mapped_stack,
                 MappedMemory *__mapped_heap, MappedMemory *__memory_arena)
      : mapped_memorys(__mapped_memorys),
        stack_memory(__mapped_stack),
        heap_memory(__mapped_heap),
        memory_arena(__memory_arena),
        addr_fn_map({}) {}
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
  MappedMemory *stack_memory;
  MappedMemory *heap_memory;
  MappedMemory *memory_arena;
  std::unordered_map<addr_t, LiftedFunc> addr_fn_map;
  std::unordered_map<addr_t, const char *> addr_fn_symbol_map;
  std::map<addr_t, std::map<uint64_t, uint64_t *>> addr_block_addrs_map;
  std::vector<addr_t> call_stacks;

  int cnt = 0;
  std::unordered_map<std::string, uint64_t> sec_map;
};