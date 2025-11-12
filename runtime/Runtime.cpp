#include "Runtime.h"

// translates vma_addr to the address of the memory arena
void *TranslateVMA(uint8_t *arena_ptr, addr_t vma_addr) {
  return arena_ptr + (vma_addr - MEMORY_ARENA_VMA);
};
