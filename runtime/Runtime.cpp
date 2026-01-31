#include "Runtime.h"

#include "Memory.h"
#include "utils/Util.h"

#include <cstdlib>
#include <remill/BC/HelperMacro.h>

bool INVALID_ADDR_ACCESS;

// translates vma_addr to the address of the memory arena
void *TranslateVMA(RuntimeManager *rt_m, uint8_t *arena_ptr, addr_t t_addr) {
#if defined(MEMORY_INSTRUMENT)
  int m_kind = 0;
  // stack
  if (STACK_REGION_USABLE_VMA <= t_addr && t_addr < STACK_TOP_VMA) {
    m_kind = 1;
  }
  // heap (brk)
  if (BRK_START_VMA <= t_addr && t_addr < rt_m->main_memory_arena->brk_cur) {
    m_kind = 2;
  }
  // mmap
  if (MMAP_START_VMA <= t_addr && t_addr < rt_m->main_memory_arena->mmap_cur) {
    m_kind = 3;
  }
  // data section
  for (size_t i = 0; i < _ecv_data_sec_num; i++) {
    if (_ecv_data_sec_vma_array[i] <= t_addr &&
        t_addr < _ecv_data_sec_vma_array[i] + _ecv_data_sec_size_array[i]) {
      m_kind = 4;
      break;
    }
  }
  if (m_kind == 0) {
    printf("stack: 0x%llx ~ 0x%llx\n", STACK_REGION_USABLE_VMA, STACK_TOP_VMA);
    printf("heap (brk): 0x%llx ~ 0x%llx\n", BRK_START_VMA, rt_m->main_memory_arena->brk_cur);
    printf("mmap: 0x%llx ~ 0x%llx\n", MMAP_START_VMA, rt_m->main_memory_arena->mmap_cur);
    for (size_t i = 0; i < _ecv_data_sec_num; i++) {
      printf("section[%zu]: 0x%llx ~ 0x%llx\n", i, _ecv_data_sec_vma_array[i],
             _ecv_data_sec_vma_array[i] + _ecv_data_sec_size_array[i]);
    }
    INVALID_ADDR_ACCESS = true;
    printf("invalid target addr: 0x%llx\n", t_addr);
    elfconv_runtime_error("[ERROR] Invalid Memory Access. t_addr: 0x%llx\n", t_addr);
  }
#endif
  return arena_ptr + (t_addr - MEMORY_ARENA_VMA);
};
