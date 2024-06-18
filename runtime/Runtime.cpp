#include "Runtime.h"

#include <utils/Util.h>
#include <utils/elfconv.h>

void *RuntimeManager::TranslateVMA(addr_t vma_addr) {
  /* search in every mapped memory */
  if (vma_addr >= stack_memory->vma)
    return reinterpret_cast<void *>(stack_memory->bytes + (vma_addr - stack_memory->vma));
  if (vma_addr >= heap_memory->vma)
    return reinterpret_cast<void *>(heap_memory->bytes + (vma_addr - heap_memory->vma));
  for (auto &memory : mapped_memorys) {
    if (memory->vma <= vma_addr && vma_addr < memory->vma_end)
      return reinterpret_cast<void *>(memory->bytes + (vma_addr - memory->vma));
  }
  debug_state_machine();
  /* not exist sections which includes the vma_addr. */
  elfconv_runtime_error("[ERROR] The accessed memory is not mapped. vma_addr: 0x%llx, PC: 0x%llx",
                        vma_addr, g_state.gpr.pc.qword);
}
