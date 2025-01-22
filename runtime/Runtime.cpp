#include "Runtime.h"

#include <sstream>
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
  /* not exist sections which includes the vma_addr. */
  std::stringstream err_ss;
  err_ss << std::hex << "[ERROR] The accessed memory is not mapped. \nvma_addr: 0x" << vma_addr
         << "\nstack_memory->vma: 0x" << stack_memory->vma << "\nheap_memory->vma: 0x"
         << heap_memory->vma << "\n";
  for (auto &memory : mapped_memorys) {
    err_ss << memory->name << "->vma: 0x" << memory->vma << " ~ 0x" << memory->vma_end << "\n";
  }
  elfconv_runtime_error(err_ss.str().c_str());
}
