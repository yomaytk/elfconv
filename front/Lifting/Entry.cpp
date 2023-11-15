#include <stdio.h>
#include <cstring>
#include <cstdint>
#include "remill/Arch/Runtime/Intrinsics.h"
#include "remill/Arch/AArch64/Runtime/State.h"
#include "memory.h"

State g_state = State();
RuntimeManager *g_run_mgr;

int main(int argc, char* argv[]) {

  std::vector<EmulatedMemory*> emulated_memorys;

  /* allocate Stack */
  emulated_memorys.push_back(EmulatedMemory::VMAStackEntryInit(argc, argv, &g_state));
  /* allocate Heap */
  emulated_memorys.push_back(EmulatedMemory::VMAHeapEntryInit());
  /* allocate every sections */
  for (int i = 0; i < __g_data_sec_num; i++) {
    emulated_memorys.push_back( new EmulatedMemory(
      MemoryAreaType::DATA,
      reinterpret_cast<const char*>(__g_data_sec_name_ptr_array[i]),
      __g_data_sec_vma_array[i],
      static_cast<size_t>(__g_data_sec_size_array[i]),
      __g_data_sec_bytes_ptr_array[i],
      __g_data_sec_bytes_ptr_array[i] + __g_data_sec_size_array[i],
      false
      )
    );
  }
  /* set program counter */
  g_state.gpr.pc = { .qword = __g_entry_pc };
  /* set global RuntimeManager */
  g_run_mgr = new RuntimeManager (emulated_memorys);
  g_run_mgr->heap_num = 1;
  g_run_mgr->heaps_end_addr = HEAPS_START_VMA + HEAP_SIZE;
  /* set lifted function pointer table */
  for (int i = 0;__g_fn_vmas[i] && __g_fn_ptr_table[i];i++) {
    g_run_mgr->addr_fn_map[__g_fn_vmas[i]] = __g_fn_ptr_table[i];
  }
  /* go to the entry function (entry function is injected by lifted LLVM IR) */
  __g_entry_func(&g_state, __g_entry_pc, reinterpret_cast<Memory*>(g_run_mgr));

  delete(g_run_mgr);

  return 0;

}
