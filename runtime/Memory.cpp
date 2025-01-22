#include "Memory.h"

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <utils/Util.h>
#include <utils/elfconv.h>

/*
  MappedMemory
*/
MappedMemory *MappedMemory::VMAStackEntryInit(int argc, char *argv[],
                                              State *state /* start stack pointer */) {
  _ecv_reg64_t sp;
  addr_t vma = STACK_START_VMA;
  uint64_t len = STACK_SIZE;
  auto bytes = reinterpret_cast<uint8_t *>(malloc(len));
  memset(bytes, 0, len);

  /* Initialize the stack */
  sp = vma + len;

  /* Initialize AT_RANDOM */
  /* FIXME: this shouldn't be on the stack? */
  sp -= 16;
  // getentropy(bytes + (sp - vma), 16);
  memset(bytes + (sp - vma), 1, 16);
  _ecv_reg64_t randomp = sp;

  /* Initialize AT_PHDR */
  /* FIXME: this shouldn't be on the stack? */
  auto e_ph_size = __g_e_phent * __g_e_phnum;
  sp -= e_ph_size;
  memcpy(bytes + (sp - vma), __g_e_ph, e_ph_size);
  _ecv_reg64_t phdr = sp;

  /* auxv */
  struct {
    _ecv_reg64_t _ecv_a_type;
    union {
      _ecv_reg64_t _ecv_a_val;
    } _ecv_a_un;
  } _ecv_auxv64[] = {
#if defined(ELFC_WASI_ENV)
    {3 /* AT_PHDR */, phdr},
    {4 /* AT_PHENT */, __g_e_phent},
    {5 /* AT_PHNUM */, __g_e_phnum},
    {6 /* AT_PAGESZ */, 4096},
    {9 /* AT_ENTRY */, __g_entry_pc},
    {11 /* AT_UID */, 42},
    {12 /* AT_EUID */, 42},
    {13 /* AT_GID */, 42},
    {14 /* AT_EGID */, 42},
    {23 /* AT_SECURE */, 0},
    {25 /* AT_RANDOM */, randomp},
    {0 /* AT_NULL */, 0},
#else
    {3 /* AT_PHDR */, phdr},
    {4 /* AT_PHENT */, __g_e_phent},
    {5 /* AT_PHNUM */, __g_e_phnum},
    {6 /* AT_PAGESZ */, 4096},
    {9 /* AT_ENTRY */, __g_entry_pc},
    {11 /* AT_UID */, getuid()},
    {12 /* AT_EUID */, geteuid()},
    {13 /* AT_GID */, getgid()},
    {14 /* AT_EGID */, getegid()},
    {23 /* AT_SECURE */, 0},
    {25 /* AT_RANDOM */, randomp},
    {0 /* AT_NULL */, 0},
#endif
  };
  sp -= sizeof(_ecv_auxv64);
  memcpy(bytes + (sp - vma), _ecv_auxv64, sizeof(_ecv_auxv64));

  /* TODO envp */
  sp -= sizeof(_ecv_reg64_t);
  /* TODO argv */
  // auto arg = argv;
  // while(*arg)
  //   arg++;
  // sp -= (arg - argv) + sizeof(addr_t);
  // memcpy(bytes + (sp - vma), (uint8_t*)argv, arg - argv);
  sp -= sizeof(_ecv_reg64_t) * (argc + 1);
  /* argc */
  sp -= sizeof(_ecv_reg64_t);
  auto argc64 = (_ecv_reg64_t) argc;
  memcpy(bytes + (sp - vma), &argc64, sizeof(_ecv_reg64_t));
  state->gpr.sp.qword = sp;
  return new MappedMemory(MemoryAreaType::STACK, "Stack", vma, vma + len, len, bytes, bytes + len,
                          true);
}

MappedMemory *MappedMemory::VMAHeapEntryInit() {
  auto bytes = reinterpret_cast<uint8_t *>(malloc(HEAP_UNIT_SIZE));
  auto upper_bytes = bytes + HEAP_UNIT_SIZE;
  auto heap =
      new MappedMemory(MemoryAreaType::HEAP, "Heap", HEAPS_START_VMA,
                       HEAPS_START_VMA + HEAP_UNIT_SIZE, HEAP_UNIT_SIZE, bytes, upper_bytes, true);
  heap->heap_cur = HEAPS_START_VMA;
  return heap;
}

void MappedMemory::DebugEmulatedMemory() {
  std::cout << "memory_area_type: ";
  switch (memory_area_type) {
    case MemoryAreaType::STACK: std::cout << "STACK, "; break;
    case MemoryAreaType::HEAP: std::cout << "HEAP, "; break;
    case MemoryAreaType::DATA: std::cout << "DATA, "; break;
    case MemoryAreaType::RODATA: std::cout << "RODATA, "; break;
    case MemoryAreaType::OTHER: std::cout << "OTHER, "; break;
    default: elfconv_runtime_error("[ERROR] unknown memory area type, "); break;
  }
  std::cout << "name: " << name.c_str() << ", vma: 0x" << std::hex << std::setw(16)
            << std::setfill('0') << vma << ", len: " << std::dec << len << std::hex << std::setw(16)
            << std::setfill('0') << ", bytes: 0x" << (addr_t) bytes << ", upper_bytes: 0x"
            << (addr_t) upper_bytes << ", bytes_on_heap" << (bytes_on_heap ? "true" : "false")
            << std::endl;
}
uint8_t RuntimeManager::get(uint64_t vma_addr) {
  if (vma_addr >= stack_memory->vma) {
    if (stack_memory->other_memory) {
      return stack_memory->other_memory->get(vma_addr - stack_memory->vma);
    } else {
      return stack_memory->bytes[vma_addr - stack_memory->vma];
    }
  }
  if (vma_addr >= heap_memory->vma) {
    if (heap_memory->other_memory) {
      return heap_memory->other_memory->get(vma_addr - heap_memory->vma);
    } else {
      return heap_memory->bytes[vma_addr - heap_memory->vma];
    }
  };
  for (auto &memory : mapped_memorys) {
    if (memory->vma <= vma_addr && vma_addr < memory->vma_end) {
      if (memory->other_memory) {
        return memory->other_memory->get(vma_addr - memory->vma);
      } else {
        return memory->bytes[vma_addr - memory->vma];
      }
    };
  }
};
void RuntimeManager::set(uint64_t vma_addr, uint8_t y) {
  if (vma_addr >= stack_memory->vma) {
    if (stack_memory->other_memory) {
      stack_memory->other_memory->set(vma_addr - stack_memory->vma, y);
    } else {
      stack_memory->bytes[vma_addr - stack_memory->vma] = y;
    }
  }
  if (vma_addr >= heap_memory->vma) {
    if (heap_memory->other_memory) {
      heap_memory->other_memory->set(vma_addr - heap_memory->vma,y);
    } else {
      heap_memory->bytes[vma_addr - heap_memory->vma] = y;
    }
  };
  for (auto &memory : mapped_memorys) {
    if (memory->vma <= vma_addr && vma_addr < memory->vma_end) {
      if (memory->other_memory) {
        memory->other_memory->set(vma_addr - memory->vma,y);
      } else {
        memory->bytes[vma_addr - memory->vma] = y;
      }
    };
  }
};
// void *RuntimeManager::TranslateVMA(addr_t vma_addr) {
//   /* search in every mapped memory */
//   if (vma_addr >= stack_memory->vma)
//     return reinterpret_cast<void *>(stack_memory->bytes + (vma_addr - stack_memory->vma));
//   if (vma_addr >= heap_memory->vma)
//     return reinterpret_cast<void *>(heap_memory->bytes + (vma_addr - heap_memory->vma));
//   for (auto &memory : mapped_memorys) {
//     if (memory->vma <= vma_addr && vma_addr < memory->vma_end)
//       return reinterpret_cast<void *>(memory->bytes + (vma_addr - memory->vma));
//   }
//   debug_state_machine();
//   /* not exist sections which includes the vma_addr. */
//   elfconv_runtime_error("[ERROR] The accessed memory is not mapped. vma_addr: 0x%llx, PC: 0x%llx",
//                         vma_addr, g_state.gpr.pc.qword);
// }

// /* Wrapper of RuntimeManager::TranslateVMA */
// void *_ecv_translate_ptr(addr_t vma_addr) {
//   return g_run_mgr->TranslateVMA(vma_addr);
// }

extern "C" uint64_t *__g_get_indirectbr_block_address(uint64_t fun_vma, uint64_t bb_vma) {
  if (g_run_mgr->addr_block_addrs_map.count(fun_vma) == 1) {
    auto vma_bb_map = g_run_mgr->addr_block_addrs_map[fun_vma];
    if (vma_bb_map.count(bb_vma) == 1) {
      return vma_bb_map[bb_vma];
    } else {
      if (g_run_mgr->addr_fn_map.count(fun_vma) == 1)
        return vma_bb_map[UINT64_MAX];
      else
        elfconv_runtime_error("[ERROR] 0x%llx is not the vma of the block address of '%s'.\n",
                              bb_vma, __func__);
    }
  } else {
    elfconv_runtime_error(
        "[ERROR] 0x%llx is not the entry address of any lifted function. (at %s)\n", fun_vma,
        __func__);
  }
}

extern "C" void debug_call_stack_push(uint64_t fn_vma) {
  if (auto func_name = g_run_mgr->addr_fn_symbol_map[fn_vma]; func_name) {
    if (strncmp(func_name, "fn_plt", 6) == 0) {
      return;
    }
    g_run_mgr->call_stacks.push_back(fn_vma);
    std::string tab_space;
    for (int i = 0; i < g_run_mgr->call_stacks.size(); i++) {
      if (i & 0b1)
        tab_space += "\033[34m";
      else
        tab_space += "\033[31m";
      tab_space += "|";
    }
    tab_space += "\033[0m";
    char entry_func_log[100];
    snprintf(entry_func_log, 100, "start : %s\n", func_name);
    printf("%s", tab_space.c_str());
    printf("%s", entry_func_log);
  } else {
    elfconv_runtime_error("[ERROR] unknown entry func vma: 0x%08llx\n", fn_vma);
  }
}

extern "C" void debug_call_stack_pop(uint64_t fn_vma) {
  if (g_run_mgr->call_stacks.empty()) {
    elfconv_runtime_error("invalid debug call stack empty. PC: 0x%016llx\n", g_state.gpr.pc.qword);
  } else {
    auto last_call_vma = g_run_mgr->call_stacks.back();
    auto func_name = g_run_mgr->addr_fn_symbol_map[last_call_vma];
    if (strncmp(func_name, "fn_plt", 6) != 0) {
      if (fn_vma != last_call_vma)
        elfconv_runtime_error("fn_vma: %lu(%s) must be equal to last_call_vma(%s): %lu\n", fn_vma,
                              last_call_vma, g_run_mgr->addr_fn_symbol_map[fn_vma],
                              g_run_mgr->addr_fn_symbol_map[last_call_vma]);
      g_run_mgr->call_stacks.pop_back();
      return;
      std::string tab_space;
      for (int i = 0; i < g_run_mgr->call_stacks.size(); i++) {
        if (i & 0b1)
          tab_space += "\033[34m";
        else
          tab_space += "\033[31m";
        tab_space += "|";
      }
      tab_space += "\033[0m";
      char return_func_log[100];
      snprintf(return_func_log, 100, "end   : %s\n", func_name);
      printf("%s", tab_space.c_str());
      printf("%s", return_func_log);
    }
  }
}

extern "C" void temp_patch_f_flags(uint64_t f_flags_vma) {
  uint64_t x = 0xfbad2a84;
  g_run_mgr->write(f_flags_vma,&x);
  // uint64_t *pma = (uint64_t *) _ecv_translate_ptr(f_flags_vma);
  // *pma = ;
  return;
}