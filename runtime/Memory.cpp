#include "Memory.h"

#include "utils/Util.h"
#include "utils/elfconv.h"

#include <iomanip>
#include <iostream>

// #define MULSECTIONS_WARNING_MSG 1

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
      {3 /* AT_PHDR */, phdr},          {4 /* AT_PHENT */, __g_e_phent},
      {5 /* AT_PHNUM */, __g_e_phnum},  {6 /* AT_PAGESZ */, 4096},
      {9 /* AT_ENTRY */, __g_entry_pc}, {11 /* AT_UID */, getuid()},
      {12 /* AT_EUID */, geteuid()},    {13 /* AT_GID */, getgid()},
      {14 /* AT_EGID */, getegid()},    {23 /* AT_SECURE */, 0},
      {25 /* AT_RANDOM */, randomp},    {0 /* AT_NULL */, 0},
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
  return new MappedMemory(MemoryAreaType::STACK, "Stack", vma, len, bytes, bytes + len, true);
}

MappedMemory *MappedMemory::VMAHeapEntryInit() {
  auto bytes = reinterpret_cast<uint8_t *>(malloc(HEAP_SIZE));
  auto upper_bytes = bytes + HEAP_SIZE;
  auto heap = new MappedMemory(MemoryAreaType::HEAP, "Heap", HEAPS_START_VMA, HEAP_SIZE, bytes,
                               upper_bytes, true);
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

void *RuntimeManager::TranslateVMA(addr_t vma_addr) {
  void *pma_addr = nullptr;
  /* search in every mapped memory */
  int exist = 0;
  for (auto &memory : mapped_memorys) {
    if (memory->vma <= vma_addr && vma_addr < memory->vma + memory->len) {
      /*
              for Debug (we should break out this loop at the same time of finding the target
              emulated memory) There are multiple sections whose vma is 0x00000000
            */
      exist++;
      pma_addr = reinterpret_cast<void *>(memory->bytes + (vma_addr - memory->vma));
    }
  }
  /* don't exist sections which includes the vma_addr. */
  if (0 == exist) {
    std::cout << "[ERROR] The accessed memory is not mapped. vma_addr: 0x" << std::hex
              << std::setw(16) << std::setfill('0') << vma_addr << ", pc: 0x"
              << g_state.gpr.pc.qword << ", Heap vma: 0x" << mapped_memorys[1]->vma
              << ", Heap len: " << std::dec << mapped_memorys[1]->len << std::endl;
    debug_state_machine();
    abort();
  }
  /* multiple sections which includes the vma_addr */
#if defined(MULSECTIONS_WARNING_MSG)
  if (exist > 1) {
    std::cout << "[WARNING] vma_addr (0x" << std::hex << std::setw(16) << std::setfill('0')
              << vma_addr << ") exists at multiple sections." << std::endl;
  }
#endif

  return pma_addr;
}

/* Wrapper of RuntimeManager::TranslateVMA */
void *_ecv_translate_ptr(addr_t vma_addr) {
  return g_run_mgr->TranslateVMA(vma_addr);
}

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

extern "C" void debug_call_stack() {
  auto current_pc = g_state.gpr.pc.qword;
  if (auto func_name = g_run_mgr->addr_fn_symbol_map[current_pc]; func_name) {
    if (strncmp(func_name, "fn_plt", 6) == 0) {
      return;
    }
    g_run_mgr->call_stacks.push_back(current_pc);
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
    elfconv_runtime_error("[ERROR] unknown entry func vma: 0x%08llx\n", current_pc);
  }
}
