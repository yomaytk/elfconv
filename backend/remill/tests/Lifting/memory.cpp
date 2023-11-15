#include "memory.h"

#define PRINT_GPREGISTERS(index) printf("x" #index ": 0x%llx, ", g_state.gpr.x##index.qword)

/* 
  EmulatedMemory 
*/
EmulatedMemory *EmulatedMemory::VMAStackEntryInit(int argc, char *argv[], State *state /* start stack pointer */) {
  _ecv_reg64_t sp;
  addr_t vma = STACK_START_VMA; 
  uint64_t len = STACK_SIZE; 
  auto bytes = reinterpret_cast<uint8_t*>(malloc(len));
  memset(bytes, 0, len);

  /* Initialize the stack */
  sp = vma + len;
  state->gpr.x29.qword = sp;

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
    {15 /* AT_PLATFORM */, (_ecv_reg64_t)__g_platform_name},
    {33 /* AT_SYSINFO_EHDR */, 0xffffffffebe8},
    {0 /* AT_NULL */, 0},
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
  auto argc64 = (_ecv_reg64_t)argc;
  memcpy(bytes + (sp - vma), &argc64, sizeof(_ecv_reg64_t));
  state->gpr.sp.qword = sp;
  return new EmulatedMemory(MemoryAreaType::STACK, "Stack", vma, len, bytes, bytes + len, true);
}

EmulatedMemory *EmulatedMemory::VMAHeapEntryInit() {
  auto bytes = reinterpret_cast<uint8_t*>(malloc(HEAP_SIZE));
  auto upper_bytes = bytes + HEAP_SIZE;
  auto heap = new EmulatedMemory(MemoryAreaType::HEAP, "Heap", HEAPS_START_VMA, HEAP_SIZE, bytes, upper_bytes, true);
  heap->heap_cur = HEAPS_START_VMA;
  return heap;
}

void EmulatedMemory::DebugEmulatedMemory() {
  printf("memory_area_type: ");
  switch (memory_area_type)
  {
    case MemoryAreaType::STACK:
      printf("STACK, ");
      break;
    case MemoryAreaType::HEAP:
      printf("HEAP, ");
      break;
    case MemoryAreaType::DATA:
      printf("DATA, ");
      break;
    case MemoryAreaType::RODATA:
      printf("RODATA, ");
      break;
    case MemoryAreaType::OTHER:
      printf("OTHER, ");
      break;
    default:
      printf("[ERROR] unknown memory area type, ");
      abort();
      break;
  }
  printf("name: %s, vma: 0x%016llx, len: %llu (0x%08llx) , bytes: 0x%016llx, upper_bytes: 0x%016llx, bytes_on_heap: %s\n",
    name.c_str(), vma, len, len, (addr_t)bytes, (addr_t)upper_bytes, bytes_on_heap ? "true" : "false");
}

/*
  RuntimeManager
*/
void *RuntimeManager::TranslateVMA(addr_t vma_addr) {
  void *pma_addr = nullptr;
  /* search in every emulated memory */
  bool vma_allocated = false;
  for(auto &memory : emulated_memorys) {
    if (memory->vma <= vma_addr && vma_addr < memory->vma + memory->len) {
          /* 
            for Debug (we should break out this loop at the same time of finding the target emulated memory) 
            There are multiple sections whose vma is 0x00000000
          */
          if (vma_allocated && 0x00000000 != memory->vma) {
            debug_state_machine();
            printf("[ERROR] vma_addr (0x%016llx) exists at multiple memorys.\n", vma_addr);
            abort();
          }
      vma_allocated = true;
      pma_addr = reinterpret_cast<void*>(memory->bytes + (vma_addr - memory->vma));
    }
  }
  if (!vma_allocated) {
    printf("[ERROR] The accessed memory is not mapped. vma_addr: 0x%016llx, pc: %016llx\nHeap vma: %016llx, Heap len: %016llx\n",
             vma_addr, g_state.gpr.pc.qword, emulated_memorys[1]->vma, emulated_memorys[1]->len);
    debug_state_machine();
    abort();
  }
  
  return pma_addr;
}

/* translate vma address to the actual mapped memory address */
void *_ecv_translate_ptr(addr_t vma_addr) {
  return g_run_mgr->TranslateVMA(vma_addr);
}

extern "C" void debug_state_machine() {
  printf("[Debug] State Machine. Program Counter: 0x%016llx\n", g_state.gpr.pc.qword);
  printf("State.GPR: ");
  PRINT_GPREGISTERS(0);
  PRINT_GPREGISTERS(1);
  PRINT_GPREGISTERS(2);
  PRINT_GPREGISTERS(3);
  PRINT_GPREGISTERS(4);
  PRINT_GPREGISTERS(5);
  PRINT_GPREGISTERS(6);
  PRINT_GPREGISTERS(7);
  PRINT_GPREGISTERS(8);
  PRINT_GPREGISTERS(9);
  PRINT_GPREGISTERS(10);
  PRINT_GPREGISTERS(11);
  PRINT_GPREGISTERS(12);
  PRINT_GPREGISTERS(13);
  PRINT_GPREGISTERS(14);
  PRINT_GPREGISTERS(15);
  PRINT_GPREGISTERS(16);
  PRINT_GPREGISTERS(17);
  PRINT_GPREGISTERS(18);
  PRINT_GPREGISTERS(19);
  PRINT_GPREGISTERS(20);
  PRINT_GPREGISTERS(21);
  PRINT_GPREGISTERS(22);
  PRINT_GPREGISTERS(23);
  PRINT_GPREGISTERS(24);
  PRINT_GPREGISTERS(25);
  PRINT_GPREGISTERS(26);
  PRINT_GPREGISTERS(27);
  PRINT_GPREGISTERS(28);
  PRINT_GPREGISTERS(29);
  PRINT_GPREGISTERS(30);
  printf("sp: 0x%016llx, pc: 0x%016llx\n", g_state.gpr.sp.qword, g_state.gpr.pc.qword);
  auto nzcv = g_state.nzcv;
  printf("State.NZCV:\nn: %hhu, z: %hhu, c: %hhu, v: %hhu\n", nzcv.n, nzcv.z, nzcv.c, nzcv.v);
  auto sr = g_state.sr;
  printf("State.SR:\ntpidr_el0: %llu, tpidrro_el0: %llu, ctr_el0: %llu, dczid_el0: %llu, midr_el0: %llu, n: %hhu, z: %hhu, c: %hhu, v: %hhu, ixc: %hhu, ofc: %hhu, ufc: %hhu, idc: %hhu, ioc: %hhu\n", 
    sr.tpidr_el0.qword, sr.tpidrro_el0.qword, sr.ctr_el0.qword, sr.dczid_el0.qword, sr.midr_el1.qword, sr.n, sr.z, sr.c, sr.v, sr.ixc, sr.ofc, sr.ufc, sr.idc, sr.ioc);
  printf("\n");
}

extern "C" void debug_pc() {
  printf("[Debug] PC: 0x%llx, x0: 0x%llx, x1: 0x%llx, x2: 0x%llx, x3: 0x%llx, x4: 0x%llx\n", g_state.gpr.pc.qword, g_state.gpr.x0.qword, g_state.gpr.x1.qword, g_state.gpr.x2.qword, g_state.gpr.x3.qword, g_state.gpr.x4.qword);
}
