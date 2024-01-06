#include "elfconv.h"

#include "remill/Arch/AArch64/Runtime/State.h"

#if defined(__clang__)
#  define PRINT_GPREGISTERS(index) printf("x" #index ": 0x%lx\n", g_state.gpr.x##index.qword)
#elif defined(__wasm__)
#  define PRINT_GPREGISTERS(index) printf("x" #index ": 0x%llx\n", g_state.gpr.x##index.qword)
#endif

extern State g_state;

/* debug func */
extern "C" void debug_state_machine() {
  printf("[Debug] State Machine. Program Counter: 0x%016llx\n", g_state.gpr.pc.qword);
  printf("State.GPR:\n");
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
  auto sr = g_state.sr;
  printf("State.SR:\ntpidr_el0: %llu, tpidrro_el0: %llu, ctr_el0: %llu, dczid_el0: %llu, midr_el0: "
         "%llu, n: %hhu, z: %hhu, c: %hhu, v: %hhu, ixc: %hhu, ofc: %hhu, ufc: %hhu, idc: %hhu, "
         "ioc: %hhu\n",
         sr.tpidr_el0.qword, sr.tpidrro_el0.qword, sr.ctr_el0.qword, sr.dczid_el0.qword,
         sr.midr_el1.qword, sr.n, sr.z, sr.c, sr.v, sr.ixc, sr.ofc, sr.ufc, sr.idc, sr.ioc);
}

extern "C" void debug_pc() {
  printf("PC: 0x%08x\n", g_state.gpr.pc.dword);
}

extern "C" void debug_insn() {
  auto gpr = g_state.gpr;
  printf("[DEBUG_INSN]\nPC: 0x%08x, x0: 0x%016llx, x1: 0x%08llx, x2, 0x%016llx, x3: 0x%016llx, x4: "
         "0x%016llx, x5: 0x%016llx\n",
         gpr.pc.dword, gpr.x0.qword, gpr.x1.qword, gpr.x2.qword, gpr.x3.qword, gpr.x4.qword,
         gpr.x5.qword);
}
