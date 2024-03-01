#include "elfconv.h"

#include <iomanip>
#include <iostream>
#include <remill/Arch/AArch64/Runtime/State.h>
#include <remill/BC/HelperMacro.h>

#define PRINT_GPR(index) \
  std::cout << std::hex << "x" << #index << ": 0x" << g_state.gpr.x##index.qword << std::endl;

extern State g_state;

/* debug func */
extern "C" void debug_state_machine() {
  std::cout << "[Debug] State Machine. Program Counter: 0x" << std::hex << std::setw(16)
            << std::setfill('0') << g_state.gpr.pc.qword << std::endl;
  std::cout << "State.GPR:" << std::endl;
  PRINT_GPR(0);
  PRINT_GPR(1);
  PRINT_GPR(2);
  PRINT_GPR(3);
  PRINT_GPR(4);
  PRINT_GPR(5);
  PRINT_GPR(6);
  PRINT_GPR(7);
  PRINT_GPR(8);
  PRINT_GPR(9);
  PRINT_GPR(10);
  PRINT_GPR(11);
  PRINT_GPR(12);
  PRINT_GPR(13);
  PRINT_GPR(14);
  PRINT_GPR(15);
  PRINT_GPR(16);
  PRINT_GPR(17);
  PRINT_GPR(18);
  PRINT_GPR(19);
  PRINT_GPR(20);
  PRINT_GPR(21);
  PRINT_GPR(22);
  PRINT_GPR(23);
  PRINT_GPR(24);
  PRINT_GPR(25);
  PRINT_GPR(26);
  PRINT_GPR(27);
  PRINT_GPR(28);
  PRINT_GPR(29);
  PRINT_GPR(30);
  std::cout << std::hex << "sp: 0x" << g_state.gpr.sp.qword << ", pc: 0x" << g_state.gpr.pc.qword
            << std::endl;
  auto sr = g_state.sr;
  std::cout << "State.SR" << std::dec << std::endl;
  std::cout << std::hex << "tpidr_el0: 0x" << sr.tpidr_el0.qword << ", tpidrro_el0: 0x"
            << sr.tpidrro_el0.qword << ", ctr_el0: 0x" << sr.ctr_el0.qword << ", dczid_el0: 0x"
            << sr.dczid_el0.qword << ", midr_el1: 0x" << sr.midr_el1.qword << std::dec
            << ", n: " << sr.n << ", z: " << sr.z << ", c: " << sr.c << ", v: " << sr.v
            << ", ixc: " << sr.ixc << ", ofc: " << sr.ofc << ", ufc: " << sr.ufc
            << ", idc: " << sr.idc << ", ioc: " << sr.ioc << std::endl;
}

extern "C" void debug_state_machine_vectors() {
  std::cout << "[Debug] State Machine Vector Registers. Program Counter: 0x" << std::hex
            << std::setw(16) << std::setfill('0') << g_state.gpr.pc.qword << std::endl;
  std::cout << "State.SIMD:" << std::endl;
  std::cout << std::hex;
  for (int i = 0; i < kNumVecRegisters /* = 32 */; i++) {
    std::cout << "v." << std::to_string(i) << " = { [63:0]: 0x" << g_state.simd.v[i].qwords.elems[0]
              << ", [127:64]: 0x" << g_state.simd.v[i].qwords.elems[1] << " }" << std::endl;
  }
}

extern "C" void debug_insn() {
  auto gpr = g_state.gpr;
  std::cout << "[DEBUG INSN]" << std::endl;
  std::cout << std::hex << "PC: 0x" << gpr.pc.qword << ", SP: 0x" << gpr.sp.qword << ", x19: 0x"
            << gpr.x19.qword << ", x20: 0x" << gpr.x20.qword << ", x21: 0x" << gpr.x21.qword
            << ", x22: 0x" << gpr.x22.qword << ", x29: 0x" << gpr.x29.qword << ", x30: 0x"
            << gpr.x30.qword << std::endl;
}

#if defined(LIFT_DEBUG)
extern "C" void segv_debug_state_machine(int sig, siginfo_t *info, void *ctx) {
  std::cout << "[ERROR] Segmantation Fault." << std::endl;
  std::cout << "signo: " << info->si_signo << " code: " << info->si_code << std::endl;
  debug_state_machine();
  exit(0);
}
#endif