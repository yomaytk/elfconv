#include "elfconv.h"

#include "remill/Arch/AArch64/Runtime/State.h"

#include <iomanip>
#include <iostream>

#define PRINT_GPREGISTERS(index) \
  std::cout << std::hex << "x" << #index << ": 0x" << g_state.gpr.x##index.qword << std::endl;

extern State g_state;

/* debug func */
extern "C" void debug_state_machine() {
  std::cout << "[Debug] State Machine. Program Counter: 0x" << std::hex << std::setw(16)
            << std::setfill('0') << g_state.gpr.pc.qword << std::endl;
  std::cout << "State.GPR:" << std::endl;
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
  std::cout << std::hex << std::setw(16) << std::setfill('0') << "sp: 0x" << g_state.gpr.sp.qword
            << ", pc: 0x" << g_state.gpr.pc.qword;
  auto sr = g_state.sr;
  std::cout << "State.SR" << std::dec << std::endl;
  std::cout << "tpidr_el0: " << sr.tpidr_el0.qword << ", tpidrro_el0: " << sr.tpidrro_el0.qword
            << ", ctr_el0: " << sr.ctr_el0.qword << ", dczid_el0: " << sr.dczid_el0.qword
            << ", midr_el1: " << sr.midr_el1.qword << ", n: " << sr.n << ", z: " << sr.z
            << ", c: " << sr.c << ", v: " << sr.v << ", ixc: " << sr.ixc << ", ofc: " << sr.ofc
            << ", ufc: " << sr.ufc << ", idc: " << sr.idc << ", ioc: " << sr.ioc << std::endl;
}

extern "C" void debug_pc() {
  std::cout << std::hex << std::setw(8) << std::setfill('0') << "PC: 0x" << g_state.gpr.pc.dword
            << std::endl;
}

extern "C" void debug_insn() {
  auto gpr = g_state.gpr;
  std::cout << "[DEBUG INSN]" << std::endl;
  std::cout << std::hex << std::setw(16) << std::setfill('0') << "PC: 0x" << gpr.pc.qword
            << ", x0: 0x" << gpr.x0.qword << ", x1: 0x" << gpr.x1.qword << ", x2: 0x"
            << gpr.x2.qword << ", x3: 0x" << gpr.x3.qword << ", x4: 0x" << gpr.x4.qword
            << ", x5: 0x" << gpr.x5.qword << std::endl;
}
