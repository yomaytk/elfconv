#include "elfconv.h"

#include <iomanip>
#include <iostream>
#include <remill/Arch/AArch64/Runtime/State.h>
#include <remill/BC/HelperMacro.h>
#include <vector>

#define PRINT_GPR(index) \
  std::cout << std::hex << "x" << #index << ": 0x" << g_state.gpr.x##index.qword << std::endl;

extern State g_state;

#define SR_ECV_NZCV__N ((ecv_nzcv & 0b1000) >> 3)
#define SR_ECV_NZCV__Z ((ecv_nzcv & 0b100) >> 2)
#define SR_ECV_NZCV__C ((ecv_nzcv & 0b10) >> 1)
#define SR_ECV_NZCV__V (ecv_nzcv & 0b1)

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
  auto ecv_nzcv = g_state.ecv_nzcv;
  std::cout << "State.SR" << std::dec << std::endl;
  std::cout << std::hex << "tpidr_el0: 0x" << sr.tpidr_el0.qword << ", tpidrro_el0: 0x"
            << sr.tpidrro_el0.qword << ", ctr_el0: 0x" << sr.ctr_el0.qword << ", dczid_el0: 0x"
            << sr.dczid_el0.qword << ", midr_el1: 0x" << sr.midr_el1.qword << std::dec
            << ", n: " << (uint64_t) SR_ECV_NZCV__N << ", z: " << (uint64_t) SR_ECV_NZCV__Z
            << ", c: " << (uint64_t) SR_ECV_NZCV__C << ", v: " << (uint64_t) SR_ECV_NZCV__V
            << ", ixc: " << (uint64_t) sr.ixc << ", ofc: " << (uint64_t) sr.ofc
            << ", ufc: " << (uint64_t) sr.ufc << ", idc: " << (uint64_t) sr.idc
            << ", ioc: " << (uint64_t) sr.ioc << std::endl;
}

extern "C" void debug_state_machine_vectors() {
  std::cout << "[Debug] State Machine Vector Registers. Program Counter: 0x" << std::hex
            << std::setw(16) << std::setfill('0') << g_state.gpr.pc.qword << std::endl;
  std::cout << "State.SIMD:" << std::endl;
  std::cout << std::hex;
  for (int i = 0; i < kNumVecRegisters /* = 32 */; i++) {
    std::cout << "v." << std::to_string(i) << " = { [64:127]: 0x"
              << (_ecv_u64v2_t(g_state.simd.v[i]))[1] << ", [0:63]: 0x"
              << (_ecv_u64v2_t(g_state.simd.v[i]))[0] << " }" << std::endl;
  }
}

extern "C" void debug_llvmir_u64value(uint64_t val) {
  std::cout << std::hex << "LLVM IR value: 0x" << val << std::endl;
}

extern "C" void debug_llvmir_f64value(double val) {
  std::cout << "LLVM IR value: " << val << std::endl;
}

extern "C" void debug_insn() {
  auto gpr = g_state.gpr;
  std::cout << "[DEBUG INSN]" << std::endl;
  std::cout << std::hex << "PC: 0x" << gpr.pc.qword << " x0: 0x" << gpr.x0.qword << " x1: 0x"
            << gpr.x1.qword << " x2: 0x" << gpr.x2.qword << " x3: 0x" << gpr.x3.qword << std::endl;
}

extern "C" void debug_reach() {
  std::cout << "Reach!" << std::endl;
}

#if defined(LIFT_DEBUG) && defined(__linux__)
extern "C" void segv_debug_state_machine(int sig, siginfo_t *info, void *ctx) {
  std::cout << "[ERROR] Segmantation Fault." << std::endl;
  std::cout << "signo: " << info->si_signo << " code: " << info->si_code << std::endl;
  debug_state_machine();
  exit(0);
}
#endif