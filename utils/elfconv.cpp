#include "elfconv.h"

#include <remill/BC/HelperMacro.h>
#include <stdio.h>

#if defined(ELF_IS_AARCH64)
#  include <remill/Arch/AArch64/Runtime/State.h>
#elif defined(ELF_IS_AMD64)
#  include <remill/Arch/X86/Runtime/State.h>
#else
#  include <remill/Arch/AArch64/Runtime/State.h>
#endif

typedef unsigned long long ull;

#define PRINT_GPR(index) printf("X" #index ": 0x%llx ", (ull) CPUState->gpr.x##index.qword)

extern State *CPUState;

#if defined(__EMSCRIPTEN__)
extern "C" uint32_t me_forked;
#endif

#define SR_ECV_NZCV__N ((ecv_nzcv & 0b1000) >> 3)
#define SR_ECV_NZCV__Z ((ecv_nzcv & 0b100) >> 2)
#define SR_ECV_NZCV__C ((ecv_nzcv & 0b10) >> 1)
#define SR_ECV_NZCV__V (ecv_nzcv & 0b1)

/* debug func */
extern "C" void debug_state_machine() {
#if !defined(ELF_IS_AMD64)
  printf("PC: 0x%llx ", (ull) CPUState->gpr.pc.qword);
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
  printf("SP: 0x%llx PC: 0x%llx\n", (ull) CPUState->gpr.sp.qword, (ull) CPUState->gpr.pc.qword);
  auto sr = CPUState->sr;
  auto ecv_nzcv = CPUState->ecv_nzcv;
  printf("State.SR\n");
  printf(
      "tpidr_el0: 0x%llx, tpidrro_el0: 0x%llx, ctr_el0: 0x%llx, dczid_el0: 0x%llx, midr_el1: 0x%llx, "
      "n: %llu, z: %llu, c: %llu, v: %llu, ixc: %llu, ofc: %llu, ufc: %llu, idc: %llu, ioc: %llu\n",
      (ull) sr.tpidr_el0.qword, (ull) sr.tpidrro_el0.qword, (ull) sr.ctr_el0.qword,
      (ull) sr.dczid_el0.qword, (ull) sr.midr_el1.qword, (ull) SR_ECV_NZCV__N, (ull) SR_ECV_NZCV__Z,
      (ull) SR_ECV_NZCV__C, (ull) SR_ECV_NZCV__V, (ull) sr.ixc, (ull) sr.ofc, (ull) sr.ufc,
      (ull) sr.idc, (ull) sr.ioc);
#endif
}

extern "C" void debug_gprs_nzcv(uint64_t pc) {
  printf("PC: 0x%llx ", (ull) pc);
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
  printf("SP: 0x%llx PC: 0x%llx ECV_NZCV: 0x%llx\n", (ull) CPUState->gpr.sp.qword, (ull) pc,
         (ull) CPUState->ecv_nzcv);
}

extern "C" void debug_state_machine_vectors() {
#if !defined(ELF_IS_AMD64)
  printf("[Debug] State Machine Vector Registers. Program Counter: 0x%016llx\n",
         (ull) CPUState->gpr.pc.qword);
  printf("State.SIMD:\n");
  for (size_t i = 0; i < kNumVecRegisters /* = 32 */; i++) {
    printf("v.%zu = { [64:127]: 0x%llx, [0:63]: 0x%llx }\n", i,
           (ull) (_ecv_u64v2_t(CPUState->simd.v[i]))[1],
           (ull) (_ecv_u64v2_t(CPUState->simd.v[i]))[0]);
  }
#endif
}

extern "C" void debug_llvmir_u64value(uint64_t val) {
  printf("LLVM IR value: 0x%llx\n", (ull) val);
}

extern "C" void debug_llvmir_f64value(double val) {
  printf("LLVM IR value: %f\n", val);
}

extern "C" void print_addr(uint64_t addr) {
  printf("addr: 0x%llx\n", (ull) addr);
}

extern "C" void debug_insn() {
#if !defined(ELF_IS_AMD64)
  auto gpr = CPUState->gpr;
  printf("[DEBUG INSN]\n");
  printf("PC: 0x%llx x0: 0x%llx x1: 0x%llx x2: 0x%llx x3: 0x%llx\n", (ull) gpr.pc.qword,
         (ull) gpr.x0.qword, (ull) gpr.x1.qword, (ull) gpr.x2.qword, (ull) gpr.x3.qword);
#endif
}

extern "C" void debug_reach() {
  printf("Reach!\n");
}
