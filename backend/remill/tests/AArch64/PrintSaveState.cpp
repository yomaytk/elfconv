/*
 * Copyright (c) 2017 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstddef>
#include <cstdio>

#define ADDRESS_SIZE_BITS 64

#include "remill/Arch/AArch64/Runtime/State.h"

int main(void) {

  printf("/* Auto-generated file! Don't modify! */\n\n");

  // X28 - State *

  // General purpose regs (except x28, which contains State *).
  printf("str x0, [x28, #%lu]\n", offsetof(State, gpr.x0));
  printf("str x1, [x28, #%lu]\n", offsetof(State, gpr.x1));
  printf("str x2, [x28, #%lu]\n", offsetof(State, gpr.x2));
  printf("str x3, [x28, #%lu]\n", offsetof(State, gpr.x3));
  printf("str x4, [x28, #%lu]\n", offsetof(State, gpr.x4));
  printf("str x5, [x28, #%lu]\n", offsetof(State, gpr.x5));
  printf("str x6, [x28, #%lu]\n", offsetof(State, gpr.x6));
  printf("str x7, [x28, #%lu]\n", offsetof(State, gpr.x7));
  printf("str x8, [x28, #%lu]\n", offsetof(State, gpr.x8));
  printf("str x9, [x28, #%lu]\n", offsetof(State, gpr.x9));
  printf("str x10, [x28, #%lu]\n", offsetof(State, gpr.x10));
  printf("str x11, [x28, #%lu]\n", offsetof(State, gpr.x11));
  printf("str x12, [x28, #%lu]\n", offsetof(State, gpr.x12));
  printf("str x13, [x28, #%lu]\n", offsetof(State, gpr.x13));
  printf("str x14, [x28, #%lu]\n", offsetof(State, gpr.x14));
  printf("str x15, [x28, #%lu]\n", offsetof(State, gpr.x15));
  printf("str x16, [x28, #%lu]\n", offsetof(State, gpr.x16));
  printf("str x17, [x28, #%lu]\n", offsetof(State, gpr.x17));
  printf("str x18, [x28, #%lu]\n", offsetof(State, gpr.x18));
  printf("str x19, [x28, #%lu]\n", offsetof(State, gpr.x19));
  printf("str x20, [x28, #%lu]\n", offsetof(State, gpr.x20));
  printf("str x21, [x28, #%lu]\n", offsetof(State, gpr.x21));
  printf("str x22, [x28, #%lu]\n", offsetof(State, gpr.x22));
  printf("str x23, [x28, #%lu]\n", offsetof(State, gpr.x23));
  printf("str x24, [x28, #%lu]\n", offsetof(State, gpr.x24));
  printf("str x25, [x28, #%lu]\n", offsetof(State, gpr.x25));
  printf("str x26, [x28, #%lu]\n", offsetof(State, gpr.x26));
  printf("str x27, [x28, #%lu]\n", offsetof(State, gpr.x27));
  printf("str x29, [x28, #%lu]\n", offsetof(State, gpr.x29));
  printf("str x30, [x28, #%lu]\n", offsetof(State, gpr.x30));

  // Save the stack pointer.
  printf("mov x29, sp\n");
  printf("str x29, [x28, #%lu]\n", offsetof(State, gpr.sp));

  printf("mov x29, #1\n");

  // Save the N flag.
  printf("strb w29, [x28, #%lu]\n", offsetof(State, sr.n));
  printf("b.mi 1f\n");
  printf("strb wzr, [x28, #%lu]\n", offsetof(State, sr.n));
  printf("1:\n");

  // Save the Z flag.
  printf("strb w29, [x28, #%lu]\n", offsetof(State, sr.z));
  printf("b.eq 1f\n");
  printf("strb wzr, [x28, #%lu]\n", offsetof(State, sr.z));
  printf("1:\n");

  // Save the C flag.
  printf("strb w29, [x28, #%lu]\n", offsetof(State, sr.c));
  printf("b.cs 1f\n");
  printf("strb wzr, [x28, #%lu]\n", offsetof(State, sr.c));
  printf("1:\n");

  // Save the V flag.
  printf("strb w29, [x28, #%lu]\n", offsetof(State, sr.v));
  printf("b.vs 1f\n");
  printf("strb wzr, [x28, #%lu]\n", offsetof(State, sr.v));
  printf("1:\n");

  // Save the real version of the nzvc reg.
  printf("mrs x1, nzcv\n");
  printf("str x1, [x28, #%lu]\n", offsetof(State, nzcv));

  // Save the real version of the nzvc reg for ecv_nzcv.
  printf("mrs x1, nzcv\n");
  printf("str x1, [x28, #%lu]\n", offsetof(State, ecv_nzcv));

  // Floating point condition register.
  printf("mrs x1, fpcr\n");
  printf("str x1, [x28, #%lu]\n", offsetof(State, fpcr));

  // Floating point condition register for ecv_fpsr.
  printf("mrs x1, fpcr\n");
  printf("str x1, [x28, #%lu]\n", offsetof(State, ecv_fpsr));

  // Floating point status register.
  printf("mrs x1, fpsr\n");
  printf("str x1, [x28, #%lu]\n", offsetof(State, fpsr));

  // Save the cumulative invalid operation flag from the FPSR into the SR.
  printf("ubfx x29, x1, #0, #1\n");
  printf("strb w29, [x28, #%lu]\n", offsetof(State, sr.ioc));

  // Save the cumulative overflow flag from the FPSR into the SR.
  printf("ubfx x29, x1, #2, #1\n");
  printf("strb w29, [x28, #%lu]\n", offsetof(State, sr.ofc));

  // Save the cumulative underflow flag from the FPSR into the SR.
  printf("ubfx x29, x1, #3, #1\n");
  printf("strb w29, [x28, #%lu]\n", offsetof(State, sr.ufc));

  // Save the cumulative inexact flag from the FPSR into the SR.
  printf("ubfx x29, x1, #4, #1\n");
  printf("strb w29, [x28, #%lu]\n", offsetof(State, sr.ixc));

  // Save the cumulative input denormal flag from the FPSR into the SR.
  printf("ubfx x29, x1, #6, #1\n");
  printf("strb w29, [x28, #%lu]\n", offsetof(State, sr.idc));

  // Restore x29.
  printf("ldr x29, [x28, #%lu]\n", offsetof(State, gpr.x29));

  // User-space thread pointer register.
  printf("mrs x1, tpidr_el0\n");
  printf("str x1, [x28, #%lu]\n", offsetof(State, sr.tpidr_el0));

  // Secondary user space thread pointer register that is read-only from
  // user space.
  printf("mrs x1, tpidrro_el0\n");
  printf("str x1, [x28, #%lu]\n", offsetof(State, sr.tpidrro_el0));

  // SIMD regs.
  auto base = offsetof(State, simd.v[0]);
  printf("add x1, x28, #%lu\n", base);

  printf("stur q0, [x1, #%lu]\n", offsetof(State, simd.v[0]) - base);
  printf("stur q1, [x1, #%lu]\n", offsetof(State, simd.v[1]) - base);
  printf("stur q2, [x1, #%lu]\n", offsetof(State, simd.v[2]) - base);
  printf("stur q3, [x1, #%lu]\n", offsetof(State, simd.v[3]) - base);
  printf("stur q4, [x1, #%lu]\n", offsetof(State, simd.v[4]) - base);
  printf("stur q5, [x1, #%lu]\n", offsetof(State, simd.v[5]) - base);
  printf("stur q6, [x1, #%lu]\n", offsetof(State, simd.v[6]) - base);
  printf("stur q7, [x1, #%lu]\n", offsetof(State, simd.v[7]) - base);
  printf("stur q8, [x1, #%lu]\n", offsetof(State, simd.v[8]) - base);
  printf("stur q9, [x1, #%lu]\n", offsetof(State, simd.v[9]) - base);
  printf("stur q10, [x1, #%lu]\n", offsetof(State, simd.v[10]) - base);
  printf("stur q11, [x1, #%lu]\n", offsetof(State, simd.v[11]) - base);
  printf("stur q12, [x1, #%lu]\n", offsetof(State, simd.v[12]) - base);
  printf("stur q13, [x1, #%lu]\n", offsetof(State, simd.v[13]) - base);
  printf("stur q14, [x1, #%lu]\n", offsetof(State, simd.v[14]) - base);
  printf("stur q15, [x1, #%lu]\n", offsetof(State, simd.v[15]) - base);

  base = offsetof(State, simd.v[16]);
  printf("add x1, x28, #%lu\n", base);
  printf("stur q16, [x1, #%lu]\n", offsetof(State, simd.v[16]) - base);
  printf("stur q17, [x1, #%lu]\n", offsetof(State, simd.v[17]) - base);
  printf("stur q18, [x1, #%lu]\n", offsetof(State, simd.v[18]) - base);
  printf("stur q19, [x1, #%lu]\n", offsetof(State, simd.v[19]) - base);
  printf("stur q20, [x1, #%lu]\n", offsetof(State, simd.v[20]) - base);
  printf("stur q21, [x1, #%lu]\n", offsetof(State, simd.v[21]) - base);
  printf("stur q22, [x1, #%lu]\n", offsetof(State, simd.v[22]) - base);
  printf("stur q23, [x1, #%lu]\n", offsetof(State, simd.v[23]) - base);
  printf("stur q24, [x1, #%lu]\n", offsetof(State, simd.v[24]) - base);
  printf("stur q25, [x1, #%lu]\n", offsetof(State, simd.v[25]) - base);
  printf("stur q26, [x1, #%lu]\n", offsetof(State, simd.v[26]) - base);
  printf("stur q27, [x1, #%lu]\n", offsetof(State, simd.v[27]) - base);
  printf("stur q28, [x1, #%lu]\n", offsetof(State, simd.v[28]) - base);
  printf("stur q29, [x1, #%lu]\n", offsetof(State, simd.v[29]) - base);
  printf("stur q30, [x1, #%lu]\n", offsetof(State, simd.v[30]) - base);
  printf("stur q31, [x1, #%lu]\n", offsetof(State, simd.v[31]) - base);

  // Restore stolen `x1`.
  printf("ldr x1, [x28, #%lu]\n", offsetof(State, gpr.x1));

  return 0;
}
