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

#include "remill/Arch/AArch64/Runtime/Operators.h"
#include "remill/Arch/AArch64/Runtime/State.h"
#include "remill/Arch/AArch64/Runtime/Types.h"
#include "remill/Arch/Name.h"
#include "remill/Arch/Runtime/Float.h"
#include "remill/Arch/Runtime/Intrinsics.h"
#include "remill/Arch/Runtime/Operators.h"
#include "remill/Arch/Runtime/Types.h"

namespace {

#define SR_NZCV__N ((sr_nzcv & 0b1000) >> 3)
#define SR_NZCV__Z ((sr_nzcv & 0b100) >> 2)
#define SR_NZCV__C ((sr_nzcv & 0b10) >> 1)
#define SR_NZCV__V (sr_nzcv & 0b1)

// when '101' result = (PSTATE.N == PSTATE.V); // GE or LT
static inline uint8_t CondGE(uint64_t sr_nzcv) {
  return SR_NZCV__N == SR_NZCV__V;
  // return __remill_compare_sge(FLAG_N == FLAG_V);
}

// when '101' result = (PSTATE.N == PSTATE.V); // GE or LT
static inline uint8_t CondLT(uint64_t sr_nzcv) {
  return SR_NZCV__N != SR_NZCV__V;
  // return __remill_compare_slt(FLAG_N != FLAG_V);
}

// when '000' result = (PSTATE.Z == '1'); // EQ or NE
static inline uint8_t CondEQ(uint64_t sr_nzcv) {
  return SR_NZCV__Z;
  // return __remill_compare_eq(FLAG_Z);
}

// when '000' result = (PSTATE.Z == '1'); // EQ or NE
static inline uint8_t CondNE(uint64_t sr_nzcv) {
  return !SR_NZCV__Z;
  // return __remill_compare_neq(!FLAG_Z);
}

// when '110' result = (PSTATE.N == PSTATE.V && PSTATE.Z == '0'); // GT or LE
static inline uint8_t CondGT(uint64_t sr_nzcv) {
  return (SR_NZCV__N == SR_NZCV__V) && !SR_NZCV__Z;
  // return __remill_compare_sgt((FLAG_N == FLAG_V) && !FLAG_Z);
}

// when '110' result = (PSTATE.N == PSTATE.V && PSTATE.Z == '0'); // GT or LE
static inline uint8_t CondLE(uint64_t sr_nzcv) {
  return (SR_NZCV__N != SR_NZCV__V) || SR_NZCV__Z;
  // return __remill_compare_sle((FLAG_N != FLAG_V) || FLAG_Z);
}

// when '001' result = (PSTATE.C == '1'); // CS or CC
static inline uint8_t CondCS(uint64_t sr_nzcv) {
  return SR_NZCV__C;
  // return __remill_compare_uge(FLAG_C);
}

// when '001' result = (PSTATE.C == '1'); // CS or CC
static inline uint8_t CondCC(uint64_t sr_nzcv) {
  return !SR_NZCV__C;
  // return __remill_compare_ult(!FLAG_C);
}

// when '010' result = (PSTATE.N == '1'); // MI or PL
static inline uint8_t CondMI(uint64_t sr_nzcv) {
  return SR_NZCV__N;
}

// when '010' result = (PSTATE.N == '1'); // MI or PL
static inline uint8_t CondPL(uint64_t sr_nzcv) {
  return !SR_NZCV__N;
}

// when '011' result = (PSTATE.V == '1'); // VS or VC
static inline uint8_t CondVS(uint64_t sr_nzcv) {
  return SR_NZCV__V;
}

// when '011' result = (PSTATE.V == '1'); // VS or VC
static inline uint8_t CondVC(uint64_t sr_nzcv) {
  return !SR_NZCV__V;
}

// when '100' result = (PSTATE.C == '1' && PSTATE.Z == '0'); // HI or LS
static inline uint8_t CondHI(uint64_t sr_nzcv) {
  return SR_NZCV__C && !SR_NZCV__Z;
  // return __remill_compare_ugt(FLAG_C && !FLAG_Z);
}

// when '100' result = (PSTATE.C == '1' && PSTATE.Z == '0'); // HI or LS
static inline uint8_t CondLS(uint64_t sr_nzcv) {
  return !SR_NZCV__C || SR_NZCV__Z;
  // return __remill_compare_ule(!FLAG_C || FLAG_Z);
}

static inline uint8_t CondAL(uint64_t sr_nzcv) {
  return true;
}

}  // namespace

DEF_COND(GE) = CondGE;
DEF_COND(GT) = CondGT;

DEF_COND(LE) = CondLE;
DEF_COND(LT) = CondLT;

DEF_COND(EQ) = CondEQ;
DEF_COND(NE) = CondNE;

DEF_COND(CS) = CondCS;
DEF_COND(CC) = CondCC;

DEF_COND(MI) = CondMI;
DEF_COND(PL) = CondPL;

DEF_COND(VS) = CondVS;
DEF_COND(VC) = CondVC;

DEF_COND(HI) = CondHI;
DEF_COND(LS) = CondLS;

DEF_COND(AL) = CondAL;

namespace {

// BR  <Xn>
DEF_SEM_VOID(DoDirectBranch) {}

// B  <label>
DEF_SEM_VOID(DoIndirectBranch) {}

// B.<cond>  <label>
template <uint8_t (*check_cond)(uint64_t sr_nzcv)>
DEF_SEM_U64(DirectCondBranch, R64 sr_nzcv_src) {
  return check_cond(Read(sr_nzcv_src));
}

// CBZ  <Xt>, <label>
template <typename S>
DEF_SEM_T(CBZ, S src) {
  return UCmpEq(Read(src), 0);
}

// CBNZ  <Wt>, <label>
template <typename S>
DEF_SEM_T(CBNZ, S src) {
  return UCmpNeq(Read(src), 0);
}

// TBZ  <R><t>, #<imm>, <label>
template <typename S>
DEF_SEM_T(TBZ, I8 bit_pos, S src) {
  auto bit_n = ZExtTo<S>(Read(bit_pos));
  auto reg_val = ZExtTo<S>(Read(src));
  auto bit_set = UAnd(reg_val, UShl(ZExtTo<S>(1), bit_n));
  return UCmpEq(bit_set, 0);
}

// TBNZ  <R><t>, #<imm>, <label>
template <typename S>
DEF_SEM_T(TBNZ, I8 bit_pos, S src) {
  auto bit_n = ZExtTo<S>(Read(bit_pos));
  auto reg_val = ZExtTo<S>(Read(src));
  auto bit_set = UAnd(reg_val, UShl(ZExtTo<S>(1), bit_n));
  return UCmpNeq(bit_set, 0);
}

}  // namespace

DEF_ISEL(BR_64_BRANCH_REG) = DoIndirectBranch;

DEF_ISEL(B_ONLY_BRANCH_IMM) = DoDirectBranch;

DEF_ISEL(B_ONLY_CONDBRANCH_EQ) = DirectCondBranch<CondEQ>;
DEF_ISEL(B_ONLY_CONDBRANCH_NE) = DirectCondBranch<CondNE>;
DEF_ISEL(B_ONLY_CONDBRANCH_CS) = DirectCondBranch<CondCS>;
DEF_ISEL(B_ONLY_CONDBRANCH_CC) = DirectCondBranch<CondCC>;
DEF_ISEL(B_ONLY_CONDBRANCH_MI) = DirectCondBranch<CondMI>;
DEF_ISEL(B_ONLY_CONDBRANCH_PL) = DirectCondBranch<CondPL>;
DEF_ISEL(B_ONLY_CONDBRANCH_VS) = DirectCondBranch<CondVS>;
DEF_ISEL(B_ONLY_CONDBRANCH_VC) = DirectCondBranch<CondVC>;
DEF_ISEL(B_ONLY_CONDBRANCH_HI) = DirectCondBranch<CondHI>;
DEF_ISEL(B_ONLY_CONDBRANCH_LS) = DirectCondBranch<CondLS>;
DEF_ISEL(B_ONLY_CONDBRANCH_GE) = DirectCondBranch<CondGE>;
DEF_ISEL(B_ONLY_CONDBRANCH_LT) = DirectCondBranch<CondLT>;
DEF_ISEL(B_ONLY_CONDBRANCH_GT) = DirectCondBranch<CondGT>;
DEF_ISEL(B_ONLY_CONDBRANCH_LE) = DirectCondBranch<CondLE>;
DEF_ISEL(B_ONLY_CONDBRANCH_AL) = DirectCondBranch<CondAL>;

DEF_ISEL(CBZ_64_COMPBRANCH) = CBZ<R64>;
DEF_ISEL(CBZ_32_COMPBRANCH) = CBZ<R32>;

DEF_ISEL(CBNZ_64_COMPBRANCH) = CBNZ<R64>;
DEF_ISEL(CBNZ_32_COMPBRANCH) = CBNZ<R32>;

DEF_ISEL(TBZ_ONLY_TESTBRANCH_64) = TBZ<R64>;
DEF_ISEL(TBZ_ONLY_TESTBRANCH_32) = TBZ<R32>;

DEF_ISEL(TBNZ_ONLY_TESTBRANCH_64) = TBNZ<R64>;
DEF_ISEL(TBNZ_ONLY_TESTBRANCH_32) = TBNZ<R32>;
