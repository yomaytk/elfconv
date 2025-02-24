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


// #include "BRANCH.h"
#include "remill/Arch/AArch64/Runtime/Operators.h"
#include "remill/Arch/AArch64/Runtime/State.h"
#include "remill/Arch/AArch64/Runtime/Types.h"
#include "remill/Arch/Name.h"
#include "remill/Arch/Runtime/Float.h"
#include "remill/Arch/Runtime/Intrinsics.h"
#include "remill/Arch/Runtime/Operators.h"
#include "remill/Arch/Runtime/Types.h"

namespace {

// CSEL  <Wd>, <Wn>, <Wm>, <cond>
template <uint64_t (*check_cond)(uint64_t ecv_nzcv)>
DEF_SEM_U32(CSEL32, R32 src1, R32 src2, R64 ecv_nzcv_src) {
  return check_cond(Read(ecv_nzcv_src)) ? Read(src1) : Read(src2);
}

template <uint64_t (*check_cond)(uint64_t ecv_nzcv)>
DEF_SEM_U64(CSEL64, R64 src1, R64 src2, R64 ecv_nzcv_src) {
  return check_cond(Read(ecv_nzcv_src)) ? Read(src1) : Read(src2);
}

// FCSEL  <Sd>, <Sn>, <Sm>, <cond>
template <uint64_t (*check_cond)(uint64_t ecv_nzcv)>
DEF_SEM_F32(FCSEL32, RF32 src1, RF32 src2, R64 ecv_nzcv_src) {
  return check_cond(Read(ecv_nzcv_src)) ? Read(src1) : Read(src2);
}

// FCSEL  <Dd>, <Dn>, <Dm>, <cond>
template <uint64_t (*check_cond)(uint64_t ecv_nzcv)>
DEF_SEM_F64(FCSEL64, RF64 src1, RF64 src2, R64 ecv_nzcv_src) {
  return check_cond(Read(ecv_nzcv_src)) ? Read(src1) : Read(src2);
}

}  // namespace

#define DEF_COND_ISEL(isel, sem, ...) \
  DEF_ISEL(isel##_GE) = sem<CondGE, ##__VA_ARGS__>; \
  DEF_ISEL(isel##_GT) = sem<CondGT, ##__VA_ARGS__>; \
  DEF_ISEL(isel##_LE) = sem<CondLE, ##__VA_ARGS__>; \
  DEF_ISEL(isel##_LT) = sem<CondLT, ##__VA_ARGS__>; \
  DEF_ISEL(isel##_EQ) = sem<CondEQ, ##__VA_ARGS__>; \
  DEF_ISEL(isel##_NE) = sem<CondNE, ##__VA_ARGS__>; \
  DEF_ISEL(isel##_CS) = sem<CondCS, ##__VA_ARGS__>; \
  DEF_ISEL(isel##_CC) = sem<CondCC, ##__VA_ARGS__>; \
  DEF_ISEL(isel##_MI) = sem<CondMI, ##__VA_ARGS__>; \
  DEF_ISEL(isel##_PL) = sem<CondPL, ##__VA_ARGS__>; \
  DEF_ISEL(isel##_VS) = sem<CondVS, ##__VA_ARGS__>; \
  DEF_ISEL(isel##_VC) = sem<CondVC, ##__VA_ARGS__>; \
  DEF_ISEL(isel##_HI) = sem<CondHI, ##__VA_ARGS__>; \
  DEF_ISEL(isel##_LS) = sem<CondLS, ##__VA_ARGS__>;
// DEF_ISEL(isel##_AL) = sem<CondAL, __VA_ARGS__>;

DEF_COND_ISEL(CSEL_32_CONDSEL, CSEL32)  // CSEL  <Wd>, <Wn>, <Wm>, <cond>
DEF_COND_ISEL(CSEL_64_CONDSEL, CSEL64)  // CSEL  <Xd>, <Xn>, <Xm>, <cond>

DEF_COND_ISEL(FCSEL_D_FLOATSEL, FCSEL64)  // FCSEL  <Dd>, <Dn>, <Dm>, <cond>
DEF_COND_ISEL(FCSEL_S_FLOATSEL, FCSEL32)  // FCSEL  <Sd>, <Sn>, <Sm>, <cond>

namespace {

// CSNEG  <Wd>, <Wn>, <Wm>, <cond>
template <uint64_t (*check_cond)(uint64_t ecv_nzcv), typename S1, typename S2>
DEF_SEM_T(CSNEG, S1 src1, S2 src2, R64 ecv_nzcv_src) {
  return Select(check_cond(Read(ecv_nzcv_src)), Read(src1), UAdd(UNot(Read(src2)), ZExtTo<S1>(1)));
}

}  // namespace

DEF_COND_ISEL(CSNEG_32_CONDSEL, CSNEG, R32, R32)  // CSNEG  <Wd>, <Wn>, <Wm>, <cond>
DEF_COND_ISEL(CSNEG_64_CONDSEL, CSNEG, R64, R64)  // CSNEG  <Xd>, <Xn>, <Xm>, <cond>

namespace {

// CSINC  <Wd>, <Wn>, <Wm>, <cond>
template <uint64_t (*check_cond)(uint64_t ecv_nzcv), typename S1, typename S2>
DEF_SEM_T(CSINC, S1 src1, S2 src2, R64 ecv_nzcv_src) {
  return Select(check_cond(Read(ecv_nzcv_src)), Read(src1), UAdd(Read(src2), 1));
}
}  // namespace

DEF_COND_ISEL(CSINC_32_CONDSEL, CSINC, R32, R32)  // CSINC  <Wd>, <Wn>, <Wm>, <cond>
DEF_COND_ISEL(CSINC_64_CONDSEL, CSINC, R64, R64)  // CSINC  <Xd>, <Xn>, <Xm>, <cond>

namespace {

// CSINV  <Wd>, <Wn>, <Wm>, <cond>
template <uint64_t (*check_cond)(uint64_t ecv_nzcv), typename S1, typename S2>
DEF_SEM_T(CSINV, S1 src1, S2 src2, R64 ecv_nzcv_src) {
  return Select(check_cond(Read(ecv_nzcv_src)), Read(src1), UNot(Read(src2)));
}
}  // namespace

DEF_COND_ISEL(CSINV_32_CONDSEL, CSINV, R32, R32)  // CSINV  <Wd>, <Wn>, <Wm>, <cond>
DEF_COND_ISEL(CSINV_64_CONDSEL, CSINV, R64, R64)  // CSINV  <Xd>, <Xn>, <Xm>, <cond>

namespace {

// CCMP  <Wn>, #<imm>, #<nzcv>, <cond>
#define MAKE_CCMP(esize) \
  template <uint64_t (*check_cond)(uint64_t ecv_nzcv), typename S1, typename S2> \
  DEF_SEM_U64(CCMP##esize, S1 src1, S2 src2, S2 nzcv, R64 ecv_nzcv_src) { \
    using T = typename BaseType<S1>::BT; \
    static_assert(sizeof(T) == esize / 8); \
    if (check_cond(Read(ecv_nzcv_src))) { \
      auto [_, flag_nzcv] = \
          AddWithCarryNZCV##esize(Read(src1), UNot(Read(src2)), Read(src2), T(1)); \
      return flag_nzcv; \
    } else { \
      auto nzcv_val = Read(nzcv); \
      uint64_t flag_v = UCmpNeq(UAnd(nzcv_val, T(1)), T(0)); \
      uint64_t flag_c = UCmpNeq(UAnd(nzcv_val, T(2)), T(0)); \
      uint64_t flag_z = UCmpNeq(UAnd(nzcv_val, T(4)), T(0)); \
      uint64_t flag_n = UCmpNeq(UAnd(nzcv_val, T(8)), T(0)); \
      return (flag_n << 3) | (flag_z << 2) | (flag_c << 1) | flag_v; \
    } \
  }

MAKE_CCMP(32)
MAKE_CCMP(64)

#undef MAKE_CCMP

// CCMN  <Wn>, #<imm>, #<nzcv>, <cond>
#define MAKE_CCMN(esize) \
  template <uint64_t (*check_cond)(uint64_t ecv_nzcv), typename S1, typename S2> \
  DEF_SEM_U64(CCMN##esize, S1 src1, S2 src2, S2 nzcv, R64 ecv_nzcv_src) { \
    using T = typename BaseType<S1>::BT; \
    static_assert(sizeof(T) == esize / 8); \
    if (check_cond(Read(ecv_nzcv_src))) { \
      auto [_, flag_nzcv] = AddWithCarryNZCV##esize(Read(src1), Read(src2), Read(src2), T(0)); \
      return flag_nzcv; \
    } else { \
      auto nzcv_val = Read(nzcv); \
      uint64_t flag_v = UCmpNeq(UAnd(nzcv_val, T(1)), T(0)); \
      uint64_t flag_c = UCmpNeq(UAnd(nzcv_val, T(2)), T(0)); \
      uint64_t flag_z = UCmpNeq(UAnd(nzcv_val, T(4)), T(0)); \
      uint64_t flag_n = UCmpNeq(UAnd(nzcv_val, T(8)), T(0)); \
      return (flag_n << 3) | (flag_z << 2) | (flag_c << 1) | flag_v; \
    } \
  }

MAKE_CCMN(32)
MAKE_CCMN(64)

#undef MAKE_CCMN

}  // namespace

DEF_COND_ISEL(CCMP_32_CONDCMP_IMM, CCMP32, R32, I32)  // CCMP  <Wn>, #<imm>, #<nzcv>, <cond>
DEF_COND_ISEL(CCMP_64_CONDCMP_IMM, CCMP64, R64, I64)  // CCMP  <Xn>, #<imm>, #<nzcv>, <cond>

DEF_COND_ISEL(CCMP_32_CONDCMP_REG, CCMP32, R32, R32)  // CCMP  <Wn>, <Wm>, #<nzcv>, <cond>
DEF_COND_ISEL(CCMP_64_CONDCMP_REG, CCMP64, R64, R64)  // CCMP  <Xn>, <Xm>, #<nzcv>, <cond>

DEF_COND_ISEL(CCMN_32_CONDCMP_IMM, CCMN32, R32, I32)  // CCMN  <Wn>, #<imm>, #<nzcv>, <cond>
DEF_COND_ISEL(CCMN_64_CONDCMP_IMM, CCMN64, R64, I64)  // CCMN  <Xn>, #<imm>, #<nzcv>, <cond>
