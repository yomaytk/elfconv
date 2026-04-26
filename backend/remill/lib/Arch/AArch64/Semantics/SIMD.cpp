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

// Disable the "loop not unrolled warnings"
#include "remill/Arch/AArch64/Runtime/AArch64Definitions.h"
#include "remill/Arch/AArch64/Runtime/Types.h"
#include "remill/Arch/Runtime/Definitions.h"
#include "remill/Arch/Runtime/Types.h"

#include <algorithm>
#include <type_traits>
#pragma clang diagnostic ignored "-Wpass-failed"

namespace {

template <typename S>
DEF_SEM_T(ORR_Vec, S src1, S src2) {
  return UOrVI64(UReadVI64(src1), UReadVI64(src2));
}

template <typename S>
DEF_SEM_T(AND_Vec, S src1, S src2) {
  return UAndVI64(UReadVI64(src1), UReadVI64(src2));
}

template <typename S>
DEF_SEM_T(BIC_Vec, S src1, S src2) {
  return UAndVI64(UReadVI64(src1), UNotVI64(UReadVI64(src2)));
}

template <typename S>
DEF_SEM_T(EOR_Vec, S src1, S src2) {
  auto operand4 = UReadVI64(src1);
  auto operand1 = UReadVI64(src2);
  auto operand2 = UClearVI64(operand4);
  auto operand3 = UNotVI64(operand2);
  return UXorVI64(operand1, UAndVI64(UXorVI64(operand2, operand4), operand3));
}

template <typename S>
DEF_SEM_T(BIT_Vec, S dst_src, S src1, S src2) {
  auto operand4 = UReadVI64(src1);
  auto operand1 = UReadVI64(dst_src);
  auto operand3 = UReadVI64(src2);
  return UXorVI64(operand1, UAndVI64(UXorVI64(operand1, operand4), operand3));
}

template <typename S>
DEF_SEM_T(BIF_Vec, S dst_src, S src1, S src2) {
  auto operand4 = UReadVI64(src1);
  auto operand1 = UReadVI64(dst_src);
  auto operand3 = UNotVI64(UReadVI64(src2));
  return UXorVI64(operand1, UAndVI64(UXorVI64(operand1, operand4), operand3));
}

template <typename S>
DEF_SEM_T(BSL_Vec, S dst_src, S src1, S src2) {
  auto operand4 = UReadVI64(src1);
  auto operand1 = UReadVI64(src2);
  auto operand3 = UReadVI64(dst_src);
  return UXorVI64(operand1, UAndVI64(UXorVI64(operand1, operand4), operand3));
}

}  // namespace

DEF_ISEL(ORR_ASIMDSAME_ONLY_8B) = ORR_Vec<VIu64v1>;  // ORR  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(ORR_ASIMDSAME_ONLY_16B) = ORR_Vec<VIu64v2>;  // ORR  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>

DEF_ISEL(AND_ASIMDSAME_ONLY_8B) = AND_Vec<VIu64v1>;  // AND  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(AND_ASIMDSAME_ONLY_16B) = AND_Vec<VIu64v2>;  // AND  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>

DEF_ISEL(BIC_ASIMDSAME_ONLY_8B) = BIC_Vec<VIu64v1>;  // BIC  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(BIC_ASIMDSAME_ONLY_16B) = BIC_Vec<VIu64v2>;  // BIC  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>

DEF_ISEL(EOR_ASIMDSAME_ONLY_8B) = EOR_Vec<VIu64v1>;  // EOR  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(EOR_ASIMDSAME_ONLY_16B) = EOR_Vec<VIu64v2>;  // EOR  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>

DEF_ISEL(BIT_ASIMDSAME_ONLY_8B) = BIT_Vec<VIu64v1>;  // BIT  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(BIT_ASIMDSAME_ONLY_16B) = BIT_Vec<VIu64v2>;  // BIT  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>

DEF_ISEL(BIF_ASIMDSAME_ONLY_8B) = BIF_Vec<VIu64v1>;  // BIF  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(BIF_ASIMDSAME_ONLY_16B) = BIF_Vec<VIu64v2>;  // BIF  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>

DEF_ISEL(BSL_ASIMDSAME_ONLY_8B) = BSL_Vec<VIu64v1>;  // BSL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(BSL_ASIMDSAME_ONLY_16B) = BSL_Vec<VIu64v2>;  // BSL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>

namespace {

DEF_SEM_U64(FMOV_VectorToUInt64, VIu64v2 src) {
  auto val = UExtractVI64(UReadVI64(src), 1);
  return val;
}

DEF_SEM_U128V1(FMOV_UInt64ToVector, VIu64v2 dst_src, R64 src) {
  auto val = Read(src);
  _ecv_u64v2_t res = {};
  res[0] = UReadVI64(dst_src)[0];
  res[1] = val;
  return *reinterpret_cast<_ecv_u128v1_t *>(&res);
}
}  // namespace

DEF_ISEL(FMOV_64VX_FLOAT2INT) = FMOV_VectorToUInt64;
DEF_ISEL(FMOV_V64I_FLOAT2INT) = FMOV_UInt64ToVector;

namespace {

#define MAKE_DUP(size) \
  template <typename V> \
  DEF_SEM_T(DUP_##size, R64 src) { \
    auto val = TruncTo<uint##size##_t>(Read(src)); \
    V vec = {}; \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(vec); ++i) { \
      vec[i] = val; \
    } \
    return vec; \
  }  // namespace

MAKE_DUP(8) MAKE_DUP(16) MAKE_DUP(32) MAKE_DUP(64)

#undef MAKE_DUP

}  // namespace

DEF_ISEL(DUP_ASIMDINS_DR_R_8B) = DUP_8<VIu8v8>;  // DUP  <Vd>.<T>, <R><n>
DEF_ISEL(DUP_ASIMDINS_DR_R_16B) = DUP_8<VIu8v16>;  // DUP  <Vd>.<T>, <R><n>
DEF_ISEL(DUP_ASIMDINS_DR_R_4H) = DUP_16<VIu16v4>;  // DUP  <Vd>.<T>, <R><n>
DEF_ISEL(DUP_ASIMDINS_DR_R_8H) = DUP_16<VIu16v8>;  // DUP  <Vd>.<T>, <R><n>
DEF_ISEL(DUP_ASIMDINS_DR_R_2S) = DUP_32<VIu32v2>;  // DUP  <Vd>.<T>, <R><n>
DEF_ISEL(DUP_ASIMDINS_DR_R_4S) = DUP_32<VIu32v4>;  // DUP  <Vd>.<T>, <R><n>
DEF_ISEL(DUP_ASIMDINS_DR_R_2D) = DUP_64<VIu64v2>;  // DUP  <Vd>.<T>, <R><n>

// DUP  <Vd>.<T>, <Vn>.<Ts>[<index>]
namespace {

#define MAKE_DUP(size) \
  template <typename V, typename SV> \
  DEF_SEM_T(DUP_DV_##size, SV src, I32 imm) { \
    auto index = Read(imm); \
    V src_vec = UReadVI##size(src); \
    auto val = TruncTo<uint##size##_t>(UExtractVI##size(src_vec, index)); \
    V vec = {}; \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(vec); i++) { \
      vec[i] = val; \
    } \
    return vec; \
  }

MAKE_DUP(8);
MAKE_DUP(16);
MAKE_DUP(32);
MAKE_DUP(64);

#undef MAKE_DUP

}  // namespace

DEF_ISEL(DUP_ASIMDINS_DV_V_8B) = DUP_DV_8<VIu8v8, VIu8v8>;  // DUP  <Vd>.<T>, <Vn>.<Ts>[<index>]
DEF_ISEL(DUP_ASIMDINS_DV_V_16B) = DUP_DV_8<VIu8v16, VIu8v16>;  // DUP  <Vd>.<T>, <Vn>.<Ts>[<index>]
DEF_ISEL(DUP_ASIMDINS_DV_V_4H) = DUP_DV_16<VIu16v4, VIu16v4>;  // DUP  <Vd>.<T>, <Vn>.<Ts>[<index>]
DEF_ISEL(DUP_ASIMDINS_DV_V_8H) = DUP_DV_16<VIu16v8, VIu16v8>;  // DUP  <Vd>.<T>, <Vn>.<Ts>[<index>]
DEF_ISEL(DUP_ASIMDINS_DV_V_2S) = DUP_DV_32<VIu32v2, VIu32v2>;  // DUP  <Vd>.<T>, <Vn>.<Ts>[<index>]
DEF_ISEL(DUP_ASIMDINS_DV_V_4S) = DUP_DV_32<VIu32v4, VIu32v4>;  // DUP  <Vd>.<T>, <Vn>.<Ts>[<index>]
DEF_ISEL(DUP_ASIMDINS_DV_V_2D) = DUP_DV_64<VIu64v2, VIu64v2>;  // DUP  <Vd>.<T>, <Vn>.<Ts>[<index>]

namespace {

template <typename T>
ALWAYS_INLINE static T UMin(T lhs, T rhs) {
  return lhs < rhs ? lhs : rhs;
}

template <typename T>
ALWAYS_INLINE static T UMax(T lhs, T rhs) {
  return lhs < rhs ? rhs : lhs;
}

#define SMin UMin
#define SMax UMax

#define MAKE_BROADCAST(op, prefix, binop, size) \
  template <typename V> \
  DEF_SEM_T(op##_##size, V src1, V src2) { \
    auto vec1 = prefix##ReadVI##size(src1); \
    auto vec2 = prefix##ReadVI##size(src2); \
    V sum = {}; \
    _Pragma("unroll") for (size_t i = 0, max_i = GetVectorElemsNum(sum); i < max_i; ++i) { \
      sum[i] = prefix##binop(vec1[i], vec2[i]); \
    } \
    return sum; \
  }

MAKE_BROADCAST(ADD, U, Add, 8)
MAKE_BROADCAST(ADD, U, Add, 16)
MAKE_BROADCAST(ADD, U, Add, 32)
MAKE_BROADCAST(ADD, U, Add, 64)

MAKE_BROADCAST(SUB, U, Sub, 8)
MAKE_BROADCAST(SUB, U, Sub, 16)
MAKE_BROADCAST(SUB, U, Sub, 32)
MAKE_BROADCAST(SUB, U, Sub, 64)

MAKE_BROADCAST(UMIN, U, Min, 8)
MAKE_BROADCAST(UMIN, U, Min, 16)
MAKE_BROADCAST(UMIN, U, Min, 32)

MAKE_BROADCAST(SMIN, S, Min, 8)
MAKE_BROADCAST(SMIN, S, Min, 16)
MAKE_BROADCAST(SMIN, S, Min, 32)

MAKE_BROADCAST(UMAX, U, Max, 8)
MAKE_BROADCAST(UMAX, U, Max, 16)
MAKE_BROADCAST(UMAX, U, Max, 32)

MAKE_BROADCAST(SMAX, S, Max, 8)
MAKE_BROADCAST(SMAX, S, Max, 16)
MAKE_BROADCAST(SMAX, S, Max, 32)

// SSHL shifts by signed values in the second operand
#define MAKE_SSHL(size) \
  template <typename V> \
  DEF_SEM_T(SSHL_##size, V src1, V src2) { \
    auto vec1 = SReadVI##size(src1); \
    auto vec2 = SReadVI##size(src2); \
    V res = {}; \
    _Pragma("unroll") for (size_t i = 0, max_i = GetVectorElemsNum(res); i < max_i; ++i) { \
      auto shift = SExtractVI##size(vec2, i); \
      auto val = SExtractVI##size(vec1, i); \
      if (shift >= 0) { \
        res[i] = val << shift; \
      } else { \
        res[i] = val >> (-shift); \
      } \
    } \
    return res; \
  }

MAKE_SSHL(8)
MAKE_SSHL(16)
MAKE_SSHL(32)
MAKE_SSHL(64)

#undef MAKE_SSHL

#undef MAKE_BROADCAST

}  // namespace

DEF_ISEL(ADD_ASIMDSAME_ONLY_8B) = ADD_8<VIu8v8>;  // ADD  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(ADD_ASIMDSAME_ONLY_16B) = ADD_8<VIu8v16>;  // ADD  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(ADD_ASIMDSAME_ONLY_4H) = ADD_16<VIu16v4>;  // ADD  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(ADD_ASIMDSAME_ONLY_8H) = ADD_16<VIu16v8>;  // ADD  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(ADD_ASIMDSAME_ONLY_2S) = ADD_32<VIu32v2>;  // ADD  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(ADD_ASIMDSAME_ONLY_4S) = ADD_32<VIu32v4>;  // ADD  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(ADD_ASIMDSAME_ONLY_2D) = ADD_64<VIu64v2>;  // ADD  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>

DEF_ISEL(SUB_ASIMDSAME_ONLY_8B) = SUB_8<VIu8v8>;  // SUB  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(SUB_ASIMDSAME_ONLY_16B) = SUB_8<VIu8v16>;  // SUB  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(SUB_ASIMDSAME_ONLY_4H) = SUB_16<VIu16v4>;  // SUB  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(SUB_ASIMDSAME_ONLY_8H) = SUB_16<VIu16v8>;  // SUB  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(SUB_ASIMDSAME_ONLY_2S) = SUB_32<VIu32v2>;  // SUB  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(SUB_ASIMDSAME_ONLY_4S) = SUB_32<VIu32v4>;  // SUB  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(SUB_ASIMDSAME_ONLY_2D) = SUB_64<VIu64v2>;  // SUB  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>

DEF_ISEL(SSHL_ASIMDSAME_ONLY_8B) = SSHL_8<VIi8v8>;  // SSHL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(SSHL_ASIMDSAME_ONLY_16B) = SSHL_8<VIi8v16>;  // SSHL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(SSHL_ASIMDSAME_ONLY_4H) = SSHL_16<VIi16v4>;  // SSHL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(SSHL_ASIMDSAME_ONLY_8H) = SSHL_16<VIi16v8>;  // SSHL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(SSHL_ASIMDSAME_ONLY_2S) = SSHL_32<VIi32v2>;  // SSHL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(SSHL_ASIMDSAME_ONLY_4S) = SSHL_32<VIi32v4>;  // SSHL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(SSHL_ASIMDSAME_ONLY_2D) = SSHL_64<VIi64v2>;  // SSHL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>

DEF_ISEL(UMIN_ASIMDSAME_ONLY_8B) = UMIN_8<VIu8v8>;  // UMIN  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(UMIN_ASIMDSAME_ONLY_16B) = UMIN_8<VIu8v16>;  // UMIN  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(UMIN_ASIMDSAME_ONLY_4H) = UMIN_16<VIu16v4>;  // UMIN  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(UMIN_ASIMDSAME_ONLY_8H) = UMIN_16<VIu16v8>;  // UMIN  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(UMIN_ASIMDSAME_ONLY_2S) = UMIN_32<VIu32v2>;  // UMIN  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(UMIN_ASIMDSAME_ONLY_4S) = UMIN_32<VIu32v4>;  // UMIN  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>

DEF_ISEL(UMAX_ASIMDSAME_ONLY_8B) = UMAX_8<VIu8v8>;  // UMAX  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(UMAX_ASIMDSAME_ONLY_16B) = UMAX_8<VIu8v16>;  // UMAX  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(UMAX_ASIMDSAME_ONLY_4H) = UMAX_16<VIu16v4>;  // UMAX  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(UMAX_ASIMDSAME_ONLY_8H) = UMAX_16<VIu16v8>;  // UMAX  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(UMAX_ASIMDSAME_ONLY_2S) = UMAX_32<VIu32v2>;  // UMAX  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(UMAX_ASIMDSAME_ONLY_4S) = UMAX_32<VIu32v4>;  // UMAX  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>

DEF_ISEL(SMIN_ASIMDSAME_ONLY_8B) = SMIN_8<VIi8v8>;  // SMIN  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(SMIN_ASIMDSAME_ONLY_16B) = SMIN_8<VIi8v16>;  // SMIN  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(SMIN_ASIMDSAME_ONLY_4H) = SMIN_16<VIi16v4>;  // SMIN  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(SMIN_ASIMDSAME_ONLY_8H) = SMIN_16<VIi16v8>;  // SMIN  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(SMIN_ASIMDSAME_ONLY_2S) = SMIN_32<VIi32v2>;  // SMIN  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(SMIN_ASIMDSAME_ONLY_4S) = SMIN_32<VIi32v4>;  // SMIN  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>

DEF_ISEL(SMAX_ASIMDSAME_ONLY_8B) = SMAX_8<VIi8v8>;  // SMAX  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(SMAX_ASIMDSAME_ONLY_16B) = SMAX_8<VIi8v16>;  // SMAX  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(SMAX_ASIMDSAME_ONLY_4H) = SMAX_16<VIi16v4>;  // SMAX  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(SMAX_ASIMDSAME_ONLY_8H) = SMAX_16<VIi16v8>;  // SMAX  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(SMAX_ASIMDSAME_ONLY_2S) = SMAX_32<VIi32v2>;  // SMAX  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(SMAX_ASIMDSAME_ONLY_4S) = SMAX_32<VIi32v4>;  // SMAX  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>

namespace {

#define MAKE_CMP_BROADCAST(op, prefix, binop, size) \
  template <typename SV, typename V> \
  DEF_SEM_T(op##_##size, SV src1, I##size imm) { \
    auto vec1 = prefix##ReadVI##size(src1); \
    auto ucmp_val = Read(imm); \
    auto cmp_val = Signed(ucmp_val); \
    decltype(ucmp_val) zeros = 0; \
    decltype(ucmp_val) ones = ~zeros; \
    V res = {}; \
    _Pragma("unroll") for (size_t i = 0, max_i = GetVectorElemsNum(res); i < max_i; ++i) { \
      res[i] = Select(prefix##binop(prefix##ExtractVI##size(vec1, i), cmp_val), ones, zeros); \
    } \
    return res; \
  }

MAKE_CMP_BROADCAST(CMPEQ_IMM, S, CmpEq, 8)
MAKE_CMP_BROADCAST(CMPEQ_IMM, S, CmpEq, 16)
MAKE_CMP_BROADCAST(CMPEQ_IMM, S, CmpEq, 32)
MAKE_CMP_BROADCAST(CMPEQ_IMM, S, CmpEq, 64)

MAKE_CMP_BROADCAST(CMPLT_IMM, S, CmpLt, 8)
MAKE_CMP_BROADCAST(CMPLT_IMM, S, CmpLt, 16)
MAKE_CMP_BROADCAST(CMPLT_IMM, S, CmpLt, 32)
MAKE_CMP_BROADCAST(CMPLT_IMM, S, CmpLt, 64)

MAKE_CMP_BROADCAST(CMPLE_IMM, S, CmpLte, 8)
MAKE_CMP_BROADCAST(CMPLE_IMM, S, CmpLte, 16)
MAKE_CMP_BROADCAST(CMPLE_IMM, S, CmpLte, 32)
MAKE_CMP_BROADCAST(CMPLE_IMM, S, CmpLte, 64)

MAKE_CMP_BROADCAST(CMPGT_IMM, S, CmpGt, 8)
MAKE_CMP_BROADCAST(CMPGT_IMM, S, CmpGt, 16)
MAKE_CMP_BROADCAST(CMPGT_IMM, S, CmpGt, 32)
MAKE_CMP_BROADCAST(CMPGT_IMM, S, CmpGt, 64)

MAKE_CMP_BROADCAST(CMPGE_IMM, S, CmpGte, 8)
MAKE_CMP_BROADCAST(CMPGE_IMM, S, CmpGte, 16)
MAKE_CMP_BROADCAST(CMPGE_IMM, S, CmpGte, 32)
MAKE_CMP_BROADCAST(CMPGE_IMM, S, CmpGte, 64)

#undef MAKE_CMP_BROADCAST

}  // namespace

DEF_ISEL(CMEQ_ASIMDMISC_Z_8B) = CMPEQ_IMM_8<VIi8v8, VIu8v8>;  // CMEQ  <Vd>.<T>, <Vn>.<T>, #0
DEF_ISEL(CMLT_ASIMDMISC_Z_8B) = CMPLT_IMM_8<VIi8v8, VIu8v8>;  // CMLT  <Vd>.<T>, <Vn>.<T>, #0
DEF_ISEL(CMLE_ASIMDMISC_Z_8B) = CMPLE_IMM_8<VIi8v8, VIu8v8>;  // CMLE  <Vd>.<T>, <Vn>.<T>, #0
DEF_ISEL(CMGT_ASIMDMISC_Z_8B) = CMPGT_IMM_8<VIi8v8, VIu8v8>;  // CMGT  <Vd>.<T>, <Vn>.<T>, #0
DEF_ISEL(CMGE_ASIMDMISC_Z_8B) = CMPGE_IMM_8<VIi8v8, VIu8v8>;  // CMGE  <Vd>.<T>, <Vn>.<T>, #0

DEF_ISEL(CMEQ_ASIMDMISC_Z_16B) = CMPEQ_IMM_8<VIi8v16, VIu8v16>;  // CMEQ  <Vd>.<T>, <Vn>.<T>, #0
DEF_ISEL(CMLT_ASIMDMISC_Z_16B) = CMPLT_IMM_8<VIi8v16, VIu8v16>;  // CMLT  <Vd>.<T>, <Vn>.<T>, #0
DEF_ISEL(CMLE_ASIMDMISC_Z_16B) = CMPLE_IMM_8<VIi8v16, VIu8v16>;  // CMLE  <Vd>.<T>, <Vn>.<T>, #0
DEF_ISEL(CMGT_ASIMDMISC_Z_16B) = CMPGT_IMM_8<VIi8v16, VIu8v16>;  // CMGT  <Vd>.<T>, <Vn>.<T>, #0
DEF_ISEL(CMGE_ASIMDMISC_Z_16B) = CMPGE_IMM_8<VIi8v16, VIu8v16>;  // CMGE  <Vd>.<T>, <Vn>.<T>, #0

DEF_ISEL(CMEQ_ASIMDMISC_Z_4H) = CMPEQ_IMM_16<VIi16v4, VIu16v4>;  // CMEQ  <Vd>.<T>, <Vn>.<T>, #0
DEF_ISEL(CMLT_ASIMDMISC_Z_4H) = CMPLT_IMM_16<VIi16v4, VIu16v4>;  // CMLT  <Vd>.<T>, <Vn>.<T>, #0
DEF_ISEL(CMLE_ASIMDMISC_Z_4H) = CMPLE_IMM_16<VIi16v4, VIu16v4>;  // CMLE  <Vd>.<T>, <Vn>.<T>, #0
DEF_ISEL(CMGT_ASIMDMISC_Z_4H) = CMPGT_IMM_16<VIi16v4, VIu16v4>;  // CMGT  <Vd>.<T>, <Vn>.<T>, #0
DEF_ISEL(CMGE_ASIMDMISC_Z_4H) = CMPGE_IMM_16<VIi16v4, VIu16v4>;  // CMGE  <Vd>.<T>, <Vn>.<T>, #0

DEF_ISEL(CMEQ_ASIMDMISC_Z_8H) = CMPEQ_IMM_16<VIi16v8, VIu16v8>;  // CMEQ  <Vd>.<T>, <Vn>.<T>, #0
DEF_ISEL(CMLT_ASIMDMISC_Z_8H) = CMPLT_IMM_16<VIi16v8, VIu16v8>;  // CMLT  <Vd>.<T>, <Vn>.<T>, #0
DEF_ISEL(CMLE_ASIMDMISC_Z_8H) = CMPLE_IMM_16<VIi16v8, VIu16v8>;  // CMLE  <Vd>.<T>, <Vn>.<T>, #0
DEF_ISEL(CMGT_ASIMDMISC_Z_8H) = CMPGT_IMM_16<VIi16v8, VIu16v8>;  // CMGT  <Vd>.<T>, <Vn>.<T>, #0
DEF_ISEL(CMGE_ASIMDMISC_Z_8H) = CMPGE_IMM_16<VIi16v8, VIu16v8>;  // CMGE  <Vd>.<T>, <Vn>.<T>, #0

DEF_ISEL(CMEQ_ASIMDMISC_Z_2S) = CMPEQ_IMM_32<VIi32v2, VIu32v2>;  // CMEQ  <Vd>.<T>, <Vn>.<T>, #0
DEF_ISEL(CMLT_ASIMDMISC_Z_2S) = CMPLT_IMM_32<VIi32v2, VIu32v2>;  // CMLT  <Vd>.<T>, <Vn>.<T>, #0
DEF_ISEL(CMLE_ASIMDMISC_Z_2S) = CMPLE_IMM_32<VIi32v2, VIu32v2>;  // CMLE  <Vd>.<T>, <Vn>.<T>, #0
DEF_ISEL(CMGT_ASIMDMISC_Z_2S) = CMPGT_IMM_32<VIi32v2, VIu32v2>;  // CMGT  <Vd>.<T>, <Vn>.<T>, #0
DEF_ISEL(CMGE_ASIMDMISC_Z_2S) = CMPGE_IMM_32<VIi32v2, VIu32v2>;  // CMGE  <Vd>.<T>, <Vn>.<T>, #0

DEF_ISEL(CMEQ_ASIMDMISC_Z_4S) = CMPEQ_IMM_32<VIi32v4, VIu32v4>;  // CMEQ  <Vd>.<T>, <Vn>.<T>, #0
DEF_ISEL(CMLT_ASIMDMISC_Z_4S) = CMPLT_IMM_32<VIi32v4, VIu32v4>;  // CMLT  <Vd>.<T>, <Vn>.<T>, #0
DEF_ISEL(CMLE_ASIMDMISC_Z_4S) = CMPLE_IMM_32<VIi32v4, VIu32v4>;  // CMLE  <Vd>.<T>, <Vn>.<T>, #0
DEF_ISEL(CMGT_ASIMDMISC_Z_4S) = CMPGT_IMM_32<VIi32v4, VIu32v4>;  // CMGT  <Vd>.<T>, <Vn>.<T>, #0
DEF_ISEL(CMGE_ASIMDMISC_Z_4S) = CMPGE_IMM_32<VIi32v4, VIu32v4>;  // CMGE  <Vd>.<T>, <Vn>.<T>, #0

DEF_ISEL(CMEQ_ASIMDMISC_Z_1D) = CMPEQ_IMM_64<VIi64v1, VIu64v1>;  // CMEQ  <Vd>.<T>, <Vn>.<T>, #0
DEF_ISEL(CMLT_ASIMDMISC_Z_1D) = CMPLT_IMM_64<VIi64v1, VIu64v1>;  // CMLT  <Vd>.<T>, <Vn>.<T>, #0
DEF_ISEL(CMLE_ASIMDMISC_Z_1D) = CMPLE_IMM_64<VIi64v1, VIu64v1>;  // CMLE  <Vd>.<T>, <Vn>.<T>, #0
DEF_ISEL(CMGT_ASIMDMISC_Z_1D) = CMPGT_IMM_64<VIi64v1, VIu64v1>;  // CMGT  <Vd>.<T>, <Vn>.<T>, #0
DEF_ISEL(CMGE_ASIMDMISC_Z_1D) = CMPGE_IMM_64<VIi64v1, VIu64v1>;  // CMGE  <Vd>.<T>, <Vn>.<T>, #0

DEF_ISEL(CMEQ_ASIMDMISC_Z_2D) = CMPEQ_IMM_64<VIi64v2, VIu64v2>;  // CMEQ  <Vd>.<T>, <Vn>.<T>, #0
DEF_ISEL(CMLT_ASIMDMISC_Z_2D) = CMPLT_IMM_64<VIi64v2, VIu64v2>;  // CMLT  <Vd>.<T>, <Vn>.<T>, #0
DEF_ISEL(CMLE_ASIMDMISC_Z_2D) = CMPLE_IMM_64<VIi64v2, VIu64v2>;  // CMLE  <Vd>.<T>, <Vn>.<T>, #0
DEF_ISEL(CMGT_ASIMDMISC_Z_2D) = CMPGT_IMM_64<VIi64v2, VIu64v2>;  // CMGT  <Vd>.<T>, <Vn>.<T>, #0
DEF_ISEL(CMGE_ASIMDMISC_Z_2D) = CMPGE_IMM_64<VIi64v2, VIu64v2>;  // CMGE  <Vd>.<T>, <Vn>.<T>, #0

namespace {

DEF_SEM_T(CMGE_ASISDMISC_ONLYD, VIi64v1 src) {
  auto src_v = SReadVI64(src);
  int64_t element = src_v[0];
  return element >= 0 ? ~0ULL : 0ULL;
}

}  // namespace

DEF_ISEL(CMGE_ASISDMISC_Z) = CMGE_ASISDMISC_ONLYD;  // CMGE  <V><d>, <V><n>, #0

namespace {

#define MAKE_CMP_BROADCAST(op, prefix, binop, size) \
  template <typename SV, typename V> \
  DEF_SEM_T(op##_##size, SV src1, SV src2) { \
    auto vec1 = prefix##ReadVI##size(src1); \
    auto vec2 = prefix##ReadVI##size(src2); \
    uint##size##_t zeros = 0; \
    uint##size##_t ones = ~zeros; \
    V res = {}; \
    _Pragma("unroll") for (size_t i = 0, max_i = GetVectorElemsNum(res); i < max_i; ++i) { \
      res[i] = Select( \
          prefix##binop(prefix##ExtractVI##size(vec1, i), prefix##ExtractVI##size(vec2, i)), ones, \
          zeros); \
    } \
    return res; \
  }

template <typename T>
ALWAYS_INLINE static bool UCmpTst(T lhs, T rhs) {
  return UCmpNeq(UAnd(lhs, rhs), T(0));
}

MAKE_CMP_BROADCAST(CMPEQ, S, CmpEq, 8)
MAKE_CMP_BROADCAST(CMPEQ, S, CmpEq, 16)
MAKE_CMP_BROADCAST(CMPEQ, S, CmpEq, 32)
MAKE_CMP_BROADCAST(CMPEQ, S, CmpEq, 64)

MAKE_CMP_BROADCAST(CMPTST, U, CmpTst, 8)
MAKE_CMP_BROADCAST(CMPTST, U, CmpTst, 16)
MAKE_CMP_BROADCAST(CMPTST, U, CmpTst, 32)
MAKE_CMP_BROADCAST(CMPTST, U, CmpTst, 64)

MAKE_CMP_BROADCAST(CMPGT, S, CmpGt, 8)
MAKE_CMP_BROADCAST(CMPGT, S, CmpGt, 16)
MAKE_CMP_BROADCAST(CMPGT, S, CmpGt, 32)
MAKE_CMP_BROADCAST(CMPGT, S, CmpGt, 64)

MAKE_CMP_BROADCAST(CMPGE, S, CmpGte, 8)
MAKE_CMP_BROADCAST(CMPGE, S, CmpGte, 16)
MAKE_CMP_BROADCAST(CMPGE, S, CmpGte, 32)
MAKE_CMP_BROADCAST(CMPGE, S, CmpGte, 64)

MAKE_CMP_BROADCAST(CMPHS, U, CmpGte, 8)
MAKE_CMP_BROADCAST(CMPHS, U, CmpGte, 16)
MAKE_CMP_BROADCAST(CMPHS, U, CmpGte, 32)
MAKE_CMP_BROADCAST(CMPHS, U, CmpGte, 64)

MAKE_CMP_BROADCAST(CMPHI, U, CmpGt, 8)
MAKE_CMP_BROADCAST(CMPHI, U, CmpGt, 16)
MAKE_CMP_BROADCAST(CMPHI, U, CmpGt, 32)
MAKE_CMP_BROADCAST(CMPHI, U, CmpGt, 64)

#undef MAKE_CMP_BROADCAST

}  // namespace

DEF_ISEL(CMEQ_ASIMDSAME_ONLY_8B) = CMPEQ_8<VIi8v8, VIu8v8>;  // CMEQ  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(CMGT_ASIMDSAME_ONLY_8B) = CMPGT_8<VIi8v8, VIu8v8>;  // CMGT  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(CMGE_ASIMDSAME_ONLY_8B) = CMPGE_8<VIi8v8, VIu8v8>;  // CMGE  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(CMTST_ASIMDSAME_ONLY_8B) =
    CMPTST_8<VIu8v8, VIu8v8>;  // CMTST  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(CMHS_ASIMDSAME_ONLY_8B) = CMPHS_8<VIu8v8, VIu8v8>;  // CMHS  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>

DEF_ISEL(CMEQ_ASIMDSAME_ONLY_16B) =
    CMPEQ_8<VIi8v16, VIu8v16>;  // CMEQ  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(CMGT_ASIMDSAME_ONLY_16B) =
    CMPGT_8<VIi8v16, VIu8v16>;  // CMGT  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(CMGE_ASIMDSAME_ONLY_16B) =
    CMPGE_8<VIi8v16, VIu8v16>;  // CMGE  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(CMTST_ASIMDSAME_ONLY_16B) =
    CMPTST_8<VIu8v16, VIu8v16>;  // CMTST  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(CMHS_ASIMDSAME_ONLY_16B) =
    CMPHS_8<VIu8v16, VIu8v16>;  // CMHS  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>

DEF_ISEL(CMEQ_ASIMDSAME_ONLY_4H) =
    CMPEQ_16<VIi16v4, VIu16v4>;  // CMEQ  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(CMGT_ASIMDSAME_ONLY_4H) =
    CMPGT_16<VIi16v4, VIu16v4>;  // CMGT  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(CMGE_ASIMDSAME_ONLY_4H) =
    CMPGE_16<VIi16v4, VIu16v4>;  // CMGE  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(CMTST_ASIMDSAME_ONLY_4H) =
    CMPTST_16<VIu16v4, VIu16v4>;  // CMTST  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(CMHS_ASIMDSAME_ONLY_4H) =
    CMPHS_16<VIu16v4, VIu16v4>;  // CMHS  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>

DEF_ISEL(CMEQ_ASIMDSAME_ONLY_8H) =
    CMPEQ_16<VIi16v8, VIu16v8>;  // CMEQ  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(CMGT_ASIMDSAME_ONLY_8H) =
    CMPGT_16<VIi16v8, VIu16v8>;  // CMGT  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(CMGE_ASIMDSAME_ONLY_8H) =
    CMPGE_16<VIi16v8, VIu16v8>;  // CMGE  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(CMTST_ASIMDSAME_ONLY_8H) =
    CMPTST_16<VIu16v8, VIu16v8>;  // CMTST  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(CMHS_ASIMDSAME_ONLY_8H) =
    CMPHS_16<VIu16v8, VIu16v8>;  // CMHS  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>

DEF_ISEL(CMEQ_ASIMDSAME_ONLY_2S) =
    CMPEQ_32<VIi32v2, VIu32v2>;  // CMEQ  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(CMGT_ASIMDSAME_ONLY_2S) =
    CMPGT_32<VIi32v2, VIu32v2>;  // CMGT  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(CMGE_ASIMDSAME_ONLY_2S) =
    CMPGE_32<VIi32v2, VIu32v2>;  // CMGE  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(CMTST_ASIMDSAME_ONLY_2S) =
    CMPTST_32<VIu32v2, VIu32v2>;  // CMTST  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(CMHS_ASIMDSAME_ONLY_2S) =
    CMPHS_32<VIu32v2, VIu32v2>;  // CMHS  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>

DEF_ISEL(CMEQ_ASIMDSAME_ONLY_4S) =
    CMPEQ_32<VIi32v4, VIu32v4>;  // CMEQ  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(CMGT_ASIMDSAME_ONLY_4S) =
    CMPGT_32<VIi32v4, VIu32v4>;  // CMGT  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(CMGE_ASIMDSAME_ONLY_4S) =
    CMPGE_32<VIi32v4, VIu32v4>;  // CMGE  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(CMTST_ASIMDSAME_ONLY_4S) =
    CMPTST_32<VIu32v4, VIu32v4>;  // CMTST  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(CMHS_ASIMDSAME_ONLY_4S) =
    CMPHS_32<VIu32v4, VIu32v4>;  // CMHS  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>

DEF_ISEL(CMEQ_ASIMDSAME_ONLY_2D) =
    CMPEQ_64<VIi64v2, VIu64v2>;  // CMEQ  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(CMGT_ASIMDSAME_ONLY_2D) =
    CMPGT_64<VIi64v2, VIu64v2>;  // CMGT  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(CMGE_ASIMDSAME_ONLY_2D) =
    CMPGE_64<VIi64v2, VIu64v2>;  // CMGE  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(CMTST_ASIMDSAME_ONLY_2D) =
    CMPTST_64<VIu64v2, VIu64v2>;  // CMTST  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(CMHS_ASIMDSAME_ONLY_2D) =
    CMPHS_64<VIu64v2, VIu64v2>;  // CMHS  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>

DEF_ISEL(CMHI_ASIMDSAME_ONLY_8B) = CMPHI_8<VIu8v8, VIu8v8>;  // CMHI  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(CMHI_ASIMDSAME_ONLY_16B) =
    CMPHI_8<VIu8v16, VIu8v16>;  // CMHI  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(CMHI_ASIMDSAME_ONLY_4H) =
    CMPHI_16<VIu16v4, VIu16v4>;  // CMHI  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(CMHI_ASIMDSAME_ONLY_8H) =
    CMPHI_16<VIu16v8, VIu16v8>;  // CMHI  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(CMHI_ASIMDSAME_ONLY_2S) =
    CMPHI_32<VIu32v2, VIu32v2>;  // CMHI  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(CMHI_ASIMDSAME_ONLY_4S) =
    CMPHI_32<VIu32v4, VIu32v4>;  // CMHI  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(CMHI_ASIMDSAME_ONLY_2D) =
    CMPHI_64<VIu64v2, VIu64v2>;  // CMHI  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>

namespace {

#define MAKE_PAIRWAISE_BROADCAST(op, prefix, binop, size) \
  template <typename V> \
  DEF_SEM_T(op##_##size, V src1, V src2) { \
    auto vec1 = prefix##ReadVI##size(src1); \
    auto vec2 = prefix##ReadVI##size(src2); \
    V res = {}; \
    size_t max_i = GetVectorElemsNum(res); \
    size_t j = 0; \
    _Pragma("unroll") for (size_t i = 0; i < max_i; i += 2) { \
      res[j++] = \
          prefix##binop(prefix##ExtractVI##size(vec1, i), prefix##ExtractVI##size(vec1, i + 1)); \
    } \
    _Pragma("unroll") for (size_t i = 0; i < max_i; i += 2) { \
      res[j++] = \
          prefix##binop(prefix##ExtractVI##size(vec2, i), prefix##ExtractVI##size(vec2, i + 1)); \
    } \
    return res; \
  }

MAKE_PAIRWAISE_BROADCAST(ADDP, U, Add, 8)
MAKE_PAIRWAISE_BROADCAST(ADDP, U, Add, 16)
MAKE_PAIRWAISE_BROADCAST(ADDP, U, Add, 32)
MAKE_PAIRWAISE_BROADCAST(ADDP, U, Add, 64)

MAKE_PAIRWAISE_BROADCAST(UMAXP, U, Max, 8)
MAKE_PAIRWAISE_BROADCAST(UMAXP, U, Max, 16)
MAKE_PAIRWAISE_BROADCAST(UMAXP, U, Max, 32)

MAKE_PAIRWAISE_BROADCAST(SMAXP, S, Max, 8)
MAKE_PAIRWAISE_BROADCAST(SMAXP, S, Max, 16)
MAKE_PAIRWAISE_BROADCAST(SMAXP, S, Max, 32)

MAKE_PAIRWAISE_BROADCAST(UMINP, U, Min, 8)
MAKE_PAIRWAISE_BROADCAST(UMINP, U, Min, 16)
MAKE_PAIRWAISE_BROADCAST(UMINP, U, Min, 32)

MAKE_PAIRWAISE_BROADCAST(SMINP, S, Min, 8)
MAKE_PAIRWAISE_BROADCAST(SMINP, S, Min, 16)
MAKE_PAIRWAISE_BROADCAST(SMINP, S, Min, 32)

#undef MAKE_PAIRWAISE_BROADCAST

}  // namespace

DEF_ISEL(ADDP_ASIMDSAME_ONLY_8B) = ADDP_8<VIu8v8>;  // ADDP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(ADDP_ASIMDSAME_ONLY_16B) = ADDP_8<VIu8v16>;  // ADDP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(ADDP_ASIMDSAME_ONLY_4H) = ADDP_16<VIu16v4>;  // ADDP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(ADDP_ASIMDSAME_ONLY_8H) = ADDP_16<VIu16v8>;  // ADDP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(ADDP_ASIMDSAME_ONLY_2S) = ADDP_32<VIu32v2>;  // ADDP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(ADDP_ASIMDSAME_ONLY_4S) = ADDP_32<VIu32v4>;  // ADDP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(ADDP_ASIMDSAME_ONLY_2D) = ADDP_64<VIu64v2>;  // ADDP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>

DEF_ISEL(UMINP_ASIMDSAME_ONLY_8B) = UMINP_8<VIu8v8>;  // UMINP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(UMINP_ASIMDSAME_ONLY_16B) = UMINP_8<VIu8v16>;  // UMINP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(UMINP_ASIMDSAME_ONLY_4H) = UMINP_16<VIu16v4>;  // UMINP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(UMINP_ASIMDSAME_ONLY_8H) = UMINP_16<VIu16v8>;  // UMINP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(UMINP_ASIMDSAME_ONLY_2S) = UMINP_32<VIu32v2>;  // UMINP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(UMINP_ASIMDSAME_ONLY_4S) = UMINP_32<VIu32v4>;  // UMINP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>

DEF_ISEL(UMAXP_ASIMDSAME_ONLY_8B) = UMAXP_8<VIu8v8>;  // UMAXP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(UMAXP_ASIMDSAME_ONLY_16B) = UMAXP_8<VIu8v16>;  // UMAXP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(UMAXP_ASIMDSAME_ONLY_4H) = UMAXP_16<VIu16v4>;  // UMAXP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(UMAXP_ASIMDSAME_ONLY_8H) = UMAXP_16<VIu16v8>;  // UMAXP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(UMAXP_ASIMDSAME_ONLY_2S) = UMAXP_32<VIu32v2>;  // UMAXP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(UMAXP_ASIMDSAME_ONLY_4S) = UMAXP_32<VIu32v4>;  // UMAXP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>

DEF_ISEL(SMINP_ASIMDSAME_ONLY_8B) = SMINP_8<VIi8v8>;  // SMINP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(SMINP_ASIMDSAME_ONLY_16B) = SMINP_8<VIi8v16>;  // SMINP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(SMINP_ASIMDSAME_ONLY_4H) = SMINP_16<VIi16v4>;  // SMINP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(SMINP_ASIMDSAME_ONLY_8H) = SMINP_16<VIi16v8>;  // SMINP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(SMINP_ASIMDSAME_ONLY_2S) = SMINP_32<VIi32v2>;  // SMINP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(SMINP_ASIMDSAME_ONLY_4S) = SMINP_32<VIi32v4>;  // SMINP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>

DEF_ISEL(SMAXP_ASIMDSAME_ONLY_8B) = SMAXP_8<VIi8v8>;  // SMAXP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(SMAXP_ASIMDSAME_ONLY_16B) = SMAXP_8<VIi8v16>;  // SMAXP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(SMAXP_ASIMDSAME_ONLY_4H) = SMAXP_16<VIi16v4>;  // SMAXP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(SMAXP_ASIMDSAME_ONLY_8H) = SMAXP_16<VIi16v8>;  // SMAXP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(SMAXP_ASIMDSAME_ONLY_2S) = SMAXP_32<VIi32v2>;  // SMAXP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(SMAXP_ASIMDSAME_ONLY_4S) = SMAXP_32<VIi32v4>;  // SMAXP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>

namespace {

template <typename VI, typename B>
ALWAYS_INLINE static auto Reduce2(const VI &vec, B binop, size_t base = 0)
    -> decltype(binop(vec[0], vec[1])) {
  return binop(vec[base + 0], vec[base + 1]);
}

template <typename VI, typename B>
ALWAYS_INLINE static auto Reduce4(const VI &vec, B binop, size_t base = 0)
    -> decltype(binop(vec[0], vec[1])) {
  auto lo = Reduce2(vec, binop, base + 0);
  auto hi = Reduce2(vec, binop, base + 2);
  return binop(lo, hi);
}

template <typename VI, typename B>
ALWAYS_INLINE static auto Reduce8(const VI &vec, B binop, size_t base = 0)
    -> decltype(binop(vec[0], vec[1])) {
  auto lo = Reduce4(vec, binop, base + 0);
  auto hi = Reduce4(vec, binop, base + 4);
  return binop(lo, hi);
}

template <typename VI, typename B>
ALWAYS_INLINE static auto Reduce16(const VI &vec, B binop, size_t base = 0)
    -> decltype(binop(vec[0], vec[1])) {
  auto lo = Reduce8(vec, binop, base + 0);
  auto hi = Reduce8(vec, binop, base + 8);
  return binop(lo, hi);
}

template <typename VI, typename B>
ALWAYS_INLINE static auto Reduce(const VI &vec, B binop) -> decltype(Reduce2(vec, binop)) {
  switch (GetVectorElemsNum(vec)) {
    case 2: return Reduce2(vec, binop);
    case 4: return Reduce4(vec, binop);
    case 8: return Reduce8(vec, binop);
    case 16: return Reduce16(vec, binop);
    default: __builtin_unreachable();
  }
}

template <typename S>
DEF_SEM_T(ADDV_8_Reduce, S src) {
  auto vec = SReadVI8(src);
  return Unsigned(Reduce(vec, SAdd8));
}

template <typename S>
DEF_SEM_T(ADDV_16_Reduce, S src) {
  auto vec = SReadVI16(src);
  return Unsigned(Reduce(vec, SAdd16));
}

template <typename S>
DEF_SEM_T(ADDV_32_Reduce, S src) {
  auto vec = SReadVI32(src);
  return Unsigned(Reduce(vec, SAdd32));
}

template <typename S>
DEF_SEM_T(UMINV_8, S src) {
  auto vec = UReadVI8(src);
  auto val = std::numeric_limits<uint8_t>::max();
  _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(vec); ++i) {
    val = UMin(vec[i], val);
  }
  return val;
}

template <typename S>
DEF_SEM_T(UMINV_16, S src) {
  auto vec = UReadVI16(src);
  auto val = std::numeric_limits<uint16_t>::max();
  _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(vec); ++i) {
    val = UMin(vec[i], val);
  }
  return val;
}

template <typename S>
DEF_SEM_T(UMINV_32, S src) {
  auto vec = UReadVI32(src);
  auto val = std::numeric_limits<uint32_t>::max();
  _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(vec); ++i) {
    val = UMin(vec[i], val);
  }
  return val;
}

template <typename S>
DEF_SEM_T(SMINV_8, S src) {
  auto vec = SReadVI8(src);
  auto val = std::numeric_limits<int8_t>::max();
  _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(vec); ++i) {
    val = SMin(vec[i], val);
  }
  return val;
}

template <typename S>
DEF_SEM_T(SMINV_16, S src) {
  auto vec = SReadVI16(src);
  auto val = std::numeric_limits<int16_t>::max();
  _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(vec); ++i) {
    val = SMin(vec[i], val);
  }
  return val;
}

template <typename S>
DEF_SEM_T(SMINV_32, S src) {
  auto vec = SReadVI32(src);
  auto val = std::numeric_limits<int32_t>::max();
  _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(vec); ++i) {
    val = SMin(vec[i], val);
  }
  return val;
}

template <typename S>
DEF_SEM_T(UMAXV_8, S src) {
  auto vec = UReadVI8(src);
  auto val = std::numeric_limits<uint8_t>::min();
  _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(vec); ++i) {
    val = UMax(vec[i], val);
  }
  return val;
}

template <typename S>
DEF_SEM_T(UMAXV_16, S src) {
  auto vec = UReadVI16(src);
  auto val = std::numeric_limits<uint16_t>::min();
  _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(vec); ++i) {
    val = UMax(vec[i], val);
  }
  return val;
}

template <typename S>
DEF_SEM_T(UMAXV_32, S src) {
  auto vec = UReadVI32(src);
  auto val = std::numeric_limits<uint32_t>::min();
  _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(vec); ++i) {
    val = UMax(vec[i], val);
  }
  return val;
}

template <typename S>
DEF_SEM_T(SMAXV_8, S src) {
  auto vec = SReadVI8(src);
  auto val = std::numeric_limits<int8_t>::min();
  _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(vec); ++i) {
    val = SMax(vec[i], val);
  }
  return val;
}

template <typename S>
DEF_SEM_T(SMAXV_16, S src) {
  auto vec = SReadVI16(src);
  auto val = std::numeric_limits<int16_t>::min();
  _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(vec); ++i) {
    val = SMax(vec[i], val);
  }
  return val;
}

template <typename S>
DEF_SEM_T(SMAXV_32, S src) {
  auto vec = SReadVI32(src);
  auto val = std::numeric_limits<int32_t>::min();
  _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(vec); ++i) {
    val = SMax(vec[i], val);
  }
  return val;
}

}  // namespace

DEF_ISEL(ADDV_ASIMDALL_ONLY_8B) = ADDV_8_Reduce<VIi8v8>;  // ADDV  <V><d>, <Vn>.<T>
DEF_ISEL(ADDV_ASIMDALL_ONLY_16B) = ADDV_8_Reduce<VIi8v16>;  // ADDV  <V><d>, <Vn>.<T>
DEF_ISEL(ADDV_ASIMDALL_ONLY_4H) = ADDV_16_Reduce<VIi16v4>;  // ADDV  <V><d>, <Vn>.<T>
DEF_ISEL(ADDV_ASIMDALL_ONLY_8H) = ADDV_16_Reduce<VIi16v8>;  // ADDV  <V><d>, <Vn>.<T>
DEF_ISEL(ADDV_ASIMDALL_ONLY_4S) = ADDV_32_Reduce<VIi32v4>;  // ADDV  <V><d>, <Vn>.<T>

DEF_ISEL(UMINV_ASIMDALL_ONLY_8B) = UMINV_8<VIu8v8>;  // UMINV  <V><d>, <Vn>.<T>
DEF_ISEL(UMINV_ASIMDALL_ONLY_16B) = UMINV_8<VIu8v16>;  // UMINV  <V><d>, <Vn>.<T>
DEF_ISEL(UMINV_ASIMDALL_ONLY_4H) = UMINV_16<VIu16v4>;  // UMINV  <V><d>, <Vn>.<T>
DEF_ISEL(UMINV_ASIMDALL_ONLY_8H) = UMINV_16<VIu16v8>;  // UMINV  <V><d>, <Vn>.<T>
DEF_ISEL(UMINV_ASIMDALL_ONLY_4S) = UMINV_32<VIu32v4>;  // UMINV  <V><d>, <Vn>.<T>

DEF_ISEL(SMINV_ASIMDALL_ONLY_8B) = SMINV_8<VIi8v8>;  // SMINV  <V><d>, <Vn>.<T>
DEF_ISEL(SMINV_ASIMDALL_ONLY_16B) = SMINV_8<VIi8v16>;  // SMINV  <V><d>, <Vn>.<T>
DEF_ISEL(SMINV_ASIMDALL_ONLY_4H) = SMINV_16<VIi16v4>;  // SMINV  <V><d>, <Vn>.<T>
DEF_ISEL(SMINV_ASIMDALL_ONLY_8H) = SMINV_16<VIi16v8>;  // SMINV  <V><d>, <Vn>.<T>
DEF_ISEL(SMINV_ASIMDALL_ONLY_4S) = SMINV_32<VIi32v4>;  // SMINV  <V><d>, <Vn>.<T>

DEF_ISEL(UMAXV_ASIMDALL_ONLY_8B) = UMAXV_8<VIu8v8>;  // UMAXV  <V><d>, <Vn>.<T>
DEF_ISEL(UMAXV_ASIMDALL_ONLY_16B) = UMAXV_8<VIu8v16>;  // UMAXV  <V><d>, <Vn>.<T>
DEF_ISEL(UMAXV_ASIMDALL_ONLY_4H) = UMAXV_16<VIu16v4>;  // UMAXV  <V><d>, <Vn>.<T>
DEF_ISEL(UMAXV_ASIMDALL_ONLY_8H) = UMAXV_16<VIu16v8>;  // UMAXV  <V><d>, <Vn>.<T>
DEF_ISEL(UMAXV_ASIMDALL_ONLY_4S) = UMAXV_32<VIu32v4>;  // UMAXV  <V><d>, <Vn>.<T>

DEF_ISEL(SMAXV_ASIMDALL_ONLY_8B) = SMAXV_8<VIi8v8>;  // SMAXV  <V><d>, <Vn>.<T>
DEF_ISEL(SMAXV_ASIMDALL_ONLY_16B) = SMAXV_8<VIi8v16>;  // SMAXV  <V><d>, <Vn>.<T>
DEF_ISEL(SMAXV_ASIMDALL_ONLY_4H) = SMAXV_16<VIi16v4>;  // SMAXV  <V><d>, <Vn>.<T>
DEF_ISEL(SMAXV_ASIMDALL_ONLY_8H) = SMAXV_16<VIi16v8>;  // SMAXV  <V><d>, <Vn>.<T>
DEF_ISEL(SMAXV_ASIMDALL_ONLY_4S) = SMAXV_32<VIi32v4>;  // SMAXV  <V><d>, <Vn>.<T>

namespace {

// template <typename T, typename I>
// ALWAYS_INLINE static T FloatMin(T lhs, T rhs) {
//   if (__builtin_isunordered(lhs, rhs)) {
//     return NAN;
//   } else if (__builtin_isless(lhs, rhs)) {
//     return lhs;
//   } else {
//     return rhs;
//   }

//   //  if (lhs < rhs) {
//   //    return lhs;
//   //
//   //  } else if (lhs > rhs) {
//   //    return rhs;
//   //
//   //  // Use integer comparisons; we need to return the "most negative" value
//   //  // (e.g. in the case of +0 and -0).
//   //  } else {
//   //    auto a = reinterpret_cast<I &>(lhs);
//   //    auto b = reinterpret_cast<I &>(rhs);
//   //    auto res = SMin(a, b);
//   //    return reinterpret_cast<T &>(res);
//   //  }
// }

// template <typename T, typename I>
// ALWAYS_INLINE static T FloatMax(T lhs, T rhs) {
//   if (__builtin_isunordered(lhs, rhs)) {
//     return NAN;
//   } else if (__builtin_isgreater(lhs, rhs)) {
//     return lhs;
//   } else {
//     return rhs;
//   }
//   //
//   //  if (lhs < rhs) {
//   //    return rhs;
//   //
//   //  } else if (lhs > rhs) {
//   //    return lhs;
//   //
//   //  // Use integer comparisons; we need to return the "most negative" value
//   //  // (e.g. in the case of +0 and -0).
//   //  } else {
//   //    auto a = reinterpret_cast<I &>(lhs);
//   //    auto b = reinterpret_cast<I &>(rhs);
//   //    auto res = SMax(a, b);
//   //    return reinterpret_cast<T &>(res);
//   //  }
// }

// // NOTE(pag): These aren't quite right w.r.t. NaN propagation.
// DEF_SEM(FMINV_32_Reduce, VI128 dst, VI128 src) {
//   auto vec = FReadV32(src);
//   FWriteV32(dst, Reduce4(vec, FloatMin<float32_t, int32_t>));
// }

// DEF_SEM(FMAXV_32_Reduce, VI128 dst, VI128 src) {
//   auto vec = FReadV32(src);
//   FWriteV32(dst, Reduce4(vec, FloatMax<float32_t, int32_t>));
// }

}  // namespace

// DEF_ISEL(FMINV_ASIMDALL_ONLY_SD_4S) = FMINV_32_Reduce;  // FMINV  <V><d>, <Vn>.<T>
// DEF_ISEL(FMAXV_ASIMDALL_ONLY_SD_4S) = FMAXV_32_Reduce;  // FMAXV  <V><d>, <Vn>.<T>

// ADDP  <V><d>, <Vn>.<T>
namespace {
DEF_SEM_T(ADDP_SCALAR, VIu64v2 src) {
  auto src_v = UReadVI64(src);
  return src_v[0] + src_v[1];
}
}  // namespace

DEF_ISEL(ADDP_ASISDPAIR_ONLY) = ADDP_SCALAR;

namespace {

template <typename S>
DEF_SEM_T(NOT_8, S src) {
  auto vec = UReadVI8(src);
  auto res = UNotVI8(vec);
  return res;
}

}  // namespace

DEF_ISEL(NOT_ASIMDMISC_R_8B) = NOT_8<VIu8v8>;  // NOT  <Vd>.<T>, <Vn>.<T>
DEF_ISEL(NOT_ASIMDMISC_R_16B) = NOT_8<VIu8v16>;  // NOT  <Vd>.<T>, <Vn>.<T>

namespace {

template <typename T, size_t count>
DEF_SEM_T(EXT, T src1, T src2, I32 src3) {
  auto lsb = Read(src3);
  auto vn = UReadVI8(src1);
  auto vm = UReadVI8(src2);
  VIu8v16 res = {};
  _Pragma("unroll") for (size_t i = 0; i < count; i++) {
    size_t src_pos = i + lsb;
    if (src_pos < count) {
      res[i] = vn[src_pos];
    } else {
      res[i] = vm[src_pos - count];
    }
  }
  return res;
}

}  //  namespace

DEF_ISEL(EXT_ASIMDEXT_ONLY_8B) = EXT<VIu8v8, 8>;  // EXT  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>, #<index>
DEF_ISEL(EXT_ASIMDEXT_ONLY_16B) = EXT<VIu8v16, 16>;  // EXT  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>, #<index>


// TODO(pag):
// FMINV_ASIMDALL_ONLY_H
// FMAXV_ASIMDALL_ONLY_H
// FMINNMV_ASIMDALL_ONLY_H
// FMINNMV_ASIMDALL_ONLY_SD
// FMAXNMV_ASIMDALL_ONLY_H
// FMAXNMV_ASIMDALL_ONLY_SD

DEF_SEM_T(USHR_64B, VIu64v2 src, I64 shift) {
  auto src_v0 = UExtractVI64(UReadVI64(src), 0);
  auto sft = Read(shift);
  auto shifted = UShr64(src_v0, sft);
  VIu64v2 resv = {};
  resv[0] = shifted;
  resv[1] = 0;
  return resv;
}

DEF_ISEL(USHR_ASISDSHF_R) = USHR_64B;  // USHR  <V><d>, <V><n>, #<shift>

// USHR  <Vd>.<T>, <Vn>.<T>, #<shift>
namespace {
#define MAKE_USHR_VECTOR(esize) \
  template <typename S> \
  DEF_SEM_T(USHR_VECTOR_##esize, S src, I64 shift_val) { \
    auto src_v = UReadVI##esize(src); \
    auto sft_val = Read(shift_val); \
    S res = {}; \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(src_v); i++) { \
      res[i] = UShr##esize(src_v[i], sft_val); \
    } \
    return res; \
  }

MAKE_USHR_VECTOR(8);
MAKE_USHR_VECTOR(16);
MAKE_USHR_VECTOR(32);
MAKE_USHR_VECTOR(64);

#undef MAKE_USHR_VECTOR

}  // namespace

DEF_ISEL(USHR_ASIMDSHF_R_8B) = USHR_VECTOR_8<VIu8v8>;
DEF_ISEL(USHR_ASIMDSHF_R_16B) = USHR_VECTOR_8<VIu8v16>;
DEF_ISEL(USHR_ASIMDSHF_R_4H) = USHR_VECTOR_16<VIu16v4>;
DEF_ISEL(USHR_ASIMDSHF_R_8H) = USHR_VECTOR_16<VIu16v8>;
DEF_ISEL(USHR_ASIMDSHF_R_2S) = USHR_VECTOR_32<VIu32v2>;
DEF_ISEL(USHR_ASIMDSHF_R_4S) = USHR_VECTOR_32<VIu32v4>;
DEF_ISEL(USHR_ASIMDSHF_R_2D) = USHR_VECTOR_64<VIu64v2>;

// SRI  <Vd>.<T>, <Vn>.<T>, #<shift>
namespace {
#define MAKE_SRI_VECTOR(esize) \
  template <typename S> \
  DEF_SEM_T(SRI_VECTOR_##esize, S dst_src, S src, I64 shift_val) { \
    auto src_v = UReadVI##esize(src); \
    auto dst_v = UReadVI##esize(dst_src); \
    auto sft_val = Read(shift_val); \
    uint##esize##_t mask; \
    if (sft_val >= esize) { \
      mask = ~uint##esize##_t(0); \
    } else { \
      mask = static_cast<uint##esize##_t>(~uint##esize##_t(0) << (esize - sft_val)); \
    } \
    S res = {}; \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(src_v); i++) { \
      uint##esize##_t shifted = \
          sft_val >= esize ? uint##esize##_t(0) : UShr##esize(src_v[i], sft_val); \
      res[i] = (dst_v[i] & mask) | shifted; \
    } \
    return res; \
  }

MAKE_SRI_VECTOR(8);
MAKE_SRI_VECTOR(16);
MAKE_SRI_VECTOR(32);
MAKE_SRI_VECTOR(64);

#undef MAKE_SRI_VECTOR

}  // namespace

DEF_ISEL(SRI_ASIMDSHF_R_8B) = SRI_VECTOR_8<VIu8v8>;
DEF_ISEL(SRI_ASIMDSHF_R_16B) = SRI_VECTOR_8<VIu8v16>;
DEF_ISEL(SRI_ASIMDSHF_R_4H) = SRI_VECTOR_16<VIu16v4>;
DEF_ISEL(SRI_ASIMDSHF_R_8H) = SRI_VECTOR_16<VIu16v8>;
DEF_ISEL(SRI_ASIMDSHF_R_2S) = SRI_VECTOR_32<VIu32v2>;
DEF_ISEL(SRI_ASIMDSHF_R_4S) = SRI_VECTOR_32<VIu32v4>;
DEF_ISEL(SRI_ASIMDSHF_R_2D) = SRI_VECTOR_64<VIu64v2>;

// SSHR  <V><d>, <V><n>, #<shift>
namespace {
DEF_SEM_T(SSHR_64B, VIi64v2 src, I64 shift) {
  auto src_v0 = SExtractVI64(SReadVI64(src), 0);
  auto sft = Read(shift);
  auto shifted = SShr64(src_v0, sft);
  VIi64v2 resv = {};
  resv[0] = shifted;
  resv[1] = 0;
  return resv;
}
}  // namespace

DEF_ISEL(SSHR_ASISDSHF_R) = SSHR_64B;  // SSHR  <V><d>, <V><n>, #<shift>

// SSHR  <Vd>.<T>, <Vn>.<T>, #<shift>
namespace {
#define MAKE_SSHR_VECTOR(esize) \
  template <typename S> \
  DEF_SEM_T(SSHR_VECTOR_##esize, S src, I64 shift_val) { \
    auto src_v = SReadVI##esize(src); \
    auto sft_val = Read(shift_val); \
    S res = {}; \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(src_v); i++) { \
      res[i] = SShr##esize(src_v[i], sft_val); \
    } \
    return res; \
  }

MAKE_SSHR_VECTOR(8);
MAKE_SSHR_VECTOR(16);
MAKE_SSHR_VECTOR(32);
MAKE_SSHR_VECTOR(64);

#undef MAKE_SSHR_VECTOR

}  // namespace

DEF_ISEL(SSHR_ASIMDSHF_R_8B) = SSHR_VECTOR_8<VIi8v8>;
DEF_ISEL(SSHR_ASIMDSHF_R_16B) = SSHR_VECTOR_8<VIi8v16>;
DEF_ISEL(SSHR_ASIMDSHF_R_4H) = SSHR_VECTOR_16<VIi16v4>;
DEF_ISEL(SSHR_ASIMDSHF_R_8H) = SSHR_VECTOR_16<VIi16v8>;
DEF_ISEL(SSHR_ASIMDSHF_R_2S) = SSHR_VECTOR_32<VIi32v2>;
DEF_ISEL(SSHR_ASIMDSHF_R_4S) = SSHR_VECTOR_32<VIi32v4>;
DEF_ISEL(SSHR_ASIMDSHF_R_2D) = SSHR_VECTOR_64<VIi64v2>;

// USHL  <V><d>, <V><n>, <V><m>
namespace {
DEF_SEM_T(USHL_64B, VIu64v2 src, VIi64v2 shift_src) {
  auto src_v0 = UExtractVI64(UReadVI64(src), 0);
  auto shift_v0 = SExtractVI64(SReadVI64(shift_src), 0);
  int64_t shift_val = shift_v0;
  uint64_t shifted;
  if (shift_val >= 0) {
    shifted = UShl64(src_v0, static_cast<uint64_t>(shift_val));
  } else {
    shifted = UShr64(src_v0, static_cast<uint64_t>(-shift_val));
  }
  VIu64v2 resv = {};
  resv[0] = shifted;
  resv[1] = 0;
  return resv;
}
}  // namespace

DEF_ISEL(USHL_ASISDSAME_ONLY) = USHL_64B;  // USHL  <V><d>, <V><n>, <V><m>

// USHL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
namespace {
#define MAKE_USHL_VECTOR(esize) \
  template <typename S, typename ShiftS> \
  DEF_SEM_T(USHL_VECTOR_##esize, S src, ShiftS shift_src) { \
    auto src_v = UReadVI##esize(src); \
    auto shift_v = SReadVI##esize(shift_src); \
    S res = {}; \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(src_v); i++) { \
      int##esize##_t shift_val = shift_v[i]; \
      if (shift_val >= 0) { \
        res[i] = UShl##esize(src_v[i], static_cast<uint##esize##_t>(shift_val)); \
      } else { \
        res[i] = UShr##esize(src_v[i], static_cast<uint##esize##_t>(-shift_val)); \
      } \
    } \
    return res; \
  }

MAKE_USHL_VECTOR(8);
MAKE_USHL_VECTOR(16);
MAKE_USHL_VECTOR(32);
MAKE_USHL_VECTOR(64);

#undef MAKE_USHL_VECTOR

}  // namespace

DEF_ISEL(USHL_ASIMDSAME_ONLY_8B) = USHL_VECTOR_8<VIu8v8, VIi8v8>;
DEF_ISEL(USHL_ASIMDSAME_ONLY_16B) = USHL_VECTOR_8<VIu8v16, VIi8v16>;
DEF_ISEL(USHL_ASIMDSAME_ONLY_4H) = USHL_VECTOR_16<VIu16v4, VIi16v4>;
DEF_ISEL(USHL_ASIMDSAME_ONLY_8H) = USHL_VECTOR_16<VIu16v8, VIi16v8>;
DEF_ISEL(USHL_ASIMDSAME_ONLY_2S) = USHL_VECTOR_32<VIu32v2, VIi32v2>;
DEF_ISEL(USHL_ASIMDSAME_ONLY_4S) = USHL_VECTOR_32<VIu32v4, VIi32v4>;
DEF_ISEL(USHL_ASIMDSAME_ONLY_2D) = USHL_VECTOR_64<VIu64v2, VIi64v2>;

// FMLA  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
// FMLA_ASIMDSAME_ONLY
namespace {

#define MAKE_FTWICEOP_ASIMDSAME_ONLY(prefix, elem_size, op1, op2) \
  template <typename V> \
  DEF_SEM_T_STATE(F##prefix##_V##elem_size, V dst_src, V src1, V src2) { \
    /* it might good to use F##binop##V##elem_size (e.g. FAddV32)*/ \
    auto dst_src_v = FReadVI##elem_size(dst_src); \
    auto srcv1 = FReadVI##elem_size(src1); \
    auto srcv2 = FReadVI##elem_size(src2); \
    V res = {}; \
    /* res = Vn op1 Vm */ \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(srcv1); i++) { \
      res[i] = \
          F##op1##elem_size(FExtractVI##elem_size(srcv1, i), FExtractVI##elem_size(srcv2, i)); \
    } \
    /* res = res op2 Vd */ \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(dst_src_v); i++) { \
      res[i] = \
          F##op2##elem_size(FExtractVI##elem_size(dst_src_v, i), FExtractVI##elem_size(res, i)); \
    } \
    return res; \
  }

// no support of float16
MAKE_FTWICEOP_ASIMDSAME_ONLY(MLA, 32, Mul, Add);
MAKE_FTWICEOP_ASIMDSAME_ONLY(MLA, 64, Mul, Add);

#undef MAKE_FTWICEOP_ASIMDSAME_ONLY

#define MAKE_FTWICEOP_ASIMDSAME_ONLY_FPSRSTATUS(prefix, elem_size, op1, op2) \
  template <typename V> \
  DEF_SEM_T_STATE(F##prefix##_V##elem_size##_FPSRStatus, V dst_src, V src1, V src2) { \
    /* it might good to use F##binop##V##elem_size (e.g. FAddV32)*/ \
    auto dst_src_v = FReadVI##elem_size(dst_src); \
    auto srcv1 = FReadVI##elem_size(src1); \
    auto srcv2 = FReadVI##elem_size(src2); \
    V res = {}; \
    /* res = Vn op1 Vm */ \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(srcv1); i++) { \
      res[i] = CheckedFloatBinOp(state, F##op1##elem_size, FExtractVI##elem_size(srcv1, i), \
                                 FExtractVI##elem_size(srcv2, i)); \
    } \
    /* res = res op2 Vd */ \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(dst_src_v); i++) { \
      res[i] = CheckedFloatBinOp(state, F##op2##elem_size, FExtractVI##elem_size(dst_src_v, i), \
                                 FExtractVI##elem_size(res, i)); \
    } \
    return res; \
  }

// no support of float16
MAKE_FTWICEOP_ASIMDSAME_ONLY_FPSRSTATUS(MLA, 32, Mul, Add);
MAKE_FTWICEOP_ASIMDSAME_ONLY_FPSRSTATUS(MLA, 64, Mul, Add);

#undef MAKE_FTWICEOP_ASIMDSAME_ONLY_FPSRSTATUS

}  // namespace

// no support of float16
DEF_ISEL(FMLA_ASIMDSAME_ONLY_2S) = FMLA_V32<VIf32v2>;  // FMLA  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(FMLA_ASIMDSAME_ONLY_4S) = FMLA_V32<VIf32v4>;  // FMLA  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(FMLA_ASIMDSAME_ONLY_2D) = FMLA_V64<VIf64v2>;  // FMLA  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
// FPSR
DEF_ISEL(FMLA_ASIMDSAME_ONLY_2S_FPSRSTATUS) =
    FMLA_V32_FPSRStatus<VIf32v2>;  // FMLA  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(FMLA_ASIMDSAME_ONLY_4S_FPSRSTATUS) =
    FMLA_V32_FPSRStatus<VIf32v4>;  // FMLA  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(FMLA_ASIMDSAME_ONLY_2D_FPSRSTATUS) =
    FMLA_V64_FPSRStatus<VIf64v2>;  // FMLA  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>

// FMLA  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
// FMLA_ASIMDELEM_R_SD
namespace {

#define MAKE_FTWICEOP_ASIMDELEM_R_SD(prefix, elem_size, op1, op2) \
  template <typename V> \
  DEF_SEM_T_STATE(F##prefix##_ELEM_V##elem_size, V dst_src, V src1, V src2, I64 index) { \
    /* it might good to use F##binop##V##elem_size (e.g. FAddV32)*/ \
    auto dst_src_v = FReadVI##elem_size(dst_src); \
    auto srcv1 = FReadVI##elem_size(src1); \
    auto srcv2 = FReadVI##elem_size(src2); \
    auto id = Read(index); \
    V res = {}; \
    /* res = Vn op1 Vm */ \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(srcv1); i++) { \
      res[i] = \
          F##op1##elem_size(FExtractVI##elem_size(srcv1, i), FExtractVI##elem_size(srcv2, id)); \
    } \
    /* res = res op2 Vd */ \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(dst_src_v); i++) { \
      res[i] = \
          F##op2##elem_size(FExtractVI##elem_size(dst_src_v, i), FExtractVI##elem_size(res, i)); \
    } \
    return res; \
  }

MAKE_FTWICEOP_ASIMDELEM_R_SD(MLA, 32, Mul, Add);
MAKE_FTWICEOP_ASIMDELEM_R_SD(MLA, 64, Mul, Add);

#undef MAKE_FTWICEOP_ASIMDELEM_R_SD

#define MAKE_FTWICEOP_ASIMDELEM_R_SD_FPSRSTATUS(prefix, elem_size, op1, op2) \
  template <typename V> \
  DEF_SEM_T_STATE(F##prefix##_ELEM_V##elem_size##_FPSRStatus, V dst_src, V src1, V src2, \
                  I64 index) { \
    /* it might good to use F##binop##V##elem_size (e.g. FAddV32)*/ \
    auto dst_src_v = FReadVI##elem_size(dst_src); \
    auto srcv1 = FReadVI##elem_size(src1); \
    auto srcv2 = FReadVI##elem_size(src2); \
    auto id = Read(index); \
    V res = {}; \
    /* res = Vn op1 Vm */ \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(srcv1); i++) { \
      res[i] = CheckedFloatBinOp(state, F##op1##elem_size, FExtractVI##elem_size(srcv1, i), \
                                 FExtractVI##elem_size(srcv2, id)); \
    } \
    /* res = res op2 Vd */ \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(dst_src_v); i++) { \
      res[i] = CheckedFloatBinOp(state, F##op2##elem_size, FExtractVI##elem_size(dst_src_v, i), \
                                 FExtractVI##elem_size(res, i)); \
    } \
    return res; \
  }

MAKE_FTWICEOP_ASIMDELEM_R_SD_FPSRSTATUS(MLA, 32, Mul, Add);
MAKE_FTWICEOP_ASIMDELEM_R_SD_FPSRSTATUS(MLA, 64, Mul, Add);

#undef MAKE_FTWICEOP_ASIMDELEM_R_SD_FPSRSTATUS

}  // namespace

DEF_ISEL(FMLA_ASIMDELEM_R_SD_2S) =
    FMLA_ELEM_V32<VIf32v2>;  // FMLA  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
DEF_ISEL(FMLA_ASIMDELEM_R_SD_4S) =
    FMLA_ELEM_V32<VIf32v4>;  // FMLA  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
DEF_ISEL(FMLA_ASIMDELEM_R_SD_2D) =
    FMLA_ELEM_V64<VIf64v2>;  // FMLA  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
// FPSR
DEF_ISEL(FMLA_ASIMDELEM_R_SD_2S_FPSRSTATUS) =
    FMLA_ELEM_V32_FPSRStatus<VIf32v2>;  // FMLA  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
DEF_ISEL(FMLA_ASIMDELEM_R_SD_4S_FPSRSTATUS) =
    FMLA_ELEM_V32_FPSRStatus<VIf32v4>;  // FMLA  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
DEF_ISEL(FMLA_ASIMDELEM_R_SD_2D_FPSRSTATUS) =
    FMLA_ELEM_V64_FPSRStatus<VIf64v2>;  // FMLA  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]

// FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
// FMUL_ASIMDSAME_ONLY
namespace {

#define MAKE_FONCEOP_ASIMDSAME_ONLY(prefix, elem_size, op) \
  template <typename V> \
  DEF_SEM_T_STATE(F##prefix##_V##elem_size, V src1, V src2) { \
    /* it might be good to use F##binop##V##elem_size (e.g. FAddV32)*/ \
    auto srcv1 = FReadVI##elem_size(src1); \
    auto srcv2 = FReadVI##elem_size(src2); \
    V res = {}; \
    /* res = Vn op Vm */ \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(srcv1); i++) { \
      res[i] = F##op##elem_size(FExtractVI##elem_size(srcv1, i), FExtractVI##elem_size(srcv2, i)); \
    } \
    return res; \
  }  // namespace

// no support of float16
MAKE_FONCEOP_ASIMDSAME_ONLY(MUL, 32, Mul);
MAKE_FONCEOP_ASIMDSAME_ONLY(MUL, 64, Mul);

MAKE_FONCEOP_ASIMDSAME_ONLY(ADD, 32, Add);
MAKE_FONCEOP_ASIMDSAME_ONLY(ADD, 64, Add);

#undef MAKE_FONCEOP_ASIMDSAME_ONLY

#define MAKE_FONCEOP_ASIMDSAME_ONLY_FPSRSTATUS(prefix, elem_size, op) \
  template <typename V> \
  DEF_SEM_T_STATE(F##prefix##_V##elem_size##_FPSRStatus, V src1, V src2) { \
    /* it might be good to use F##binop##V##elem_size (e.g. FAddV32)*/ \
    auto srcv1 = FReadVI##elem_size(src1); \
    auto srcv2 = FReadVI##elem_size(src2); \
    V res = {}; \
    /* res = Vn op Vm */ \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(srcv1); i++) { \
      res[i] = CheckedFloatBinOp(state, F##op##elem_size, FExtractVI##elem_size(srcv1, i), \
                                 FExtractVI##elem_size(srcv2, i)); \
    } \
    return res; \
  }  // namespace

// no support of float16
MAKE_FONCEOP_ASIMDSAME_ONLY_FPSRSTATUS(MUL, 32, Mul);
MAKE_FONCEOP_ASIMDSAME_ONLY_FPSRSTATUS(MUL, 64, Mul);

MAKE_FONCEOP_ASIMDSAME_ONLY_FPSRSTATUS(ADD, 32, Add);
MAKE_FONCEOP_ASIMDSAME_ONLY_FPSRSTATUS(ADD, 64, Add);

#undef MAKE_FONCEOP_ASIMDSAME_ONLY_FPSRSTATUS

}  // namespace

// no support of float16
DEF_ISEL(FMUL_ASIMDSAME_ONLY_2S) = FMUL_V32<VIf32v2>;  // FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(FMUL_ASIMDSAME_ONLY_4S) = FMUL_V32<VIf32v4>;  // FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(FMUL_ASIMDSAME_ONLY_2D) = FMUL_V64<VIf64v2>;  // FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>

DEF_ISEL(FADD_ASIMDSAME_ONLY_2S) = FADD_V32<VIf32v2>;  // FADD  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(FADD_ASIMDSAME_ONLY_4S) = FADD_V32<VIf32v4>;  // FADD  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(FADD_ASIMDSAME_ONLY_2D) = FADD_V64<VIf64v2>;  // FADD  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
// FPSR
DEF_ISEL(FMUL_ASIMDSAME_ONLY_2S_FPSRSTATUS) =
    FMUL_V32_FPSRStatus<VIf32v2>;  // FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(FMUL_ASIMDSAME_ONLY_4S_FPSRSTATUS) =
    FMUL_V32_FPSRStatus<VIf32v4>;  // FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(FMUL_ASIMDSAME_ONLY_2D_FPSRSTATUS) =
    FMUL_V64_FPSRStatus<VIf64v2>;  // FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>

DEF_ISEL(FADD_ASIMDSAME_ONLY_2S_FPSRSTATUS) =
    FADD_V32_FPSRStatus<VIf32v2>;  // FADD  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(FADD_ASIMDSAME_ONLY_4S_FPSRSTATUS) =
    FADD_V32_FPSRStatus<VIf32v4>;  // FADD  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(FADD_ASIMDSAME_ONLY_2D_FPSRSTATUS) =
    FADD_V64_FPSRStatus<VIf64v2>;  // FADD  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>

// FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
namespace {
#define MAKE_FONCEOP_ASIMD_INDEX(prefix, elem_size, op) \
  template <typename V> \
  DEF_SEM_T_STATE(F##prefix##ID_V##elem_size, V src1, V src2, I32 imm) { \
    auto index = Read(imm); \
    auto srcv1 = FReadVI##elem_size(src1); \
    auto srcv2 = FReadVI##elem_size(src2); \
    V res = {}; \
    auto v2_val = FExtractVI##elem_size(srcv2, index); \
    /* res = Vn + Vm[<index>] */ \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(srcv1); i++) { \
      res[i] = F##op##elem_size(FExtractVI##elem_size(srcv1, i), v2_val); \
    } \
    return res; \
  }  // namespace

// no support of float16
MAKE_FONCEOP_ASIMD_INDEX(MUL, 32, Mul);
MAKE_FONCEOP_ASIMD_INDEX(MUL, 64, Mul);

#undef MAKE_FONCEOP_ASIMD_INDEX

#define MAKE_FONCEOP_ASIMD_INDEX_FPSRSTATUS(prefix, elem_size, op) \
  template <typename V> \
  DEF_SEM_T_STATE(F##prefix##ID_V##elem_size##_FPSRStatus, V src1, V src2, I32 imm) { \
    auto index = Read(imm); \
    auto srcv1 = FReadVI##elem_size(src1); \
    auto srcv2 = FReadVI##elem_size(src2); \
    V res = {}; \
    auto v2_val = FExtractVI##elem_size(srcv2, index); \
    /* res = Vn + Vm[<index>] */ \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(srcv1); i++) { \
      res[i] = \
          CheckedFloatBinOp(state, F##op##elem_size, FExtractVI##elem_size(srcv1, i), v2_val); \
    } \
    return res; \
  }  // namespace

// no support of float16
MAKE_FONCEOP_ASIMD_INDEX_FPSRSTATUS(MUL, 32, Mul);
MAKE_FONCEOP_ASIMD_INDEX_FPSRSTATUS(MUL, 64, Mul);

#undef MAKE_FONCEOP_ASIMD_INDEX_FPSRSTATUS

}  // namespace

DEF_ISEL(FMUL_ASIMDELEM_R_SD_2S) =
    FMULID_V32<VIf32v2>;  // FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
DEF_ISEL(FMUL_ASIMDELEM_R_SD_4S) =
    FMULID_V32<VIf32v4>;  // FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
DEF_ISEL(FMUL_ASIMDELEM_R_SD_1D) =
    FMULID_V64<VIf64v1>;  // FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
DEF_ISEL(FMUL_ASIMDELEM_R_SD_2D) =
    FMULID_V64<VIf64v2>;  // FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
// FPSR
DEF_ISEL(FMUL_ASIMDELEM_R_SD_2S_FPSRSTATUS) =
    FMULID_V32_FPSRStatus<VIf32v2>;  // FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
DEF_ISEL(FMUL_ASIMDELEM_R_SD_4S_FPSRSTATUS) =
    FMULID_V32_FPSRStatus<VIf32v4>;  // FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
DEF_ISEL(FMUL_ASIMDELEM_R_SD_1D_FPSRSTATUS) =
    FMULID_V64_FPSRStatus<VIf64v1>;  // FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
DEF_ISEL(FMUL_ASIMDELEM_R_SD_2D_FPSRSTATUS) =
    FMULID_V64_FPSRStatus<VIf64v2>;  // FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]

// SHL  <V><d>, <V><n>, #<shift>
namespace {
DEF_SEM_U64(SHL_SCALAR, VIu64v1 src, I64 shift_val) {
  return UReadVI64(src)[0] << Read(shift_val);
}
}  // namespace

DEF_ISEL(SHL_ASISDSHF_R) = SHL_SCALAR;

// SHL  <Vd>.<T>, <Vn>.<T>, #<shift>
namespace {
#define MAKE_SHL_VECTOR(esize) \
  template <typename S> \
  DEF_SEM_T(SHL_VECTOR_##esize, S src, I64 shift_val) { \
    auto src_v = UReadVI##esize(src); \
    auto sft_val = Read(shift_val); \
    S res = {}; \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(src_v); i++) { \
      res[i] = src_v[i] << sft_val; \
    } \
    return res; \
  }

MAKE_SHL_VECTOR(8);
MAKE_SHL_VECTOR(16);
MAKE_SHL_VECTOR(32);
MAKE_SHL_VECTOR(64);

#undef MAKE_SHL_VECTOR

}  // namespace

DEF_ISEL(SHL_ASIMDSHF_R_8B) = SHL_VECTOR_8<VIu8v8>;
DEF_ISEL(SHL_ASIMDSHF_R_16B) = SHL_VECTOR_8<VIu8v16>;
DEF_ISEL(SHL_ASIMDSHF_R_4H) = SHL_VECTOR_16<VIu16v4>;
DEF_ISEL(SHL_ASIMDSHF_R_8H) = SHL_VECTOR_16<VIu16v8>;
DEF_ISEL(SHL_ASIMDSHF_R_2S) = SHL_VECTOR_32<VIu32v2>;
DEF_ISEL(SHL_ASIMDSHF_R_4S) = SHL_VECTOR_32<VIu32v4>;
DEF_ISEL(SHL_ASIMDSHF_R_2D) = SHL_VECTOR_64<VIu64v2>;

// USHLL{2}  <Vd>.<Ta>, <Vn>.<Tb>, #<shift>
namespace {
#define MAKE_USHLL(s_elem_size, d_elem_type) \
  template <typename D, typename S> \
  DEF_SEM_T(USHLL_##s_elem_size, S src, I64 shift_imm) { \
    auto srcv = UReadVI##s_elem_size(src); \
    D res{}; \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(srcv); i++) { \
      res[i] = (d_elem_type(srcv[i])) << Read(shift_imm); \
    } \
    return res; \
  } \
\
  template <typename D, typename S> \
  DEF_SEM_T(USHLL2_##s_elem_size, S src, I64 shift_imm) { \
    auto srcv = UReadVI##s_elem_size(src); \
    D res{}; \
    _Pragma("unroll") for (size_t i = GetVectorElemsNum(srcv) / 2; i < GetVectorElemsNum(srcv); \
                           i++) { \
      res[i - GetVectorElemsNum(srcv) / 2] = (d_elem_type(srcv[i])) << Read(shift_imm); \
    } \
    return res; \
  }

MAKE_USHLL(8, uint16_t);
MAKE_USHLL(16, uint32_t);
MAKE_USHLL(32, uint64_t);

#undef MAKE_USHLL

}  // namespace

DEF_ISEL(USHLL_ASIMDSHF_L_8H8B) = USHLL_8<VIu16v8, VIu8v8>;
DEF_ISEL(USHLL_ASIMDSHF_L_4S4H) = USHLL_16<VIu32v4, VIu16v4>;
DEF_ISEL(USHLL_ASIMDSHF_L_2D2S) = USHLL_32<VIu64v2, VIu32v2>;

DEF_ISEL(USHLL_ASIMDSHF_L_8H16B) = USHLL2_8<VIu16v8, VIu8v16>;
DEF_ISEL(USHLL_ASIMDSHF_L_4S8H) = USHLL2_16<VIu32v4, VIu16v8>;
DEF_ISEL(USHLL_ASIMDSHF_L_2D4S) = USHLL2_32<VIu64v2, VIu32v4>;

// SSHLL{2}  <Vd>.<Ta>, <Vn>.<Tb>, #<shift>
namespace {
#define MAKE_SSHLL(s_elem_size, d_elem_type) \
  template <typename D, typename S> \
  DEF_SEM_T(SSHLL_##s_elem_size, S src, I64 shift_imm) { \
    auto srcv = SReadVI##s_elem_size(src); \
    D res{}; \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(srcv); i++) { \
      res[i] = (d_elem_type(srcv[i])) << Read(shift_imm); \
    } \
    return res; \
  } \
\
  template <typename D, typename S> \
  DEF_SEM_T(SSHLL2_##s_elem_size, S src, I64 shift_imm) { \
    auto srcv = SReadVI##s_elem_size(src); \
    D res{}; \
    _Pragma("unroll") for (size_t i = GetVectorElemsNum(srcv) / 2; i < GetVectorElemsNum(srcv); \
                           i++) { \
      res[i - GetVectorElemsNum(srcv) / 2] = (d_elem_type(srcv[i])) << Read(shift_imm); \
    } \
    return res; \
  }

MAKE_SSHLL(8, int16_t);
MAKE_SSHLL(16, int32_t);
MAKE_SSHLL(32, int64_t);

#undef MAKE_SSHLL

}  // namespace

DEF_ISEL(SSHLL_ASIMDSHF_L_8H8B) = SSHLL_8<VIi16v8, VIi8v8>;
DEF_ISEL(SSHLL_ASIMDSHF_L_4S4H) = SSHLL_16<VIi32v4, VIi16v4>;
DEF_ISEL(SSHLL_ASIMDSHF_L_2D2S) = SSHLL_32<VIi64v2, VIi32v2>;

DEF_ISEL(SSHLL_ASIMDSHF_L_8H16B) = SSHLL2_8<VIi16v8, VIi8v16>;
DEF_ISEL(SSHLL_ASIMDSHF_L_4S8H) = SSHLL2_16<VIi32v4, VIi16v8>;
DEF_ISEL(SSHLL_ASIMDSHF_L_2D4S) = SSHLL2_32<VIi64v2, VIi32v4>;

// SHLL{2}  <Vd>.<Ta>, <Vn>.<Tb>, #<shift>
namespace {
#define MAKE_SHLL(s_elem_size, d_elem_type) \
  template <typename D, typename S> \
  DEF_SEM_T(SHLL_##s_elem_size, S src, I64 shift_imm) { \
    auto srcv = UReadVI##s_elem_size(src); \
    D res{}; \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(srcv); i++) { \
      res[i] = (d_elem_type(srcv[i])) << Read(shift_imm); \
    } \
    return res; \
  } \
\
  template <typename D, typename S> \
  DEF_SEM_T(SHLL2_##s_elem_size, S src, I64 shift_imm) { \
    auto srcv = UReadVI##s_elem_size(src); \
    D res{}; \
    _Pragma("unroll") for (size_t i = GetVectorElemsNum(srcv) / 2; i < GetVectorElemsNum(srcv); \
                           i++) { \
      res[i - GetVectorElemsNum(srcv) / 2] = (d_elem_type(srcv[i])) << Read(shift_imm); \
    } \
    return res; \
  }

MAKE_SHLL(8, uint16_t);
MAKE_SHLL(16, uint32_t);
MAKE_SHLL(32, uint64_t);

#undef MAKE_SHLL

}  // namespace

DEF_ISEL(SHLL_ASIMDMISC_S_8H8B) = SHLL_8<VIu16v8, VIu8v8>;
DEF_ISEL(SHLL_ASIMDMISC_S_4S4H) = SHLL_16<VIu32v4, VIu16v4>;
DEF_ISEL(SHLL_ASIMDMISC_S_2D2S) = SHLL_32<VIu64v2, VIu32v2>;

DEF_ISEL(SHLL_ASIMDMISC_S_8H16B) = SHLL2_8<VIu16v8, VIu8v16>;
DEF_ISEL(SHLL_ASIMDMISC_S_4S8H) = SHLL2_16<VIu32v4, VIu16v8>;
DEF_ISEL(SHLL_ASIMDMISC_S_2D4S) = SHLL2_32<VIu64v2, VIu32v4>;

// XTN{2}  <Vd>.<Tb>, <Vn>.<Ta>
namespace {
#define MAKE_XTN(s_esize, d_esize) \
  template <typename D, typename S> \
  DEF_SEM_T(XTN_##s_esize, D dst, S src) { \
    auto src_v = UReadVI##s_esize(src); \
    D res = {}; \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(src_v); i++) { \
      res[i] = (uint##d_esize##_t) src_v[i]; \
    } \
    return res; \
  } \
  template <typename D, typename S> \
  DEF_SEM_T(XTN2_##s_esize, D dst, S src) { \
    auto src_v = UReadVI##s_esize(src); \
    D res = UReadVI##d_esize(dst); \
    size_t srcv_enum = GetVectorElemsNum(src_v); \
    _Pragma("unroll") for (size_t i = 0; i < srcv_enum; i++) { \
      res[i + srcv_enum] = (uint##d_esize##_t) src_v[i]; \
    } \
    return res; \
  }

MAKE_XTN(16, 8);
MAKE_XTN(32, 16);
MAKE_XTN(64, 32);

#undef MAKE_XTN

}  // namespace

DEF_ISEL(XTN_ASIMDMISC_N_8B8H) = XTN_16<VIu8v8, VIu16v8>;
DEF_ISEL(XTN_ASIMDMISC_N_4H4S) = XTN_32<VIu16v4, VIu32v4>;
DEF_ISEL(XTN_ASIMDMISC_N_2S2D) = XTN_64<VIu32v2, VIu64v2>;

DEF_ISEL(XTN_ASIMDMISC_N_16B8H) = XTN2_16<VIu8v16, VIu16v8>;
DEF_ISEL(XTN_ASIMDMISC_N_8H4S) = XTN2_32<VIu16v8, VIu32v4>;
DEF_ISEL(XTN_ASIMDMISC_N_4S2D) = XTN2_64<VIu32v4, VIu64v2>;

// UADDL{2}  <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
namespace {
#define MAKE_UADDL(s_esize, d_esize) \
  template <typename D, typename S> \
  DEF_SEM_T(UADDL_##s_esize, S srcn, S srcm) { \
    auto srcn_v = UReadVI##s_esize(srcn); \
    auto srcm_v = UReadVI##s_esize(srcm); \
    D res{}; \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(srcn_v); i++) { \
      res[i] = uint##d_esize##_t(srcn_v[i]) + uint##d_esize##_t(srcm_v[i]); \
    } \
    return res; \
  } \
  template <typename D, typename S> \
  DEF_SEM_T(UADDL2_##s_esize, S srcn, S srcm) { \
    auto srcn_v = UReadVI##s_esize(srcn); \
    auto srcm_v = UReadVI##s_esize(srcm); \
    D res{}; \
    auto res_len = GetVectorElemsNum(res); \
    _Pragma("unroll") for (size_t i = res_len; i < GetVectorElemsNum(srcn_v); i++) { \
      res[i - res_len] = uint##d_esize##_t(srcn_v[i]) + uint##d_esize##_t(srcm_v[i]); \
    } \
    return res; \
  }

MAKE_UADDL(8, 16);
MAKE_UADDL(16, 32);
MAKE_UADDL(32, 64);

#undef MAKE_UADDL

}  // namespace

DEF_ISEL(UADDL_ASIMDDIFF_L_8H8B) = UADDL_8<VIu16v8, VIu8v8>;
DEF_ISEL(UADDL_ASIMDDIFF_L_4S4H) = UADDL_16<VIu32v4, VIu16v4>;
DEF_ISEL(UADDL_ASIMDDIFF_L_2D2S) = UADDL_32<VIu64v2, VIu32v2>;

DEF_ISEL(UADDL_ASIMDDIFF_L_8H16B) = UADDL2_8<VIu16v8, VIu8v16>;
DEF_ISEL(UADDL_ASIMDDIFF_L_4S8H) = UADDL2_16<VIu32v4, VIu16v8>;
DEF_ISEL(UADDL_ASIMDDIFF_L_2D4S) = UADDL2_32<VIu64v2, VIu32v4>;

// UADDW{2}  <Vd>.<Ta>, <Vn>.<Ta>, <Vm>.<Tb>
namespace {
#define MAKE_UADDW(ta_esize, tb_esize) \
  template <typename TA, typename TB> \
  DEF_SEM_T(UADDW_##ta_esize##_##tb_esize, TA srcn, TB srcm) { \
    auto srcn_v = UReadVI##ta_esize(srcn); \
    auto srcm_v = UReadVI##tb_esize(srcm); \
    TA res{}; \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(srcn_v); i++) { \
      res[i] = srcn_v[i] + uint##tb_esize##_t(srcm_v[i]); \
    } \
    return res; \
  } \
  template <typename TA, typename TB> \
  DEF_SEM_T(UADDW2_##ta_esize##_##tb_esize, TA srcn, TB srcm) { \
    auto srcn_v = UReadVI##ta_esize(srcn); \
    auto srcm_v = UReadVI##tb_esize(srcm); \
    TA res{}; \
    size_t ta_v_len = GetVectorElemsNum(srcn_v); \
    _Pragma("unroll") for (size_t i = 0; i < ta_v_len; i++) { \
      res[i] = srcn_v[i] + uint##tb_esize##_t(srcm_v[i + ta_v_len]); \
    } \
    return res; \
  }

MAKE_UADDW(16, 8);
MAKE_UADDW(32, 16);
MAKE_UADDW(64, 32);

#undef MAKE_UADDW

}  // namespace

DEF_ISEL(UADDW_ASIMDDIFF_W_8H8B) = UADDW_16_8<VIu16v8, VIu8v8>;
DEF_ISEL(UADDW_ASIMDDIFF_W_4S4H) = UADDW_32_16<VIu32v4, VIu16v4>;
DEF_ISEL(UADDW_ASIMDDIFF_W_2D2S) = UADDW_64_32<VIu64v2, VIu32v2>;

DEF_ISEL(UADDW_ASIMDDIFF_W_8H16B) = UADDW2_16_8<VIu16v8, VIu8v16>;
DEF_ISEL(UADDW_ASIMDDIFF_W_4S8H) = UADDW2_32_16<VIu32v4, VIu16v8>;
DEF_ISEL(UADDW_ASIMDDIFF_W_2D4S) = UADDW2_64_32<VIu64v2, VIu32v4>;

// SADDW{2}  <Vd>.<Ta>, <Vn>.<Ta>, <Vm>.<Tb>
namespace {
#define MAKE_SADDW(ta_esize, tb_esize) \
  template <typename TA, typename TB> \
  DEF_SEM_T(SADDW_##ta_esize##_##tb_esize, TA srcn, TB srcm) { \
    auto srcn_v = SReadVI##ta_esize(srcn); \
    auto srcm_v = SReadVI##tb_esize(srcm); \
    TA res{}; \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(srcm_v); i++) { \
      res[i] = srcn_v[i] + int##tb_esize##_t(srcm_v[i]); \
    } \
    return res; \
  } \
  template <typename TA, typename TB> \
  DEF_SEM_T(SADDW2_##ta_esize##_##tb_esize, TA srcn, TB srcm) { \
    auto srcn_v = SReadVI##ta_esize(srcn); \
    auto srcm_v = SReadVI##tb_esize(srcm); \
    TA res{}; \
    size_t ta_v_len = GetVectorElemsNum(srcn_v); \
    _Pragma("unroll") for (size_t i = 0; i < ta_v_len; i++) { \
      res[i] = srcn_v[i] + int##tb_esize##_t(srcm_v[ta_v_len + i]); \
    } \
    return res; \
  }

MAKE_SADDW(16, 8);
MAKE_SADDW(32, 16);
MAKE_SADDW(64, 32);

#undef MAKE_SADDW

}  // namespace

DEF_ISEL(SADDW_ASIMDDIFF_W_8H8B) = SADDW_16_8<VIi16v8, VIi8v8>;
DEF_ISEL(SADDW_ASIMDDIFF_W_4S4H) = SADDW_32_16<VIi32v4, VIi16v4>;
DEF_ISEL(SADDW_ASIMDDIFF_W_2D2S) = SADDW_64_32<VIi64v2, VIi32v2>;

DEF_ISEL(SADDW_ASIMDDIFF_W_8H16B) = SADDW2_16_8<VIi16v8, VIi8v16>;
DEF_ISEL(SADDW_ASIMDDIFF_W_4S8H) = SADDW2_32_16<VIi32v4, VIi16v8>;
DEF_ISEL(SADDW_ASIMDDIFF_W_2D4S) = SADDW2_64_32<VIi64v2, VIi32v4>;

// SCVTF  <Vd>.<T>, <Vn>.<T> (only 32bit or 64bit)
namespace {
#define MAKE_SCVTF_VECTOR(elem_size) \
  template <typename S, typename D> \
  DEF_SEM_T_STATE(SCVTF_Vector##elem_size, S src) { \
    auto srcv = SReadVI##elem_size(src); \
    D res{}; \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(srcv); i++) { \
      res[i] = CheckedCast<int##elem_size##_t, float##elem_size##_t>(state, srcv[i]); \
    } \
    return res; \
  }

MAKE_SCVTF_VECTOR(32);
MAKE_SCVTF_VECTOR(64);

#undef MAKE_SCVTF_VECTOR

#define MAKE_SCVTF_VECTOR_FPSRSTATUS(elem_size) \
  template <typename S, typename D> \
  DEF_SEM_T_STATE(SCVTF_Vector##elem_size##_FPSRStatus, S src) { \
    auto srcv = SReadVI##elem_size(src); \
    D res{}; \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(srcv); i++) { \
      res[i] = CheckedCastFPSRStatus<int##elem_size##_t, float##elem_size##_t>(state, srcv[i]); \
    } \
    return res; \
  }

MAKE_SCVTF_VECTOR_FPSRSTATUS(32);
MAKE_SCVTF_VECTOR_FPSRSTATUS(64);

#undef MAKE_SCVTF_VECTOR_FPSRSTATUS

}  // namespace

DEF_ISEL(SCVTF_ASIMDMISC_R_2S) = SCVTF_Vector32<VIi32v2, VIf32v2>;
DEF_ISEL(SCVTF_ASIMDMISC_R_4S) = SCVTF_Vector32<VIi32v4, VIf32v4>;
DEF_ISEL(SCVTF_ASIMDMISC_R_2D) = SCVTF_Vector64<VIi64v2, VIf64v2>;
// FPSR
DEF_ISEL(SCVTF_ASIMDMISC_R_2S_FPSRSTATUS) = SCVTF_Vector32_FPSRStatus<VIi32v2, VIf32v2>;
DEF_ISEL(SCVTF_ASIMDMISC_R_4S_FPSRSTATUS) = SCVTF_Vector32_FPSRStatus<VIi32v4, VIf32v4>;
DEF_ISEL(SCVTF_ASIMDMISC_R_2D_FPSRSTATUS) = SCVTF_Vector64_FPSRStatus<VIi64v2, VIf64v2>;

// REV32  <Vd>.<T>, <Vn>.<T>
namespace {
template <typename S>
DEF_SEM_T(REV32_VectorB, S src) {
  auto srcv = UReadVI8(src);
  S res{};
  _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(srcv); i += 4) {
    res[i] = srcv[i + 3];
    res[i + 1] = srcv[i + 2];
    res[i + 2] = srcv[i + 1];
    res[i + 3] = srcv[i];
  }
  return res;
}

template <typename S>
DEF_SEM_T(REV32_VectorH, S src) {
  auto srcv = UReadVI16(src);
  S res{};
  _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(srcv); i += 2) {
    res[i] = srcv[i + 1];
    res[i + 1] = srcv[i];
  }
  return res;
}
}  // namespace

DEF_ISEL(REV32_ASIMDMISC_R_8B) = REV32_VectorB<VIu8v8>;
DEF_ISEL(REV32_ASIMDMISC_R_16B) = REV32_VectorB<VIu8v16>;

DEF_ISEL(REV32_ASIMDMISC_R_4H) = REV32_VectorH<VIu16v4>;
DEF_ISEL(REV32_ASIMDMISC_R_8H) = REV32_VectorH<VIu16v8>;

// SHRN{2}  <Vd>.<Tb>, <Vn>.<Ta>, #<shift>
namespace {
#define MAKE_SHRN(s_esize, d_esize) \
  template <typename D, typename S> \
  DEF_SEM_T(SHRN_##s_esize, D dst, S src, I64 shift) { \
    auto src_v = UReadVI##s_esize(src); \
    auto shift_val = Read(shift); \
    D res = {}; \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(src_v); i++) { \
      res[i] = (uint##d_esize##_t)(src_v[i] >> shift_val); \
    } \
    return res; \
  } \
  template <typename D, typename S> \
  DEF_SEM_T(SHRN2_##s_esize, D dst, S src, I64 shift) { \
    auto src_v = UReadVI##s_esize(src); \
    auto shift_val = Read(shift); \
    D res = UReadVI##d_esize(dst); \
    size_t srcv_enum = GetVectorElemsNum(src_v); \
    _Pragma("unroll") for (size_t i = 0; i < srcv_enum; i++) { \
      res[i + srcv_enum] = (uint##d_esize##_t)(src_v[i] >> shift_val); \
    } \
    return res; \
  }

MAKE_SHRN(16, 8);
MAKE_SHRN(32, 16);
MAKE_SHRN(64, 32);

#undef MAKE_SHRN

}  // namespace

DEF_ISEL(SHRN_ASIMDSHF_N_8B8H) = SHRN_16<VIu8v8, VIu16v8>;
DEF_ISEL(SHRN_ASIMDSHF_N_4H4S) = SHRN_32<VIu16v4, VIu32v4>;
DEF_ISEL(SHRN_ASIMDSHF_N_2S2D) = SHRN_64<VIu32v2, VIu64v2>;

DEF_ISEL(SHRN_ASIMDSHF_N_16B8H) = SHRN2_16<VIu8v16, VIu16v8>;
DEF_ISEL(SHRN_ASIMDSHF_N_8H4S) = SHRN2_32<VIu16v8, VIu32v4>;
DEF_ISEL(SHRN_ASIMDSHF_N_4S2D) = SHRN2_64<VIu32v4, VIu64v2>;

// ADDHN{2}  <Vd>.<Tb>, <Vn>.<Ta>, <Vm>.<Ta>
namespace {
#define MAKE_ADDHN(s_esize, d_esize) \
  template <typename D, typename S> \
  DEF_SEM_T(ADDHN_##s_esize, D dst, S srcn, S srcm) { \
    auto srcn_v = UReadVI##s_esize(srcn); \
    auto srcm_v = UReadVI##s_esize(srcm); \
    D res = {}; \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(srcn_v); i++) { \
      res[i] = (uint##d_esize##_t)((srcn_v[i] + srcm_v[i]) >> d_esize); \
    } \
    return res; \
  } \
  template <typename D, typename S> \
  DEF_SEM_T(ADDHN2_##s_esize, D dst, S srcn, S srcm) { \
    auto srcn_v = UReadVI##s_esize(srcn); \
    auto srcm_v = UReadVI##s_esize(srcm); \
    D res = UReadVI##d_esize(dst); \
    size_t srcv_enum = GetVectorElemsNum(srcn_v); \
    _Pragma("unroll") for (size_t i = 0; i < srcv_enum; i++) { \
      res[i + srcv_enum] = (uint##d_esize##_t)((srcn_v[i] + srcm_v[i]) >> d_esize); \
    } \
    return res; \
  }

MAKE_ADDHN(16, 8);
MAKE_ADDHN(32, 16);
MAKE_ADDHN(64, 32);

#undef MAKE_ADDHN

}  // namespace

DEF_ISEL(ADDHN_ASIMDDIFF_N_8B8H) = ADDHN_16<VIu8v8, VIu16v8>;
DEF_ISEL(ADDHN_ASIMDDIFF_N_4H4S) = ADDHN_32<VIu16v4, VIu32v4>;
DEF_ISEL(ADDHN_ASIMDDIFF_N_2S2D) = ADDHN_64<VIu32v2, VIu64v2>;

DEF_ISEL(ADDHN_ASIMDDIFF_N_16B8H) = ADDHN2_16<VIu8v16, VIu16v8>;
DEF_ISEL(ADDHN_ASIMDDIFF_N_8H4S) = ADDHN2_32<VIu16v8, VIu32v4>;
DEF_ISEL(ADDHN_ASIMDDIFF_N_4S2D) = ADDHN2_64<VIu32v4, VIu64v2>;

// SADDL{2}  <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
namespace {
#define MAKE_SADDL(s_esize, d_esize) \
  template <typename D, typename S> \
  DEF_SEM_T(SADDL_##s_esize, S srcn, S srcm) { \
    auto srcn_v = SReadVI##s_esize(srcn); \
    auto srcm_v = SReadVI##s_esize(srcm); \
    D res{}; \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(srcn_v); i++) { \
      res[i] = int##d_esize##_t(srcn_v[i]) + int##d_esize##_t(srcm_v[i]); \
    } \
    return res; \
  } \
  template <typename D, typename S> \
  DEF_SEM_T(SADDL2_##s_esize, S srcn, S srcm) { \
    auto srcn_v = SReadVI##s_esize(srcn); \
    auto srcm_v = SReadVI##s_esize(srcm); \
    D res{}; \
    auto res_len = GetVectorElemsNum(res); \
    _Pragma("unroll") for (size_t i = res_len; i < GetVectorElemsNum(srcn_v); i++) { \
      res[i - res_len] = int##d_esize##_t(srcn_v[i]) + int##d_esize##_t(srcm_v[i]); \
    } \
    return res; \
  }

MAKE_SADDL(8, 16);
MAKE_SADDL(16, 32);
MAKE_SADDL(32, 64);

#undef MAKE_SADDL

}  // namespace

DEF_ISEL(SADDL_ASIMDDIFF_L_8H8B) = SADDL_8<VIi16v8, VIi8v8>;
DEF_ISEL(SADDL_ASIMDDIFF_L_4S4H) = SADDL_16<VIi32v4, VIi16v4>;
DEF_ISEL(SADDL_ASIMDDIFF_L_2D2S) = SADDL_32<VIi64v2, VIi32v2>;

DEF_ISEL(SADDL_ASIMDDIFF_L_8H16B) = SADDL2_8<VIi16v8, VIi8v16>;
DEF_ISEL(SADDL_ASIMDDIFF_L_4S8H) = SADDL2_16<VIi32v4, VIi16v8>;
DEF_ISEL(SADDL_ASIMDDIFF_L_2D4S) = SADDL2_32<VIi64v2, VIi32v4>;

// SSUBW{2}  <Vd>.<Ta>, <Vn>.<Ta>, <Vm>.<Tb>
namespace {
#define MAKE_SSUBW(ta_esize, tb_esize) \
  template <typename TA, typename TB> \
  DEF_SEM_T(SSUBW_##ta_esize##_##tb_esize, TA srcn, TB srcm) { \
    auto srcn_v = SReadVI##ta_esize(srcn); \
    auto srcm_v = SReadVI##tb_esize(srcm); \
    TA res{}; \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(srcn_v); i++) { \
      res[i] = srcn_v[i] - int##tb_esize##_t(srcm_v[i]); \
    } \
    return res; \
  } \
  template <typename TA, typename TB> \
  DEF_SEM_T(SSUBW2_##ta_esize##_##tb_esize, TA srcn, TB srcm) { \
    auto srcn_v = SReadVI##ta_esize(srcn); \
    auto srcm_v = SReadVI##tb_esize(srcm); \
    TA res{}; \
    size_t ta_v_len = GetVectorElemsNum(srcn_v); \
    _Pragma("unroll") for (size_t i = 0; i < ta_v_len; i++) { \
      res[i] = srcn_v[i] - int##tb_esize##_t(srcm_v[ta_v_len + i]); \
    } \
    return res; \
  }

MAKE_SSUBW(16, 8);
MAKE_SSUBW(32, 16);
MAKE_SSUBW(64, 32);

#undef MAKE_SSUBW

}  // namespace

DEF_ISEL(SSUBW_ASIMDDIFF_W_8H8B) = SSUBW_16_8<VIi16v8, VIi8v8>;
DEF_ISEL(SSUBW_ASIMDDIFF_W_4S4H) = SSUBW_32_16<VIi32v4, VIi16v4>;
DEF_ISEL(SSUBW_ASIMDDIFF_W_2D2S) = SSUBW_64_32<VIi64v2, VIi32v2>;

DEF_ISEL(SSUBW_ASIMDDIFF_W_8H16B) = SSUBW2_16_8<VIi16v8, VIi8v16>;
DEF_ISEL(SSUBW_ASIMDDIFF_W_4S8H) = SSUBW2_32_16<VIi32v4, VIi16v8>;
DEF_ISEL(SSUBW_ASIMDDIFF_W_2D4S) = SSUBW2_64_32<VIi64v2, VIi32v4>;

// ZIP1  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
namespace {
#define MAKE_ZIP1(esize) \
  template <typename S> \
  DEF_SEM_T(ZIP1_##esize, S srcn, S srcm) { \
    auto srcn_v = UReadVI##esize(srcn); \
    auto srcm_v = UReadVI##esize(srcm); \
    S res{}; \
    size_t half = GetVectorElemsNum(srcn_v) / 2; \
    _Pragma("unroll") for (size_t i = 0; i < half; i++) { \
      res[2 * i] = srcn_v[i]; \
      res[2 * i + 1] = srcm_v[i]; \
    } \
    return res; \
  }

MAKE_ZIP1(8);
MAKE_ZIP1(16);
MAKE_ZIP1(32);
MAKE_ZIP1(64);

#undef MAKE_ZIP1

}  // namespace

DEF_ISEL(ZIP1_ASIMDPERM_ONLY_8B) = ZIP1_8<VIu8v8>;
DEF_ISEL(ZIP1_ASIMDPERM_ONLY_16B) = ZIP1_8<VIu8v16>;
DEF_ISEL(ZIP1_ASIMDPERM_ONLY_4H) = ZIP1_16<VIu16v4>;
DEF_ISEL(ZIP1_ASIMDPERM_ONLY_8H) = ZIP1_16<VIu16v8>;
DEF_ISEL(ZIP1_ASIMDPERM_ONLY_2S) = ZIP1_32<VIu32v2>;
DEF_ISEL(ZIP1_ASIMDPERM_ONLY_4S) = ZIP1_32<VIu32v4>;
DEF_ISEL(ZIP1_ASIMDPERM_ONLY_2D) = ZIP1_64<VIu64v2>;

// ZIP2  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
namespace {
#define MAKE_ZIP2(esize) \
  template <typename S> \
  DEF_SEM_T(ZIP2_##esize, S srcn, S srcm) { \
    auto srcn_v = UReadVI##esize(srcn); \
    auto srcm_v = UReadVI##esize(srcm); \
    S res{}; \
    size_t half = GetVectorElemsNum(srcn_v) / 2; \
    _Pragma("unroll") for (size_t i = 0; i < half; i++) { \
      res[2 * i] = srcn_v[half + i]; \
      res[2 * i + 1] = srcm_v[half + i]; \
    } \
    return res; \
  }

MAKE_ZIP2(8);
MAKE_ZIP2(16);
MAKE_ZIP2(32);
MAKE_ZIP2(64);

#undef MAKE_ZIP2

}  // namespace

DEF_ISEL(ZIP2_ASIMDPERM_ONLY_8B) = ZIP2_8<VIu8v8>;
DEF_ISEL(ZIP2_ASIMDPERM_ONLY_16B) = ZIP2_8<VIu8v16>;
DEF_ISEL(ZIP2_ASIMDPERM_ONLY_4H) = ZIP2_16<VIu16v4>;
DEF_ISEL(ZIP2_ASIMDPERM_ONLY_8H) = ZIP2_16<VIu16v8>;
DEF_ISEL(ZIP2_ASIMDPERM_ONLY_2S) = ZIP2_32<VIu32v2>;
DEF_ISEL(ZIP2_ASIMDPERM_ONLY_4S) = ZIP2_32<VIu32v4>;
DEF_ISEL(ZIP2_ASIMDPERM_ONLY_2D) = ZIP2_64<VIu64v2>;

// UZP1  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
namespace {
#define MAKE_UZP1(esize) \
  template <typename S> \
  DEF_SEM_T(UZP1_##esize, S srcn, S srcm) { \
    auto srcn_v = UReadVI##esize(srcn); \
    auto srcm_v = UReadVI##esize(srcm); \
    S res{}; \
    size_t half = GetVectorElemsNum(srcn_v) / 2; \
    _Pragma("unroll") for (size_t i = 0; i < half; i++) { \
      res[i] = srcn_v[2 * i]; \
    } \
    _Pragma("unroll") for (size_t i = 0; i < half; i++) { \
      res[half + i] = srcm_v[2 * i]; \
    } \
    return res; \
  }

MAKE_UZP1(8);
MAKE_UZP1(16);
MAKE_UZP1(32);
MAKE_UZP1(64);

#undef MAKE_UZP1

}  // namespace

DEF_ISEL(UZP1_ASIMDPERM_ONLY_8B) = UZP1_8<VIu8v8>;
DEF_ISEL(UZP1_ASIMDPERM_ONLY_16B) = UZP1_8<VIu8v16>;
DEF_ISEL(UZP1_ASIMDPERM_ONLY_4H) = UZP1_16<VIu16v4>;
DEF_ISEL(UZP1_ASIMDPERM_ONLY_8H) = UZP1_16<VIu16v8>;
DEF_ISEL(UZP1_ASIMDPERM_ONLY_2S) = UZP1_32<VIu32v2>;
DEF_ISEL(UZP1_ASIMDPERM_ONLY_4S) = UZP1_32<VIu32v4>;
DEF_ISEL(UZP1_ASIMDPERM_ONLY_2D) = UZP1_64<VIu64v2>;

// ORN  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
namespace {
template <typename V>
DEF_SEM_T(ORN_Vec, V src1, V src2) {
  auto lhs = UReadVI64(src1);
  auto rhs = UReadVI64(src2);
  decltype(lhs) res{};
  _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(lhs); i++) {
    res[i] = lhs[i] | ~rhs[i];
  }
  return res;
}
}  // namespace

DEF_ISEL(ORN_ASIMDSAME_ONLY_8B) = ORN_Vec<VIu64v1>;
DEF_ISEL(ORN_ASIMDSAME_ONLY_16B) = ORN_Vec<VIu64v2>;

// REV64  <Vd>.<T>, <Vn>.<T>
namespace {
template <typename S>
DEF_SEM_T(REV64_VectorB, S src) {
  auto srcv = UReadVI8(src);
  S res{};
  _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(srcv); i += 8) {
    res[i] = srcv[i + 7];
    res[i + 1] = srcv[i + 6];
    res[i + 2] = srcv[i + 5];
    res[i + 3] = srcv[i + 4];
    res[i + 4] = srcv[i + 3];
    res[i + 5] = srcv[i + 2];
    res[i + 6] = srcv[i + 1];
    res[i + 7] = srcv[i];
  }
  return res;
}

template <typename S>
DEF_SEM_T(REV64_VectorH, S src) {
  auto srcv = UReadVI16(src);
  S res{};
  _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(srcv); i += 4) {
    res[i] = srcv[i + 3];
    res[i + 1] = srcv[i + 2];
    res[i + 2] = srcv[i + 1];
    res[i + 3] = srcv[i];
  }
  return res;
}

template <typename S>
DEF_SEM_T(REV64_VectorS, S src) {
  auto srcv = UReadVI32(src);
  S res{};
  _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(srcv); i += 2) {
    res[i] = srcv[i + 1];
    res[i + 1] = srcv[i];
  }
  return res;
}
}  // namespace

DEF_ISEL(REV64_ASIMDMISC_R_8B) = REV64_VectorB<VIu8v8>;
DEF_ISEL(REV64_ASIMDMISC_R_16B) = REV64_VectorB<VIu8v16>;
DEF_ISEL(REV64_ASIMDMISC_R_4H) = REV64_VectorH<VIu16v4>;
DEF_ISEL(REV64_ASIMDMISC_R_8H) = REV64_VectorH<VIu16v8>;
DEF_ISEL(REV64_ASIMDMISC_R_2S) = REV64_VectorS<VIu32v2>;
DEF_ISEL(REV64_ASIMDMISC_R_4S) = REV64_VectorS<VIu32v4>;

// RBIT  <Vd>.<T>, <Vn>.<T>
namespace {
template <typename S>
DEF_SEM_T(RBIT_VectorB, S src) {
  auto srcv = UReadVI8(src);
  S res{};
  _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(srcv); i++) {
    uint8_t b = srcv[i];
    b = uint8_t((b & 0xF0) >> 4 | (b & 0x0F) << 4);
    b = uint8_t((b & 0xCC) >> 2 | (b & 0x33) << 2);
    b = uint8_t((b & 0xAA) >> 1 | (b & 0x55) << 1);
    res[i] = b;
  }
  return res;
}
}  // namespace

DEF_ISEL(RBIT_ASIMDMISC_R_8B) = RBIT_VectorB<VIu8v8>;  // RBIT  <Vd>.8B, <Vn>.8B
DEF_ISEL(RBIT_ASIMDMISC_R_16B) = RBIT_VectorB<VIu8v16>;  // RBIT  <Vd>.16B, <Vn>.16B

// LDNP/STNP
DEF_ISEL(LDNP_32_LDSTNAPAIR_OFFS) = LoadPair32;
DEF_ISEL(LDNP_64_LDSTNAPAIR_OFFS) = LoadPair64;
DEF_ISEL(STNP_32_LDSTNAPAIR_OFFS) = StorePair32;
DEF_ISEL(STNP_64_LDSTNAPAIR_OFFS) = StorePair64;

// TBL  <Vd>.<Ta>, { <Vn>.16B }, <Vm>.<Ta>
namespace {
#define MAKE_TBL_L1_1(elem_num) \
  template <typename S> \
  DEF_SEM_T(TBL_L1_1_##elem_num##B, VIu8v16 srcn, S srcm) { \
    auto idx_v = UReadVI8(srcm); \
    auto srcn_v = UReadVI8(srcn); \
    S res{}; \
    _Pragma("unroll") for (size_t i = 0; i < elem_num; i++) { \
      res[i] = idx_v[i] < 16 ? srcn_v[idx_v[i]] : 0; \
    } \
    return res; \
  }

MAKE_TBL_L1_1(8)
MAKE_TBL_L1_1(16)

#undef MAKE_TBL_L1_1
}  // namespace

DEF_ISEL(TBL_ASIMDTBL_L1_1_8B) = TBL_L1_1_8B<VIu8v8>;  // TBL  <Vd>.<Ta>, { <Vn>.16B }, <Vm>.<Ta>
DEF_ISEL(TBL_ASIMDTBL_L1_1_16B) = TBL_L1_1_16B<VIu8v16>;  // TBL  <Vd>.<Ta>, { <Vn>.16B }, <Vm>.<Ta>

// TBL  <Vd>.<Ta>, { <Vn>.16B, <Vn+1>.16B }, <Vm>.<Ta>
namespace {
#define MAKE_TBL_L2_2(elem_num) \
  template <typename S> \
  DEF_SEM_T(TBL_L2_2_##elem_num##B, VIu8v16 srcn, VIu8v16 srcn_1, S srcm) { \
    auto srcn_v = UReadVI8(srcn); \
    auto srcn_1_v = UReadVI8(srcn_1); \
    auto idx_v = UReadVI8(srcm); \
    VIu8v32 vec_tbl = {}; \
    _Pragma("unroll") for (size_t i = 0; i < 16; i++) { \
      vec_tbl[i] = srcn_v[i]; \
    } \
    _Pragma("unroll") for (size_t i = 0; i < 16; i++) { \
      vec_tbl[i + 16] = srcn_1_v[i]; \
    } \
    S res{}; \
    _Pragma("unroll") for (size_t i = 0; i < elem_num; i++) { \
      res[i] = idx_v[i] < 32 ? vec_tbl[idx_v[i]] : 0; \
    } \
    return res; \
  }

MAKE_TBL_L2_2(8)
MAKE_TBL_L2_2(16)

#undef MAKE_TBL_L2_2
}  // namespace

DEF_ISEL(TBL_ASIMDTBL_L2_2_8B) =
    TBL_L2_2_8B<VIu8v8>;  // TBL  <Vd>.<Ta>, { <Vn>.16B, <Vn+1>.16B }, <Vm>.<Ta>
DEF_ISEL(TBL_ASIMDTBL_L2_2_16B) =
    TBL_L2_2_16B<VIu8v16>;  // TBL  <Vd>.<Ta>, { <Vn>.16B, <Vn+1>.16B }, <Vm>.<Ta>

// AES / PMULL / SHA1H
namespace {

static constexpr uint8_t kAESSBox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

static constexpr uint8_t kAESInvSBox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
};

// ShiftRows permutation in column-major state layout: result[i] = state[perm[i]].
static constexpr uint8_t kAESShiftRowsPerm[16] = {
    0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11,
};
static constexpr uint8_t kAESInvShiftRowsPerm[16] = {
    0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3,
};

ALWAYS_INLINE static uint8_t AESxtime(uint8_t x) {
  return static_cast<uint8_t>((x << 1) ^ ((x & 0x80) ? 0x1B : 0x00));
}

// AESE  <Vd>.16B, <Vn>.16B
//   state = dst XOR src; state = ShiftRows(state); state = SubBytes(state); dst = state
template <typename V>
DEF_SEM_T(AESE_16B, V dst_src, V src) {
  auto dst_v = UReadVI8(dst_src);
  auto src_v = UReadVI8(src);
  uint8_t state[16];
  _Pragma("unroll") for (int i = 0; i < 16; i++) {
    state[i] = static_cast<uint8_t>(dst_v[i] ^ src_v[i]);
  }
  V res = {};
  _Pragma("unroll") for (int i = 0; i < 16; i++) {
    res[i] = kAESSBox[state[kAESShiftRowsPerm[i]]];
  }
  return res;
}

// AESD  <Vd>.16B, <Vn>.16B
template <typename V>
DEF_SEM_T(AESD_16B, V dst_src, V src) {
  auto dst_v = UReadVI8(dst_src);
  auto src_v = UReadVI8(src);
  uint8_t state[16];
  _Pragma("unroll") for (int i = 0; i < 16; i++) {
    state[i] = static_cast<uint8_t>(dst_v[i] ^ src_v[i]);
  }
  V res = {};
  _Pragma("unroll") for (int i = 0; i < 16; i++) {
    res[i] = kAESInvSBox[state[kAESInvShiftRowsPerm[i]]];
  }
  return res;
}

// AESMC  <Vd>.16B, <Vn>.16B — MixColumns in GF(2^8).
template <typename V>
DEF_SEM_T(AESMC_16B, V src) {
  auto src_v = UReadVI8(src);
  V res = {};
  _Pragma("unroll") for (int c = 0; c < 4; c++) {
    uint8_t a0 = src_v[4 * c + 0];
    uint8_t a1 = src_v[4 * c + 1];
    uint8_t a2 = src_v[4 * c + 2];
    uint8_t a3 = src_v[4 * c + 3];
    // Matrix { {2,3,1,1},{1,2,3,1},{1,1,2,3},{3,1,1,2} } in GF(2^8).
    res[4 * c + 0] = AESxtime(a0) ^ (AESxtime(a1) ^ a1) ^ a2 ^ a3;
    res[4 * c + 1] = a0 ^ AESxtime(a1) ^ (AESxtime(a2) ^ a2) ^ a3;
    res[4 * c + 2] = a0 ^ a1 ^ AESxtime(a2) ^ (AESxtime(a3) ^ a3);
    res[4 * c + 3] = (AESxtime(a0) ^ a0) ^ a1 ^ a2 ^ AESxtime(a3);
  }
  return res;
}

// AESIMC  <Vd>.16B, <Vn>.16B — InvMixColumns in GF(2^8).
//   Uses matrix { {0E,0B,0D,09}, {09,0E,0B,0D}, {0D,09,0E,0B}, {0B,0D,09,0E} }.
ALWAYS_INLINE static uint8_t AESmul9(uint8_t x) {
  return AESxtime(AESxtime(AESxtime(x))) ^ x;
}
ALWAYS_INLINE static uint8_t AESmul11(uint8_t x) {
  return AESxtime(AESxtime(AESxtime(x))) ^ AESxtime(x) ^ x;
}
ALWAYS_INLINE static uint8_t AESmul13(uint8_t x) {
  return AESxtime(AESxtime(AESxtime(x))) ^ AESxtime(AESxtime(x)) ^ x;
}
ALWAYS_INLINE static uint8_t AESmul14(uint8_t x) {
  return AESxtime(AESxtime(AESxtime(x))) ^ AESxtime(AESxtime(x)) ^ AESxtime(x);
}

template <typename V>
DEF_SEM_T(AESIMC_16B, V src) {
  auto src_v = UReadVI8(src);
  V res = {};
  _Pragma("unroll") for (int c = 0; c < 4; c++) {
    uint8_t a0 = src_v[4 * c + 0];
    uint8_t a1 = src_v[4 * c + 1];
    uint8_t a2 = src_v[4 * c + 2];
    uint8_t a3 = src_v[4 * c + 3];
    res[4 * c + 0] = AESmul14(a0) ^ AESmul11(a1) ^ AESmul13(a2) ^ AESmul9(a3);
    res[4 * c + 1] = AESmul9(a0) ^ AESmul14(a1) ^ AESmul11(a2) ^ AESmul13(a3);
    res[4 * c + 2] = AESmul13(a0) ^ AESmul9(a1) ^ AESmul14(a2) ^ AESmul11(a3);
    res[4 * c + 3] = AESmul11(a0) ^ AESmul13(a1) ^ AESmul9(a2) ^ AESmul14(a3);
  }
  return res;
}

// PMULL{2}: polynomial multiply (GF(2)) long.
// 8B × 8B → 8H lane-wise.
template <typename D, typename S>
DEF_SEM_T(PMULL_8, S src1, S src2) {
  auto av = UReadVI8(src1);
  auto bv = UReadVI8(src2);
  D res = {};
  _Pragma("unroll") for (int i = 0; i < 8; i++) {
    uint16_t r = 0;
    uint16_t a = av[i];
    uint8_t b = bv[i];
    _Pragma("unroll") for (int k = 0; k < 8; k++) {
      if ((b >> k) & 1) {
        r ^= static_cast<uint16_t>(a << k);
      }
    }
    res[i] = r;
  }
  return res;
}

// PMULL2: uses upper 8 bytes of each 16B source.
template <typename D, typename S>
DEF_SEM_T(PMULL2_8, S src1, S src2) {
  auto av = UReadVI8(src1);
  auto bv = UReadVI8(src2);
  D res = {};
  _Pragma("unroll") for (int i = 0; i < 8; i++) {
    uint16_t r = 0;
    uint16_t a = av[i + 8];
    uint8_t b = bv[i + 8];
    _Pragma("unroll") for (int k = 0; k < 8; k++) {
      if ((b >> k) & 1) {
        r ^= static_cast<uint16_t>(a << k);
      }
    }
    res[i] = r;
  }
  return res;
}

// 64×64 polynomial multiply → 128-bit result (low lane, high lane).
ALWAYS_INLINE static VIu64v2 AESPolyMul64(uint64_t a, uint64_t b) {
  uint64_t lo = 0, hi = 0;
  _Pragma("unroll") for (int i = 0; i < 64; i++) {
    if ((b >> i) & 1) {
      lo ^= a << i;
      if (i > 0) {
        hi ^= a >> (64 - i);
      }
    }
  }
  VIu64v2 r = {};
  r[0] = lo;
  r[1] = hi;
  return r;
}

// PMULL  <Vd>.1Q, <Vn>.1D, <Vm>.1D
DEF_SEM_T(PMULL_64_1D, VIu64v1 src1, VIu64v1 src2) {
  auto a = UExtractVI64(UReadVI64(src1), 0);
  auto b = UExtractVI64(UReadVI64(src2), 0);
  return AESPolyMul64(a, b);
}

// PMULL2 <Vd>.1Q, <Vn>.2D, <Vm>.2D — uses upper 64-bit lane.
DEF_SEM_T(PMULL_64_2D, VIu64v2 src1, VIu64v2 src2) {
  auto av = UReadVI64(src1);
  auto bv = UReadVI64(src2);
  auto a = UExtractVI64(av, 1);
  auto b = UExtractVI64(bv, 1);
  return AESPolyMul64(a, b);
}

// SHA1H  <Sd>, <Sn>
//   SHA1H is the SHA1 "fixed rotation" helper: result = ROR(src, 2) = ROL(src, 30).
DEF_SEM_U32(SHA1H, R32 src) {
  uint32_t v = Read(src);
  return static_cast<uint32_t>((v >> 2) | (v << 30));
}

}  // namespace

DEF_ISEL(AESE_B_CRYPTOAES) = AESE_16B<VIu8v16>;  // AESE   <Vd>.16B, <Vn>.16B
DEF_ISEL(AESD_B_CRYPTOAES) = AESD_16B<VIu8v16>;  // AESD   <Vd>.16B, <Vn>.16B
DEF_ISEL(AESMC_B_CRYPTOAES) = AESMC_16B<VIu8v16>;  // AESMC  <Vd>.16B, <Vn>.16B
DEF_ISEL(AESIMC_B_CRYPTOAES) = AESIMC_16B<VIu8v16>;  // AESIMC <Vd>.16B, <Vn>.16B

DEF_ISEL(PMULL_ASIMDDIFF_L_8H8B) =
    PMULL_8<VIu16v8, VIu8v8>;  // PMULL  <Vd>.8H, <Vn>.8B,  <Vm>.8B
DEF_ISEL(PMULL_ASIMDDIFF_L_8H16B) =
    PMULL2_8<VIu16v8, VIu8v16>;  // PMULL2 <Vd>.8H, <Vn>.16B, <Vm>.16B
DEF_ISEL(PMULL_ASIMDDIFF_L_1Q1D) = PMULL_64_1D;  // PMULL  <Vd>.1Q, <Vn>.1D, <Vm>.1D
DEF_ISEL(PMULL_ASIMDDIFF_L_1Q2D) = PMULL_64_2D;  // PMULL2 <Vd>.1Q, <Vn>.2D, <Vm>.2D

DEF_ISEL(SHA1H_SS_CRYPTOSHA2) = SHA1H;  // SHA1H  <Sd>, <Sn>
