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

DEF_SEM_F64(FMOV_UInt64ToVector, R64 src) {
  auto val = Read(src);
  auto float_valp = (float64_t *) (&val);
  return *float_valp;
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
      sum[i] = prefix##binop(prefix##ExtractVI##size(vec1, i), prefix##ExtractVI##size(vec2, i)); \
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

DEF_SEM_T(CMGE_ASISDMISC_ONLYD, VIi64v2 src) {
  auto src_v = SReadVI64(src);
  uint64_t zeros = 0;
  uint64_t ones = ~zeros;
  VIu64v2 res = {};
  _Pragma("unroll") for (int i = 0; i < 2; i++) {
    res[i] = SExtractVI64(src_v, i) >= 0 ? ones : zeros;
  }
  return res;
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

namespace {

// template <typename S>
// DEF_SEM(NOT_8, VI128 dst, S src) {
//   auto vec = UReadVI8(src);
//   auto res = UNotV8(vec);
//   UWriteV8(dst, res);
// }

}  // namespace

// DEF_ISEL(NOT_ASIMDMISC_R_8B) = NOT_8<VI64>;  // NOT  <Vd>.<T>, <Vn>.<T>
// DEF_ISEL(NOT_ASIMDMISC_R_16B) = NOT_8<VI128>;  // NOT  <Vd>.<T>, <Vn>.<T>

namespace {

template <typename T, size_t count>
DEF_SEM_T(EXT, T src1, T src2, I32 src3) {
  auto lsb = Read(src3);
  auto vn = UReadVI8(src1);
  auto vm = UReadVI8(src2);
  VIu8v16 result = {};
  _Pragma("unroll") for (size_t i = 0, max_i = count; i + lsb < max_i; ++i) {
    result[count - 1 - i] = UExtractVI8(vm, i + lsb);
  }
  _Pragma("unroll") for (size_t i = lsb; i < count; ++i) {
    result[count - 1 - i] = UExtractVI8(vn, i - lsb);
  }
  return result;
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

// DEF_SEM(USHR_64B, VI128 dst, VI128 src, I64 shift) {
//   auto vec = UExtractV64(UReadVI64(src), 0);
//   auto sft = Read(shift);
//   auto shifted = UShr128(vec, sft);
//   VIu64v2 tmpv = {};
//   tmpv = UInsertV64(tmpv, 1, 0);
//   tmpv = UInsertV64(tmpv, 0, (uint64_t) shifted);
//   UWriteV64(dst, tmpv);
// }

// DEF_ISEL(USHR_ASISDSHF_R) = USHR_64B;  // USHR  <V><d>, <V><n>, #<shift>

// FMLA  <Vd>.<T>, <Vn>.<T>, <Vm>.<T> twice operation
// FMLA_ASIMDSAME_ONLY
namespace {

#define MAKE_FTWICEOP_ASIMDSAME_ONLY(prefix, elem_size, op1, op2) \
  template <typename V> \
  DEF_SEM_T(F##prefix##_V##elem_size, V dst_src, V src1, V src2) { \
    /* it might good to use F##binop##V##elem_size (e.g. FAddV32)*/ \
    auto dst_src_v = FReadVI##elem_size(dst_src); \
    auto srcv1 = FReadVI##elem_size(src1); \
    auto srcv2 = FReadVI##elem_size(src2); \
    V res = {}; \
    /* res = Vn op1 Vm */ \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(srcv1); i++) { \
      res[i] = CheckedFloatBinOp(F##op1##elem_size, FExtractVI##elem_size(srcv1, i), \
                                 FExtractVI##elem_size(srcv2, i)); \
    } \
    /* res = res op2 Vd */ \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(dst_src_v); i++) { \
      res[i] = CheckedFloatBinOp(F##op2##elem_size, FExtractVI##elem_size(dst_src_v, i), \
                                 FExtractVI##elem_size(res, i)); \
    } \
    return res; \
  }

// no support of float16
MAKE_FTWICEOP_ASIMDSAME_ONLY(MLA, 32, Mul, Add);
MAKE_FTWICEOP_ASIMDSAME_ONLY(MLA, 64, Mul, Add);

#undef MAKE_FTWICEOP_ASIMDSAME_ONLY

}  // namespace

// no support of float16
DEF_ISEL(FMLA_ASIMDSAME_ONLY_2S) = FMLA_V32<VIf32v2>;  // FMLA  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(FMLA_ASIMDSAME_ONLY_4S) = FMLA_V32<VIf32v4>;  // FMLA  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(FMLA_ASIMDSAME_ONLY_2D) = FMLA_V64<VIf64v2>;  // FMLA  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>

// FMLA  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
// FMLA_ASIMDELEM_R_SD
namespace {

#define MAKE_FTWICEOP_ASIMDELEM_R_SD(prefix, elem_size, op1, op2) \
  template <typename V> \
  DEF_SEM_T(F##prefix##_ELEM_V##elem_size, V dst_src, V src1, V src2, I64 index) { \
    /* it might good to use F##binop##V##elem_size (e.g. FAddV32)*/ \
    auto dst_src_v = FReadVI##elem_size(dst_src); \
    auto srcv1 = FReadVI##elem_size(src1); \
    auto srcv2 = FReadVI##elem_size(src2); \
    auto id = Read(index); \
    V res = {}; \
    /* res = Vn op1 Vm */ \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(srcv1); i++) { \
      res[i] = CheckedFloatBinOp(F##op1##elem_size, FExtractVI##elem_size(srcv1, i), \
                                 FExtractVI##elem_size(srcv2, id)); \
    } \
    /* res = res op2 Vd */ \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(dst_src_v); i++) { \
      res[i] = CheckedFloatBinOp(F##op2##elem_size, FExtractVI##elem_size(dst_src_v, i), \
                                 FExtractVI##elem_size(res, i)); \
    } \
    return res; \
  }

MAKE_FTWICEOP_ASIMDELEM_R_SD(MLA, 32, Mul, Add);
MAKE_FTWICEOP_ASIMDELEM_R_SD(MLA, 64, Mul, Add);

#undef MAKE_FTWICEOP_ASIMDELEM_R_SD

}  // namespace

DEF_ISEL(FMLA_ASIMDELEM_R_SD_2S) =
    FMLA_ELEM_V32<VIf32v2>;  // FMLA  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
DEF_ISEL(FMLA_ASIMDELEM_R_SD_4S) =
    FMLA_ELEM_V32<VIf32v4>;  // FMLA  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
DEF_ISEL(FMLA_ASIMDELEM_R_SD_2D) =
    FMLA_ELEM_V64<VIf64v2>;  // FMLA  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]

// FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T> once operation
// FMUL_ASIMDSAME_ONLY
namespace {

#define MAKE_FONCEOP_ASIMDSAME_ONLY(prefix, elem_size, op) \
  template <typename V> \
  DEF_SEM_T(F##prefix##_V##elem_size, V src1, V src2) { \
    /* it might be good to use F##binop##V##elem_size (e.g. FAddV32)*/ \
    auto srcv1 = FReadVI##elem_size(src1); \
    auto srcv2 = FReadVI##elem_size(src2); \
    V res = {}; \
    /* res = Vn op Vm */ \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(srcv1); i++) { \
      res[i] = CheckedFloatBinOp(F##op##elem_size, FExtractVI##elem_size(srcv1, i), \
                                 FExtractVI##elem_size(srcv2, i)); \
    } \
    return res; \
  }  // namespace

// no support of float16
MAKE_FONCEOP_ASIMDSAME_ONLY(MUL, 32, Mul);
MAKE_FONCEOP_ASIMDSAME_ONLY(MUL, 64, Mul);

MAKE_FONCEOP_ASIMDSAME_ONLY(ADD, 32, Add);
MAKE_FONCEOP_ASIMDSAME_ONLY(ADD, 64, Add);

#undef MAKE_FONCEOP_ASIMDSAME_ONLY

}  // namespace

// no support of float16
DEF_ISEL(FMUL_ASIMDSAME_ONLY_2S) = FMUL_V32<VIf32v2>;  // FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(FMUL_ASIMDSAME_ONLY_4S) = FMUL_V32<VIf32v4>;  // FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(FMUL_ASIMDSAME_ONLY_2D) = FMUL_V64<VIf64v2>;  // FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>

DEF_ISEL(FADD_ASIMDSAME_ONLY_2S) = FADD_V32<VIf32v2>;  // FADD  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(FADD_ASIMDSAME_ONLY_4S) = FADD_V32<VIf32v4>;  // FADD  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
DEF_ISEL(FADD_ASIMDSAME_ONLY_2D) = FADD_V64<VIf64v2>;  // FADD  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>

// FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
namespace {
#define MAKE_FONCEOP_ASIMD_INDEX(prefix, elem_size, op) \
  template <typename V> \
  DEF_SEM_T(F##prefix##ID_V##elem_size, V src1, V src2, I32 imm) { \
    auto index = Read(imm); \
    auto srcv1 = FReadVI##elem_size(src1); \
    auto srcv2 = FReadVI##elem_size(src2); \
    V res = {}; \
    auto v2_val = FExtractVI##elem_size(srcv2, index); \
    /* res = Vn + Vm[<index>] */ \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(srcv1); i++) { \
      res[i] = CheckedFloatBinOp(F##op##elem_size, FExtractVI##elem_size(srcv1, i), v2_val); \
    } \
    return res; \
  }  // namespace

// no support of float16
MAKE_FONCEOP_ASIMD_INDEX(MUL, 32, Mul);
MAKE_FONCEOP_ASIMD_INDEX(MUL, 64, Mul);

#undef MAKE_FONCEOP_ASIMD_INDEX

}  // namespace

DEF_ISEL(FMUL_ASIMDELEM_R_SD_2S) =
    FMULID_V32<VIf32v2>;  // FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
DEF_ISEL(FMUL_ASIMDELEM_R_SD_4S) =
    FMULID_V32<VIf32v4>;  // FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
DEF_ISEL(FMUL_ASIMDELEM_R_SD_2D) =
    FMULID_V64<VIf64v2>;  // FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]

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

// SCVTF  <Vd>.<T>, <Vn>.<T> (only 32bit or 64bit)
namespace {
#define MAKE_SCVTF_VECTOR(elem_size) \
  template <typename S, typename D> \
  DEF_SEM_T(SCVTF_Vector##elem_size, S src) { \
    auto srcv = SReadVI##elem_size(src); \
    D res{}; \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(srcv); i++) { \
      res[i] = CheckedCast<int##elem_size##_t, float##elem_size##_t>(srcv[i]); \
    } \
    return res; \
  }

MAKE_SCVTF_VECTOR(32);
MAKE_SCVTF_VECTOR(64);

#undef MAKE_SCVTF_VECTOR

}  // namespace

DEF_ISEL(SCVTF_ASIMDMISC_R_2S) = SCVTF_Vector32<VIi32v2, VIf32v2>;
DEF_ISEL(SCVTF_ASIMDMISC_R_4S) = SCVTF_Vector32<VIi32v4, VIf32v4>;
DEF_ISEL(SCVTF_ASIMDMISC_R_2D) = SCVTF_Vector64<VIi64v2, VIf64v2>;

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
