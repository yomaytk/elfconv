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

#include "FLAGS.h"
#include "remill/Arch/AArch64/Runtime/Operators.h"
#include "remill/Arch/AArch64/Runtime/State.h"
#include "remill/Arch/AArch64/Runtime/Types.h"
#include "remill/Arch/Name.h"
#include "remill/Arch/Runtime/Float.h"
#include "remill/Arch/Runtime/Intrinsics.h"
#include "remill/Arch/Runtime/Operators.h"
#include "remill/Arch/Runtime/Types.h"

namespace {

template <typename S, typename D>
ALWAYS_INLINE static D CheckedCast(S src) {
  return CheckedFloatUnaryOp([](S v) { return static_cast<D>(v); }, src);
}

// UCVTF  <Sd>, <Wn>
template <typename DB, typename S, typename SB>
DEF_SEM_T(UCVTF_UIntToFloat, S src) {
  return CheckedCast<SB, DB>(Read(src));
}

// UCVTF  <V><d>, <V><n>
DEF_SEM_T(UCVTF_Uint32ToFloat32_FROMV, VI128 src) {
  _ecv_f32v4_t res = {};
  auto elems_num = GetVectorElemsNum(res);
  _Pragma("unroll") for (size_t i = 0; i < elems_num; i++) {
    res[i] = CheckedCast<uint32_t, float32_t>(UExtractVI32(UReadVI32(src), i));
  }
  return res;
}

// UCVTF  <V><d>, <V><n>
DEF_SEM_T(UCVTF_Uint64ToFloat64_FROMV, VI128 src) {
  _ecv_f64v2_t res = {};
  auto elems_num = GetVectorElemsNum(res);
  _Pragma("unroll") for (size_t i = 0; i < elems_num; i++) {
    res[i] = CheckedCast<uint64_t, float64_t>(UExtractVI64(UReadVI64(src), i));
  }
  return res;
}

// FCVTZU  <Xd>, <Sn>
template <typename DB, typename S, typename SB>
DEF_SEM_T(FCVTZU_FloatToUInt, S src) {
  return CheckedCast<SB, DB>(Read(src));
}

// FCVTZS  <Wd>, <Sn>
DEF_SEM_U32(FCVTZS_Float32ToSInt32, RF32 src) {
  return CheckedCast<float32_t, int32_t>(Read(src));
}

// FCVTZS  <Wd>, <Dn>
DEF_SEM_U32(FCVTZS_Float64ToSInt32, RF64 src) {
  return CheckedCast<float64_t, int32_t>(Read(src));
}

// FCVTZS  <Xd>, <Dn>
DEF_SEM_U64(FCVTZS_Float64ToSInt64, RF64 src) {
  return CheckedCast<float64_t, int64_t>(Read(src));
}

// FCVTAS  <Xd>, <Dn>
// (FIXME) not using rounding to nearest with ties to Away
DEF_SEM_U64(FCVTAS_Float64ToSInt64, RF64 src) {
  return CheckedCast<float64_t, int64_t>(Read(src));
}

// FCVT  <Dd>, <Sn>
DEF_SEM_F64(FCVT_Float32ToFloat64, RF32 src) {
  return CheckedCast<float32_t, float64_t>(Read(src));
}

// FCVT  <Sd>, <Dn>
DEF_SEM_F32(FCVT_Float64ToFloat32, RF64 src) {
  return CheckedCast<float64_t, float32_t>(Read(src));
}

// FRINTA  <Dd>, <Dn>
// (FIXME) not using rounding to nearest with ties to Away
DEF_SEM_F64(FRINTA_Float64ToSInt64, RF64 src) {
  return CheckedCast<int64_t, float64_t>(CheckedCast<float64_t, int64_t>(Read(src)));
}

}  // namespace

// TODO(pag): UCVTF_H32_FLOAT2INT.
// TODO(pag): UCVTF_H64_FLOAT2INT.

DEF_ISEL(UCVTF_S32_FLOAT2INT) = UCVTF_UIntToFloat<float32_t, R32, uint32_t>;  // UCVTF  <Sd>, <Wn>
DEF_ISEL(UCVTF_D32_FLOAT2INT) = UCVTF_UIntToFloat<float64_t, R32, uint32_t>;  // UCVTF  <Dd>, <Wn>
DEF_ISEL(UCVTF_S64_FLOAT2INT) = UCVTF_UIntToFloat<float32_t, R64, uint64_t>;  // UCVTF  <Sd>, <Xn>
DEF_ISEL(UCVTF_D64_FLOAT2INT) = UCVTF_UIntToFloat<float64_t, R64, uint64_t>;  // UCVTF  <Dd>, <Xn>

DEF_ISEL(UCVTF_ASISDMISC_R_32) = UCVTF_Uint32ToFloat32_FROMV;  // UCVTF  <V><d>, <V><n>
DEF_ISEL(UCVTF_ASISDMISC_R_64) = UCVTF_Uint64ToFloat64_FROMV;  // UCVTF  <V><d>, <V><n>

DEF_ISEL(FCVTZU_64S_FLOAT2INT) =
    FCVTZU_FloatToUInt<uint64_t, RF32, float32_t>;  // FCVTZU  <Xd>, <Sn>
DEF_ISEL(FCVTZU_32S_FLOAT2INT) =
    FCVTZU_FloatToUInt<uint32_t, RF32, float32_t>;  // FCVTZU  <Wd>, <Dn>
DEF_ISEL(FCVTZU_32D_FLOAT2INT) =
    FCVTZU_FloatToUInt<uint32_t, RF64, float64_t>;  // FCVTZU  <Wd>, <Dn>
DEF_ISEL(FCVTZU_64D_FLOAT2INT) =
    FCVTZU_FloatToUInt<uint64_t, RF64, float64_t>;  // FCVTZU  <Xd>, <Dn>

DEF_ISEL(FCVTZS_32S_FLOAT2INT) = FCVTZS_Float32ToSInt32;  // FCVTZS  <Wd>, <Sn>
DEF_ISEL(FCVTZS_32D_FLOAT2INT) = FCVTZS_Float64ToSInt32;  // FCVTZS  <Wd>, <Dn>
DEF_ISEL(FCVTZS_64D_FLOAT2INT) = FCVTZS_Float64ToSInt64;  // FCVTZS  <Xd>, <Dn>

DEF_ISEL(FCVTAS_64D_FLOAT2INT) = FCVTAS_Float64ToSInt64;  // FCVTAS  <Xd>, <Dn>

DEF_ISEL(FCVT_DS_FLOATDP1) = FCVT_Float32ToFloat64;  // FCVT  <Dd>, <Sn>
DEF_ISEL(FCVT_SD_FLOATDP1) = FCVT_Float64ToFloat32;  // FCVT  <Sd>, <Dn>

DEF_ISEL(FRINTA_D_FLOATDP1) = FRINTA_Float64ToSInt64;  // FRINTA  <Dd>, <Dn>

namespace {

// SCVTF  <Sd>, <Wn>
template <typename DB, typename S, typename SB>
DEF_SEM_T(SCVTF_IntToFloat, S src) {
  return CheckedCast<SB, DB>(Signed(Read(src)));
}

// SCVTF  <V><d>, <V><n>
DEF_SEM_T(SCVTF_Int32ToFloat32_FROMV, VI128 src) {
  _ecv_f32v4_t res = {};
  _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(res); i++) {
    res[i] = CheckedCast<int32_t, float32_t>(SExtractVI32(SReadVI32(src), i));
  }
  return res;
}

// SCVTF  <V><d>, <V><n>
DEF_SEM_T(SCVTF_Int64ToFloat64_FROMV, VI128 src) {
  _ecv_f64v2_t res = {};
  _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(res); i++) {
    res[i] = CheckedCast<int64_t, float64_t>(SExtractVI64(SReadVI64(src), i));
  }
  return res;
}

}  // namespace

// TODO(pag): SCVTF_H32_FLOAT2INT.
// TODO(pag): SCVTF_H64_FLOAT2INT.

DEF_ISEL(SCVTF_S32_FLOAT2INT) = SCVTF_IntToFloat<float32_t, R32, int32_t>;  // SCVTF  <Sd>, <Wn>
DEF_ISEL(SCVTF_D32_FLOAT2INT) = SCVTF_IntToFloat<float64_t, R32, int32_t>;  // SCVTF  <Dd>, <Wn>
DEF_ISEL(SCVTF_S64_FLOAT2INT) = SCVTF_IntToFloat<float32_t, R64, int64_t>;  // SCVTF  <Sd>, <Xn>
DEF_ISEL(SCVTF_D64_FLOAT2INT) = SCVTF_IntToFloat<float64_t, R64, int64_t>;  // SCVTF  <Dd>, <Xn>

DEF_ISEL(SCVTF_ASISDMISC_R_32) = SCVTF_Int32ToFloat32_FROMV;  // SCVTF  <V><d>, <V><n>
DEF_ISEL(SCVTF_ASISDMISC_R_64) = SCVTF_Int64ToFloat64_FROMV;  // SCVTF  <V><d>, <V><n>
