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
#include "remill/Arch/AArch64/Runtime/AArch64Definitions.h"
#include "remill/Arch/AArch64/Runtime/Operators.h"
#include "remill/Arch/AArch64/Runtime/State.h"
#include "remill/Arch/AArch64/Runtime/Types.h"
#include "remill/Arch/Name.h"
#include "remill/Arch/Runtime/Float.h"
#include "remill/Arch/Runtime/Intrinsics.h"
#include "remill/Arch/Runtime/Math.h"
#include "remill/Arch/Runtime/Operators.h"
#include "remill/Arch/Runtime/Types.h"

#include <cstdint>
#include <math.h>

namespace {

template <typename S, typename D>
ALWAYS_INLINE static D CheckedCastFPSRStatus(State &state, S src) {
  return CheckedFloatUnaryOp(
      state, [](S v) { return static_cast<D>(v); }, src);
}

template <typename S, typename D>
ALWAYS_INLINE static D CheckedCast(State &state, S src) {
  return static_cast<D>(src);
}

// UCVTF  <Sd>, <Wn>
template <typename SB, typename S, typename DB>
DEF_SEM_T_STATE(UCVTF_UIntToFloat, S src) {
  return CheckedCast<SB, DB>(state, Read(src));
}
// FPSR
template <typename SB, typename S, typename DB>
DEF_SEM_T_STATE(UCVTF_UIntToFloat_FPSRStatus, S src) {
  return CheckedCastFPSRStatus<SB, DB>(state, Read(src));
}

// UCVTF  <V><d>, <V><n>
DEF_SEM_T_STATE(UCVTF_Uint32ToFloat32_FROMV, VIu32v4 src) {
  _ecv_f32v4_t res = {};
  auto elems_num = GetVectorElemsNum(res);
  _Pragma("unroll") for (size_t i = 0; i < elems_num; i++) {
    res[i] = CheckedCast<uint32_t, float32_t>(state, UExtractVI32(UReadVI32(src), i));
  }
  return res;
}
// FPSR
DEF_SEM_T_STATE(UCVTF_Uint32ToFloat32_FROMV_FPSRStatus, VIu32v4 src) {
  _ecv_f32v4_t res = {};
  auto elems_num = GetVectorElemsNum(res);
  _Pragma("unroll") for (size_t i = 0; i < elems_num; i++) {
    res[i] = CheckedCastFPSRStatus<uint32_t, float32_t>(state, UExtractVI32(UReadVI32(src), i));
  }
  return res;
}

// UCVTF  <V><d>, <V><n>
DEF_SEM_T_STATE(UCVTF_Uint64ToFloat64_FROMV, VIu64v2 src) {
  _ecv_f64v2_t res = {};
  auto elems_num = GetVectorElemsNum(res);
  _Pragma("unroll") for (size_t i = 0; i < elems_num; i++) {
    res[i] = CheckedCast<uint64_t, float64_t>(state, UExtractVI64(UReadVI64(src), i));
  }
  return res;
}
// FPSR
DEF_SEM_T_STATE(UCVTF_Uint64ToFloat64_FROMV_FPSRStatus, VIu64v2 src) {
  _ecv_f64v2_t res = {};
  auto elems_num = GetVectorElemsNum(res);
  _Pragma("unroll") for (size_t i = 0; i < elems_num; i++) {
    res[i] = CheckedCastFPSRStatus<uint64_t, float64_t>(state, UExtractVI64(UReadVI64(src), i));
  }
  return res;
}

// UCVTF  <Vd>.<T>, <Vn>.<T>
#define MAKE_UCVTF_VECTOR(elem_size) \
  template <typename S> \
  DEF_SEM_T_STATE(UCVTF_Vector_##elem_size, S srcn) { \
    S res{}; \
    auto srcn_v = UReadVI##elem_size(srcn); \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(srcn); i++) { \
      res[i] = CheckedCast<uint##elem_size##_t, float##elem_size##_t>(state, srcn_v[i]); \
    } \
    return res; \
  } \
  template <typename S> \
  DEF_SEM_T_STATE(UCVTF_Vector_FPSRStatus_##elem_size, S srcn) { \
    S res{}; \
    auto srcn_v = UReadVI##elem_size(srcn); \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(srcn); i++) { \
      res[i] = CheckedCastFPSRStatus<uint##elem_size##_t, float##elem_size##_t>(state, srcn_v[i]); \
    } \
    return res; \
  }

MAKE_UCVTF_VECTOR(32)
MAKE_UCVTF_VECTOR(64)

#undef MAKE_UCVTF_VECTOR

// FCVTZU  <Xd>, <Sn>
template <typename SB, typename S, typename DB>
DEF_SEM_T_STATE(FCVTZU_FloatToUInt, S src) {
  return CheckedCast<SB, DB>(state, Read(src));
}
// FPSR
template <typename SB, typename S, typename DB>
DEF_SEM_T_STATE(FCVTZU_FloatToUInt_FPSRStatus, S src) {
  return CheckedCastFPSRStatus<SB, DB>(state, Read(src));
}

// FCVTZS  <Wd>, <Sn>
DEF_SEM_U32_STATE(FCVTZS_Float32ToSInt32, RF32 src) {
  return CheckedCast<float32_t, int32_t>(state, Read(src));
}
// FPSR
DEF_SEM_U32_STATE(FCVTZS_Float32ToSInt32_FPSRStatus, RF32 src) {
  return CheckedCastFPSRStatus<float32_t, int32_t>(state, Read(src));
}

// FCVTZS  <Xd>, <Sn>
DEF_SEM_U32_STATE(FCVTZS_Float32ToSInt64, RF32 src) {
  return CheckedCast<float64_t, int32_t>(state, Read(src));
}
// FPSR
DEF_SEM_U32_STATE(FCVTZS_Float32ToSInt64_FPSRStatus, RF32 src) {
  return CheckedCastFPSRStatus<float64_t, int32_t>(state, Read(src));
}

// FCVTZS  <Wd>, <Dn>
DEF_SEM_U32_STATE(FCVTZS_Float64ToSInt32, RF64 src) {
  return CheckedCast<float64_t, int32_t>(state, Read(src));
}
// FPSR
DEF_SEM_U32_STATE(FCVTZS_Float64ToSInt32_FPSRStatus, RF64 src) {
  return CheckedCastFPSRStatus<float64_t, int32_t>(state, Read(src));
}


// FCVTZS  <Xd>, <Dn>
DEF_SEM_U64_STATE(FCVTZS_Float64ToSInt64, RF64 src) {
  return CheckedCast<float64_t, int64_t>(state, Read(src));
}
// FPSR
DEF_SEM_U64_STATE(FCVTZS_Float64ToSInt64_FPSRStatus, RF64 src) {
  return CheckedCastFPSRStatus<float64_t, int64_t>(state, Read(src));
}

// FCVTAS  <Xd>, <Dn>
// (FIXME) not using rounding to nearest with ties to Away
DEF_SEM_U64_STATE(FCVTAS_Float64ToSInt64, RF64 src) {
  return CheckedCast<float64_t, int64_t>(state, Read(src));
}
// FPSR
DEF_SEM_U64_STATE(FCVTAS_Float64ToSInt64_FPSRStatus, RF64 src) {
  return CheckedCastFPSRStatus<float64_t, int64_t>(state, Read(src));
}

// FCVT  <Dd>, <Sn>
DEF_SEM_F64_STATE(FCVT_Float32ToFloat64, RF32 src) {
  return CheckedCast<float32_t, float64_t>(state, Read(src));
}
// FPSR
DEF_SEM_F64_STATE(FCVT_Float32ToFloat64_FPSRStatus, RF32 src) {
  return CheckedCastFPSRStatus<float32_t, float64_t>(state, Read(src));
}

// FCVT  <Sd>, <Dn>
DEF_SEM_F32_STATE(FCVT_Float64ToFloat32, RF64 src) {
  return CheckedCast<float64_t, float32_t>(state, Read(src));
}
// FPSR
DEF_SEM_F32_STATE(FCVT_Float64ToFloat32_FPSRStatus, RF64 src) {
  return CheckedCastFPSRStatus<float64_t, float32_t>(state, Read(src));
}

// FRINTA  <Dd>, <Dn>
// (FIXME) not using rounding to nearest with ties to Away
DEF_SEM_F64_STATE(FRINTA_Float64ToSInt64, RF64 src) {
  return CheckedCast<int64_t, float64_t>(state, CheckedCast<float64_t, int64_t>(state, Read(src)));
}
// FPSR
DEF_SEM_F64_STATE(FRINTA_Float64ToSInt64_FPSRStatus, RF64 src) {
  return CheckedCastFPSRStatus<int64_t, float64_t>(
      state, CheckedCastFPSRStatus<float64_t, int64_t>(state, Read(src)));
}

}  // namespace

// TODO(pag): UCVTF_H32_FLOAT2INT.
// TODO(pag): UCVTF_H64_FLOAT2INT.

DEF_ISEL(UCVTF_S32_FLOAT2INT) = UCVTF_UIntToFloat<R32, uint32_t, float32_t>;  // UCVTF  <Sd>, <Wn>
DEF_ISEL(UCVTF_D32_FLOAT2INT) = UCVTF_UIntToFloat<R32, uint32_t, float64_t>;  // UCVTF  <Dd>, <Wn>
DEF_ISEL(UCVTF_S64_FLOAT2INT) = UCVTF_UIntToFloat<R64, uint64_t, float32_t>;  // UCVTF  <Sd>, <Xn>
DEF_ISEL(UCVTF_D64_FLOAT2INT) = UCVTF_UIntToFloat<R64, uint64_t, float64_t>;  // UCVTF  <Dd>, <Xn>
// FPSR
DEF_ISEL(UCVTF_S32_FLOAT2INT_FPSRSTATUS) =
    UCVTF_UIntToFloat_FPSRStatus<R32, uint32_t, float32_t>;  // UCVTF  <Sd>, <Wn>
DEF_ISEL(UCVTF_D32_FLOAT2INT_FPSRSTATUS) =
    UCVTF_UIntToFloat_FPSRStatus<R32, uint32_t, float64_t>;  // UCVTF  <Dd>, <Wn>
DEF_ISEL(UCVTF_S64_FLOAT2INT_FPSRSTATUS) =
    UCVTF_UIntToFloat_FPSRStatus<R64, uint64_t, float32_t>;  // UCVTF  <Sd>, <Xn>
DEF_ISEL(UCVTF_D64_FLOAT2INT_FPSRSTATUS) =
    UCVTF_UIntToFloat_FPSRStatus<R64, uint64_t, float64_t>;  // UCVTF  <Dd>, <Xn>

DEF_ISEL(UCVTF_ASISDMISC_R_32) = UCVTF_Uint32ToFloat32_FROMV;  // UCVTF  <V><d>, <V><n>
DEF_ISEL(UCVTF_ASISDMISC_R_64) = UCVTF_Uint64ToFloat64_FROMV;  // UCVTF  <V><d>, <V><n>
// FPSR
DEF_ISEL(UCVTF_ASISDMISC_R_32_FPSRSTATUS) =
    UCVTF_Uint32ToFloat32_FROMV_FPSRStatus;  // UCVTF  <V><d>, <V><n>
DEF_ISEL(UCVTF_ASISDMISC_R_64_FPSRSTATUS) =
    UCVTF_Uint64ToFloat64_FROMV_FPSRStatus;  // UCVTF  <V><d>, <V><n>

DEF_ISEL(UCVTF_ASIMDMISC_R_2S) = UCVTF_Vector_32<VIu32v2>;  // UCVTF  <Vd>.<T>, <Vn>.<T>
DEF_ISEL(UCVTF_ASIMDMISC_R_4S) = UCVTF_Vector_32<VIu32v4>;  // UCVTF  <Vd>.<T>, <Vn>.<T>
DEF_ISEL(UCVTF_ASIMDMISC_R_2D) = UCVTF_Vector_64<VIu64v2>;  // UCVTF  <Vd>.<T>, <Vn>.<T>
// FPSR
DEF_ISEL(UCVTF_ASIMDMISC_R_2S_FPSRSTATUS) =
    UCVTF_Vector_FPSRStatus_32<VIu32v2>;  // UCVTF  <Vd>.<T>, <Vn>.<T>
DEF_ISEL(UCVTF_ASIMDMISC_R_4S_FPSRSTATUS) =
    UCVTF_Vector_FPSRStatus_32<VIu32v4>;  // UCVTF  <Vd>.<T>, <Vn>.<T>
DEF_ISEL(UCVTF_ASIMDMISC_R_2D_FPSRSTATUS) =
    UCVTF_Vector_FPSRStatus_64<VIu64v2>;  // UCVTF  <Vd>.<T>, <Vn>.<T>

DEF_ISEL(FCVTZU_64S_FLOAT2INT) =
    FCVTZU_FloatToUInt<RF32, float32_t, uint64_t>;  // FCVTZU  <Xd>, <Sn>
DEF_ISEL(FCVTZU_32S_FLOAT2INT) =
    FCVTZU_FloatToUInt<RF32, float32_t, uint32_t>;  // FCVTZU  <Wd>, <Dn>
DEF_ISEL(FCVTZU_32D_FLOAT2INT) =
    FCVTZU_FloatToUInt<RF64, float64_t, uint32_t>;  // FCVTZU  <Wd>, <Dn>
DEF_ISEL(FCVTZU_64D_FLOAT2INT) =
    FCVTZU_FloatToUInt<RF64, float64_t, uint64_t>;  // FCVTZU  <Xd>, <Dn>
// FPSR
DEF_ISEL(FCVTZU_64S_FLOAT2INT_FPSRSTATUS) =
    FCVTZU_FloatToUInt_FPSRStatus<RF32, float32_t, uint64_t>;  // FCVTZU  <Xd>, <Sn>
DEF_ISEL(FCVTZU_32S_FLOAT2INT_FPSRSTATUS) =
    FCVTZU_FloatToUInt_FPSRStatus<RF32, float32_t, uint32_t>;  // FCVTZU  <Wd>, <Dn>
DEF_ISEL(FCVTZU_32D_FLOAT2INT_FPSRSTATUS) =
    FCVTZU_FloatToUInt_FPSRStatus<RF64, float64_t, uint32_t>;  // FCVTZU  <Wd>, <Dn>
DEF_ISEL(FCVTZU_64D_FLOAT2INT_FPSRSTATUS) =
    FCVTZU_FloatToUInt_FPSRStatus<RF64, float64_t, uint64_t>;  // FCVTZU  <Xd>, <Dn>

DEF_ISEL(FCVTZS_32S_FLOAT2INT) = FCVTZS_Float32ToSInt32;  // FCVTZS  <Wd>, <Sn>
DEF_ISEL(FCVTZS_64S_FLOAT2INT) = FCVTZS_Float32ToSInt64;  // FCVTZS  <Wd>, <Sn>
DEF_ISEL(FCVTZS_32D_FLOAT2INT) = FCVTZS_Float64ToSInt32;  // FCVTZS  <Wd>, <Dn>
DEF_ISEL(FCVTZS_64D_FLOAT2INT) = FCVTZS_Float64ToSInt64;  // FCVTZS  <Xd>, <Dn>
// FPSR
DEF_ISEL(FCVTZS_32S_FLOAT2INT_FPSRSTATUS) =
    FCVTZS_Float32ToSInt32_FPSRStatus;  // FCVTZS  <Wd>, <Sn>
DEF_ISEL(FCVTZS_64S_FLOAT2INT_FPSRSTATUS) =
    FCVTZS_Float32ToSInt64_FPSRStatus;  // FCVTZS  <Xd>, <Sn>
DEF_ISEL(FCVTZS_32D_FLOAT2INT_FPSRSTATUS) =
    FCVTZS_Float64ToSInt32_FPSRStatus;  // FCVTZS  <Wd>, <Dn>
DEF_ISEL(FCVTZS_64D_FLOAT2INT_FPSRSTATUS) =
    FCVTZS_Float64ToSInt64_FPSRStatus;  // FCVTZS  <Xd>, <Dn>

DEF_ISEL(FCVTAS_64D_FLOAT2INT) = FCVTAS_Float64ToSInt64;  // FCVTAS  <Xd>, <Dn>
// FPSR
DEF_ISEL(FCVTAS_64D_FLOAT2INT_FPSRSTATUS) =
    FCVTAS_Float64ToSInt64_FPSRStatus;  // FCVTAS  <Xd>, <Dn>

DEF_ISEL(FCVT_DS_FLOATDP1) = FCVT_Float32ToFloat64;  // FCVT  <Dd>, <Sn>
DEF_ISEL(FCVT_SD_FLOATDP1) = FCVT_Float64ToFloat32;  // FCVT  <Sd>, <Dn>
// FPSR
DEF_ISEL(FCVT_DS_FLOATDP1_FPSRSTATUS) = FCVT_Float32ToFloat64_FPSRStatus;  // FCVT  <Dd>, <Sn>
DEF_ISEL(FCVT_SD_FLOATDP1_FPSRSTATUS) = FCVT_Float64ToFloat32_FPSRStatus;  // FCVT  <Sd>, <Dn>

DEF_ISEL(FRINTA_D_FLOATDP1) = FRINTA_Float64ToSInt64;  // FRINTA  <Dd>, <Dn>
// FPSR
DEF_ISEL(FRINTA_D_FLOATDP1_FPSRSTATUS) = FRINTA_Float64ToSInt64_FPSRStatus;  // FRINTA  <Dd>, <Dn>

namespace {

// SCVTF  <Sd>, <Wn>
template <typename DB, typename S, typename SB>
DEF_SEM_T_STATE(SCVTF_IntToFloat, S src) {
  return CheckedCast<SB, DB>(state, Signed(Read(src)));
}
// FPSR
template <typename DB, typename S, typename SB>
DEF_SEM_T_STATE(SCVTF_IntToFloat_FPSRStatus, S src) {
  return CheckedCastFPSRStatus<SB, DB>(state, Signed(Read(src)));
}

// SCVTF  <V><d>, <V><n>
DEF_SEM_T_STATE(SCVTF_Int32ToFloat32_FROMV, VIi32v4 src) {
  _ecv_f32v4_t res = {};
  _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(res); i++) {
    res[i] = CheckedCast<int32_t, float32_t>(state, SExtractVI32(SReadVI32(src), i));
  }
  return res;
}
// FPSR
DEF_SEM_T_STATE(SCVTF_Int32ToFloat32_FROMV_FPSRStatus, VIi32v4 src) {
  _ecv_f32v4_t res = {};
  _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(res); i++) {
    res[i] = CheckedCastFPSRStatus<int32_t, float32_t>(state, SExtractVI32(SReadVI32(src), i));
  }
  return res;
}

// SCVTF  <V><d>, <V><n>
DEF_SEM_T_STATE(SCVTF_Int64ToFloat64_FROMV, VIi64v2 src) {
  _ecv_f64v2_t res = {};
  _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(res); i++) {
    res[i] = CheckedCast<int64_t, float64_t>(state, SExtractVI64(SReadVI64(src), i));
  }
  return res;
}
// FPSR
DEF_SEM_T_STATE(SCVTF_Int64ToFloat64_FROMV_FPSRStatus, VIi64v2 src) {
  _ecv_f64v2_t res = {};
  _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(res); i++) {
    res[i] = CheckedCastFPSRStatus<int64_t, float64_t>(state, SExtractVI64(SReadVI64(src), i));
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
// FPSR
DEF_ISEL(SCVTF_S32_FLOAT2INT_FPSRSTATUS) =
    SCVTF_IntToFloat_FPSRStatus<float32_t, R32, int32_t>;  // SCVTF  <Sd>, <Wn>
DEF_ISEL(SCVTF_D32_FLOAT2INT_FPSRSTATUS) =
    SCVTF_IntToFloat_FPSRStatus<float64_t, R32, int32_t>;  // SCVTF  <Dd>, <Wn>
DEF_ISEL(SCVTF_S64_FLOAT2INT_FPSRSTATUS) =
    SCVTF_IntToFloat_FPSRStatus<float32_t, R64, int64_t>;  // SCVTF  <Sd>, <Xn>
DEF_ISEL(SCVTF_D64_FLOAT2INT_FPSRSTATUS) =
    SCVTF_IntToFloat_FPSRStatus<float64_t, R64, int64_t>;  // SCVTF  <Dd>, <Xn>

DEF_ISEL(SCVTF_ASISDMISC_R_32) = SCVTF_Int32ToFloat32_FROMV;  // SCVTF  <V><d>, <V><n>
DEF_ISEL(SCVTF_ASISDMISC_R_64) = SCVTF_Int64ToFloat64_FROMV;  // SCVTF  <V><d>, <V><n>
// FPSR
DEF_ISEL(SCVTF_ASISDMISC_R_32_FPSRSTATUS) =
    SCVTF_Int32ToFloat32_FROMV_FPSRStatus;  // SCVTF  <V><d>, <V><n>
DEF_ISEL(SCVTF_ASISDMISC_R_64_FPSRSTATUS) =
    SCVTF_Int64ToFloat64_FROMV_FPSRStatus;  // SCVTF  <V><d>, <V><n>

// FSQRT  <Sd>, <Sn>
// FSQRT  <Dd>, <Dn>
namespace {
DEF_SEM_F32(FSQRT_32, RF32 src) {
  return sqrt(Read(src));
}
DEF_SEM_F64(FSQRT_64, RF64 src) {
  return sqrt(Read(src));
}
}  // namespace

// DEF_ISEL(FSQRT_H_FLOATDP1) = FSQRT_16;
DEF_ISEL(FSQRT_S_FLOATDP1) = FSQRT_32;
DEF_ISEL(FSQRT_D_FLOATDP1) = FSQRT_64;
