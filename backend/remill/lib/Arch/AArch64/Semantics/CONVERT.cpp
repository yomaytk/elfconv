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
ALWAYS_INLINE static D CheckedCast(State &state, S src) {
  return CheckedFloatUnaryOp(state, [](S v) { return static_cast<D>(v); }, src);
}

template <typename D, typename DB, typename S, typename SB>
DEF_SEM_V128_STATE(UCVTF_UIntToFloat, D dst, S src) {
  DB res = CheckedCast<SB, DB>(state, Read(src));
  return BackTo128Vector(res, 0);
}

DEF_SEM_V128_STATE(UCVTF_Uint32ToFloat32_FROMV, VI32 src) {
  _ecv_f32v4_t res = {};
  auto elems_num = GetVectorElemsNum(src);
  _Pragma("unroll") for (size_t i = 0; i < elems_num; i++) {
    res[i] = CheckedCast<uint32_t, float32_t>(state, UExtractVI32(src, i));
  }
  return res;
}

DEF_SEM_V128_STATE(UCVTF_Uint64ToFloat64_FROMV, VI64 src) {
  _ecv_f64v2_t res = {};
  auto elems_num = GetVectorElemsNum(src);
  _Pragma("unroll") for (size_t i = 0; i < elems_num; i++) {
    res[i] = CheckedCast<uint64_t, float64_t>(state, UExtractVI64(src, i));
  }
  return res;
}

template <typename DB, typename S, typename SB>
DEF_SEM_U64_STATE(FCVTZU_FloatToUInt, S src) {
  SB float_val = FExtractVI32(src, 0);
  return CheckedCast<SB, DB>(state, float_val);
}

DEF_SEM_I64_STATE(FCVTZS_Float32ToSInt32, VI32 src) {
  auto float_val = FExtractVI32(src, 0);
  auto res = CheckedCast<float32_t, int32_t>(state, float_val);
  return SExtTo<int64_t>(res);
}

DEF_SEM_I64_STATE(FCVTZS_Float64ToSInt32, VI64 src) {
  auto float_val = FExtractVI64(src, 0);
  auto res = CheckedCast<float64_t, int32_t>(state, float_val);
  return SExtTo<int64_t>(res);
}

DEF_SEM_I64_STATE(FCVTZS_Float64ToSInt64, VI64 src) {
  auto float_val = FExtractVI64(src, 0);
  auto res = CheckedCast<float64_t, int64_t>(state, float_val);
  return SExtTo<int64_t>(res);
}

// FCVTAS  <Xd>, <Dn>
// (FIXME) not using rounding to nearest with ties to Away
DEF_SEM_I64_STATE(FCVTAS_Float64ToSInt64, VI64 src) {
  auto float_val = FExtractVI64(src, 0);
  auto res = CheckedCast<float64_t, int64_t>(state, float_val);
  return SExtTo<int64_t>(res);
}

DEF_SEM_V128_STATE(FCVT_Float32ToFloat64, VI64 dst, VI32 src) {
  auto float_val = FExtractVI32(src, 0);
  auto res = CheckedCast<float32_t, float64_t>(state, float_val);
  return BackTo128Vector(res, 0);
}

DEF_SEM_V128_STATE(FCVT_Float64ToFloat32, VI64 dst, VI64 src) {
  auto float_val = FExtractVI64(src, 0);
  auto res = CheckedCast<float64_t, float32_t>(state, float_val);
  return BackTo128Vector(res, 0);
}

// FRINTA  <Dd>, <Dn>
// (FIXME) not using rounding to nearest with ties to Away
DEF_SEM_V128_STATE(FRINTA_Float64ToSInt64, VI64 dst, VI64 src) {
  auto float_val = FExtractVI64(src, 0);
  auto res =
      CheckedCast<int64_t, float64_t>(state, CheckedCast<float64_t, int64_t>(state, float_val));
  return BackTo128Vector(res, 0);
}

}  // namespace

// TODO(pag): UCVTF_H32_FLOAT2INT.
// TODO(pag): UCVTF_H64_FLOAT2INT.

DEF_ISEL(UCVTF_S32_FLOAT2INT) = UCVTF_UIntToFloat<VI32, float32_t, R32, uint32_t>;
DEF_ISEL(UCVTF_D32_FLOAT2INT) = UCVTF_UIntToFloat<VI64, float64_t, R32, uint32_t>;
DEF_ISEL(UCVTF_S64_FLOAT2INT) = UCVTF_UIntToFloat<VI32, float32_t, R64, uint64_t>;
DEF_ISEL(UCVTF_D64_FLOAT2INT) = UCVTF_UIntToFloat<VI64, float64_t, R64, uint64_t>;

DEF_ISEL(UCVTF_ASISDMISC_R_32) = UCVTF_Uint32ToFloat32_FROMV;
DEF_ISEL(UCVTF_ASISDMISC_R_64) = UCVTF_Uint64ToFloat64_FROMV;

DEF_ISEL(FCVTZU_64S_FLOAT2INT) = FCVTZU_FloatToUInt<uint64_t, VI32, float32_t>;
DEF_ISEL(FCVTZU_32S_FLOAT2INT) = FCVTZU_FloatToUInt<uint32_t, VI32, float32_t>;
DEF_ISEL(FCVTZU_32D_FLOAT2INT) = FCVTZU_FloatToUInt<uint32_t, VI64, float64_t>;
DEF_ISEL(FCVTZU_64D_FLOAT2INT) = FCVTZU_FloatToUInt<uint64_t, VI64, float64_t>;

DEF_ISEL(FCVTZS_32S_FLOAT2INT) = FCVTZS_Float32ToSInt32;
DEF_ISEL(FCVTZS_32D_FLOAT2INT) = FCVTZS_Float64ToSInt32;
DEF_ISEL(FCVTZS_64D_FLOAT2INT) = FCVTZS_Float64ToSInt64;

DEF_ISEL(FCVTAS_64D_FLOAT2INT) = FCVTAS_Float64ToSInt64;

DEF_ISEL(FCVT_DS_FLOATDP1) = FCVT_Float32ToFloat64;
DEF_ISEL(FCVT_SD_FLOATDP1) = FCVT_Float64ToFloat32;

DEF_ISEL(FRINTA_D_FLOATDP1) = FRINTA_Float64ToSInt64;

namespace {

template <typename D, typename DB, typename S, typename SB>
DEF_SEM_V128_STATE(SCVTF_IntToFloat, D dst, S src) {
  auto res = CheckedCast<SB, DB>(state, Signed(Read(src)));
  return BackTo128Vector(res, 0);
}

DEF_SEM_V128_STATE(SCVTF_Int32ToFloat32_FROMV, VI32 src) {
  _ecv_f32v4_t res = {};
  _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(src); i++) {
    res[i] = CheckedCast<int32_t, float32_t>(state, SExtractVI32(src, i));
  }
  return res;
}

DEF_SEM_V128_STATE(SCVTF_Int64ToFloat64_FROMV, VI64 src) {
  _ecv_f64v2_t res = {};
  _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(src); i++) {
    res[i] = CheckedCast<int64_t, float64_t>(state, SExtractVI64(src, i));
  }
  return res;
}

}  // namespace

// TODO(pag): SCVTF_H32_FLOAT2INT.
// TODO(pag): SCVTF_H64_FLOAT2INT.

DEF_ISEL(SCVTF_S32_FLOAT2INT) = SCVTF_IntToFloat<VI32, float32_t, VI32, int32_t>;
DEF_ISEL(SCVTF_D32_FLOAT2INT) = SCVTF_IntToFloat<VI64, float64_t, VI32, int32_t>;
DEF_ISEL(SCVTF_S64_FLOAT2INT) = SCVTF_IntToFloat<VI32, float32_t, VI64, int64_t>;
DEF_ISEL(SCVTF_D64_FLOAT2INT) = SCVTF_IntToFloat<VI64, float64_t, VI64, int64_t>;

DEF_ISEL(SCVTF_ASISDMISC_R_32) = SCVTF_Int32ToFloat32_FROMV;
DEF_ISEL(SCVTF_ASISDMISC_R_64) = SCVTF_Int64ToFloat64_FROMV;
