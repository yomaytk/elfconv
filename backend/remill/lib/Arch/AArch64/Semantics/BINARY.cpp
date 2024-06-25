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

#include <cassert>

namespace {

template <typename S1, typename S2>
DEF_SEM_U64(SUB, S1 src1, S2 src2) {
  return ZExtTo<R64>(USub(Read(src1), Read(src2)));
}

template <typename S1, typename S2>
DEF_SEM_U64(ADD, S1 src1, S2 src2) {
  return ZExtTo<R64>(UAdd(Read(src1), Read(src2)));
}

}  // namespace

DEF_ISEL(ADD_32_ADDSUB_IMM) = ADD<R32, I32>;
DEF_ISEL(ADD_64_ADDSUB_IMM) = ADD<R64, I64>;
DEF_ISEL(ADD_32_ADDSUB_SHIFT) = ADD<R32, I32>;
DEF_ISEL(ADD_64_ADDSUB_SHIFT) = ADD<R64, I64>;
DEF_ISEL(ADD_32_ADDSUB_EXT) = ADD<R32, I32>;
DEF_ISEL(ADD_64_ADDSUB_EXT) = ADD<R64, I64>;

DEF_ISEL(SUB_32_ADDSUB_IMM) = SUB<R32, I32>;
DEF_ISEL(SUB_64_ADDSUB_IMM) = SUB<R64, I64>;
DEF_ISEL(SUB_32_ADDSUB_SHIFT) = SUB<R32, I32>;
DEF_ISEL(SUB_64_ADDSUB_SHIFT) = SUB<R64, I64>;
DEF_ISEL(SUB_32_ADDSUB_EXT) = SUB<R32, I32>;
DEF_ISEL(SUB_64_ADDSUB_EXT) = SUB<R64, I64>;

namespace {

template <typename T>
U64U64 AddWithCarryNZCV(T lhs, T rhs, T actual_rhs, T carry) {
  auto unsigned_result = UAdd(UAdd(ZExt(lhs), ZExt(rhs)), ZExt(carry));
  auto signed_result = SAdd(SAdd(SExt(lhs), SExt(rhs)), Signed(ZExt(carry)));
  auto result = TruncTo<T>(unsigned_result);
  uint64_t flag_n = ZExtTo<uint64_t>(SignFlag(result, lhs, actual_rhs));
  uint64_t flag_z = ZExtTo<uint64_t>(ZeroFlag(result, lhs, actual_rhs));
  uint64_t flag_c = ZExtTo<uint64_t>(UCmpNeq(ZExt(result), unsigned_result));
  uint64_t flag_v = ZExtTo<uint64_t>(__remill_flag_computation_overflow(
      SCmpNeq(SExt(result), signed_result), lhs, actual_rhs, result));
  uint64_t flag_nzcv = uint64_t(flag_n << 3 | flag_z << 2 | flag_c << 1 | flag_v);
  return {static_cast<uint64_t>(result), flag_nzcv};
}

template <typename S1, typename S2>
DEF_SEM_U64U64(SUBS, S1 src1, S2 src2) {
  using T = typename BaseType<S2>::BT;
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  return AddWithCarryNZCV(lhs, UNot(rhs), rhs, T(1));
}

template <typename S1, typename S2>
DEF_SEM_U64U64(ADDS, S1 src1, S2 src2) {
  using T = typename BaseType<S2>::BT;
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  return AddWithCarryNZCV(lhs, rhs, rhs, T(0));
}

}  // namespace

DEF_ISEL(SUBS_32_ADDSUB_SHIFT) = SUBS<R32, I32>;
DEF_ISEL(SUBS_64_ADDSUB_SHIFT) = SUBS<R64, I64>;
DEF_ISEL(SUBS_32S_ADDSUB_IMM) = SUBS<R32, I32>;
DEF_ISEL(SUBS_64S_ADDSUB_IMM) = SUBS<R64, I64>;
DEF_ISEL(SUBS_32S_ADDSUB_EXT) = SUBS<R32, I32>;
DEF_ISEL(SUBS_64S_ADDSUB_EXT) = SUBS<R64, I64>;

DEF_ISEL(ADDS_32_ADDSUB_SHIFT) = ADDS<R32, I32>;
DEF_ISEL(ADDS_64_ADDSUB_SHIFT) = ADDS<R64, I64>;
DEF_ISEL(ADDS_32S_ADDSUB_IMM) = ADDS<R32, I32>;
DEF_ISEL(ADDS_64S_ADDSUB_IMM) = ADDS<R64, I64>;
DEF_ISEL(ADDS_32S_ADDSUB_EXT) = ADDS<R32, I32>;
DEF_ISEL(ADDS_64S_ADDSUB_EXT) = ADDS<R64, I64>;

namespace {

DEF_SEM_U64(UMADDL, R32 src1, R32 src2, R64 src3) {
  return UAdd(Read(src3), UMul(ZExt(Read(src1)), ZExt(Read(src2))));
}

DEF_SEM_U64(UMSUBL, R32 src1, R32 src2, R64 src3) {
  return USub(Read(src3), UMul(ZExt(Read(src1)), ZExt(Read(src2))));
}

DEF_SEM_U64(SMADDL, R32 src1, R32 src2, R64 src3) {
  auto operand1 = SExt(Signed(Read(src1)));
  auto operand2 = SExt(Signed(Read(src2)));
  auto operand3 = Signed(Read(src3));
  return Unsigned(SAdd(operand3, SMul(operand1, operand2)));
}

DEF_SEM_U64(UMULH, R64 src1, R64 src2) {
  uint128_t lhs = ZExt(Read(src1));
  uint128_t rhs = ZExt(Read(src2));
  uint128_t res = UMul(lhs, rhs);
  return Trunc(UShr(res, 64));
}

DEF_SEM_U64(SMULH, R64 src1, R64 src2) {
  int128_t lhs = SExt(Signed(Read(src1)));
  int128_t rhs = SExt(Signed(Read(src2)));
  uint128_t res = Unsigned(SMul(lhs, rhs));
  return Trunc(UShr(res, 64));
}

template <typename RT>
DEF_SEM_U64(UDIV, RT src1, RT src2) {
  using T = typename BaseType<RT>::BT;
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  if (!rhs) {
    return T(0);
  } else {
    return UDiv(lhs, rhs);
  }
}

template <typename RT>
DEF_SEM_I64(SDIV, RT src1, RT src2) {
  using T = typename BaseType<RT>::BT;
  auto lhs = Signed(Read(src1));
  auto rhs = Signed(Read(src2));
  if (!rhs) {
    return T(0);
  } else {
    return Unsigned(SDiv(lhs, rhs));
  }
}

template <typename RT>
DEF_SEM_U64(MADD, RT src1, RT src2, RT src3) {
  return UAdd(Read(src3), UMul(Read(src1), Read(src2)));
}

template <typename RT>
DEF_SEM_U64(MSUB, RT src1, RT src2, RT src3) {
  return USub(Read(src3), UMul(Read(src1), Read(src2)));
}

}  // namespace

DEF_ISEL(UMADDL_64WA_DP_3SRC) = UMADDL;
DEF_ISEL(SMADDL_64WA_DP_3SRC) = SMADDL;

DEF_ISEL(UMSUBL_64WA_DP_3SRC) = UMSUBL;

DEF_ISEL(UMULH_64_DP_3SRC) = UMULH;
DEF_ISEL(SMULH_64_DP_3SRC) = SMULH;

DEF_ISEL(UDIV_32_DP_2SRC) = UDIV<R32>;
DEF_ISEL(UDIV_64_DP_2SRC) = UDIV<R64>;

DEF_ISEL(SDIV_32_DP_2SRC) = SDIV<R32>;
DEF_ISEL(SDIV_64_DP_2SRC) = SDIV<R64>;

DEF_ISEL(MADD_32A_DP_3SRC) = MADD<R32>;
DEF_ISEL(MADD_64A_DP_3SRC) = MADD<R64>;

DEF_ISEL(MSUB_32A_DP_3SRC) = MSUB<R32>;
DEF_ISEL(MSUB_64A_DP_3SRC) = MSUB<R64>;

namespace {


template <typename RT>
DEF_SEM_U64(SBC, RT src1, RT src2, I8 flag_c) {
  auto carry = ZExtTo<R64>(Unsigned(Read(flag_c)));
  return UAdd(UAdd(Read(src1), UNot(Read(src2))), carry);
}

template <typename S>
DEF_SEM_U64U64(SBCS, S src1, S src2, I8 flag_c) {
  auto carry = ZExtTo<R64>(Unsigned(Read(flag_c)));
  return AddWithCarryNZCV(Read(src1), UNot(Read(src2)), Read(src2), carry);
}

template <typename RT>
DEF_SEM_U64(ADC, RT src1, RT src2, I8 flag_c) {
  auto carry = ZExtTo<R64>(Unsigned(Read(flag_c)));
  return UAdd(UAdd(Read(src1), Read(src2)), carry);
}

// template <typename D, typename S>
// DEF_SEM(ADCS, D S src1, S src2) {
//   auto carry = ZExtTo<S>(Unsigned(FLAG_C));
//   auto res =
//       AddWithCarryNZCV(state, Read(src1), Read(src2), Read(src2), carry);
//   WriteZExt(res);
//
// }

}  // namespace

DEF_ISEL(SBC_32_ADDSUB_CARRY) = SBC<R32>;
DEF_ISEL(SBC_64_ADDSUB_CARRY) = SBC<R64>;

DEF_ISEL(SBCS_32_ADDSUB_CARRY) = SBCS<R32>;
DEF_ISEL(SBCS_64_ADDSUB_CARRY) = SBCS<R64>;

DEF_ISEL(ADC_32_ADDSUB_CARRY) = ADC<R32>;
DEF_ISEL(ADC_64_ADDSUB_CARRY) = ADC<R64>;

namespace {

DEF_SEM_V128_STATE(FADD_Scalar32, VI32 src1, VI32 src2) {
  auto val1 = FExtractVI32(src1, 0);
  auto val2 = FExtractVI32(src2, 0);
  return BackTo128Vector(CheckedFloatBinOp(state, FAdd32, val1, val2), 0);
}

DEF_SEM_V128_STATE(FADD_Scalar64, VI64 src1, VI64 src2) {
  auto val1 = FExtractVI64(src1, 0);
  auto val2 = FExtractVI64(src2, 0);
  return BackTo128Vector(CheckedFloatBinOp(state, FAdd64, val1, val2), 0);
}

DEF_SEM_V128_STATE(FSUB_Scalar32, VI32 src1, VI32 src2) {
  auto val1 = FExtractVI32(src1, 0);
  auto val2 = FExtractVI32(src2, 0);
  return BackTo128Vector(CheckedFloatBinOp(state, FSub32, val1, val2), 0);
}

DEF_SEM_V128_STATE(FSUB_Scalar64, VI64 src1, VI64 src2) {
  auto val1 = FExtractVI64(src1, 0);
  auto val2 = FExtractV64(src2, 0);
  return BackTo128Vector(CheckedFloatBinOp(state, FSub64, val1, val2), 0);
}

DEF_SEM_V128_STATE(FMUL_Scalar32, VI32 src1, VI32 src2) {
  auto val1 = FExtractVI32(src1, 0);
  auto val2 = FExtractVI32(src2, 0);
  return BackTo128Vector(CheckedFloatBinOp(state, FMul32, val1, val2), 0);
}

DEF_SEM_V128_STATE(FMUL_Scalar64, VI64 src1, VI64 src2) {
  auto val1 = FExtractVI64(src1, 0);
  auto val2 = FExtractVI64(src2, 0);
  return BackTo128Vector(CheckedFloatBinOp(state, FMul64, val1, val2), 0);
}

DEF_SEM_V128_STATE(FDIV_Scalar32, VI32 src1, VI32 src2) {
  auto val1 = FExtractVI32(src1, 0);
  auto val2 = FExtractVI32(src2, 0);
  return BackTo128Vector(CheckedFloatBinOp(state, FDiv32, val1, val2), 0);
}

DEF_SEM_V128_STATE(FMADD_S, VI32 src1, VI32 src2, VI32 src3) {
  auto factor1 = FExtractVI32(src1, 0);
  auto factor2 = FExtractVI32(src2, 0);
  auto add = FExtractVI32(src3, 0);

  auto old_underflow = state.sr.ufc;

  // auto zero = __remill_fpu_exception_test_and_clear(0, FE_ALL_EXCEPT);
  // BarrierReorder();
  auto prod = FMul32(factor1, factor2);
  // BarrierReorder();
  // auto except_mul = __remill_fpu_exception_test_and_clear(FE_ALL_EXCEPT, zero);
  // BarrierReorder();
  auto res = FAdd32(prod, add);
  // BarrierReorder();
  // auto except_add = __remill_fpu_exception_test_and_clear(FE_ALL_EXCEPT, except_mul);
  // SetFPSRStatusFlags(state, FE_ALL_EXCEPT);

  // Sets underflow for 0x3fffffff, 0x1 but native doesn't.
  if (state.sr.ufc && !old_underflow) {
    if (IsDenormal(factor1) || IsDenormal(factor2) || IsDenormal(add)) {
      state.sr.ufc = old_underflow;
    }
  }

  return BackTo128Vector(res, 0);
}

DEF_SEM_V128_STATE(FMADD_D, VI64 src1, VI64 src2, VI64 src3) {
  auto factor1 = FExtractVI64(src1, 0);
  auto factor2 = FExtractVI64(src2, 0);
  auto add = FExtractVI64(src3, 0);

  auto old_underflow = state.sr.ufc;

  // auto zero = __remill_fpu_exception_test_and_clear(0, FE_ALL_EXCEPT);
  // BarrierReorder();
  auto prod = FMul64(factor1, factor2);
  // BarrierReorder();
  // auto except_mul = __remill_fpu_exception_test_and_clear(FE_ALL_EXCEPT, zero);
  // BarrierReorder();
  auto res = FAdd64(prod, add);
  // BarrierReorder();
  // auto except_add = __remill_fpu_exception_test_and_clear(FE_ALL_EXCEPT, except_mul);
  // SetFPSRStatusFlags(state, FE_ALL_EXCEPT);

  // Sets underflow for test case (0x3fffffffffffffff, 0x1) but native doesn't.
  if (state.sr.ufc && !old_underflow) {
    if (IsDenormal(factor1) || IsDenormal(factor2) || IsDenormal(add)) {
      state.sr.ufc = old_underflow;
    }
  }

  return BackTo128Vector(res, 0);
}

// FMSUB  <Sd>, <Sn>, <Sm>, <Sa>
DEF_SEM_V128_STATE(FMSUB_S, VI32 src1, VI32 src2, VI32 src3) {
  auto factor1 = FExtractVI32(src1, 0);
  auto factor2 = FExtractVI32(src2, 0);
  auto factora = FExtractVI32(src3, 0);

  auto old_underflow = state.sr.ufc;

  // auto zero = __remill_fpu_exception_test_and_clear(0, FE_ALL_EXCEPT);
  // BarrierReorder();
  auto prod = FMul32(factor1, factor2);
  // BarrierReorder();
  // auto except_mul = __remill_fpu_exception_test_and_clear(FE_ALL_EXCEPT, zero);
  // BarrierReorder();
  auto res = FSub32(factora, prod);
  // BarrierReorder();
  // auto except_add = __remill_fpu_exception_test_and_clear(FE_ALL_EXCEPT, except_mul);
  // SetFPSRStatusFlags(state, FE_ALL_EXCEPT);

  // Sets underflow for 0x3fffffff, 0x1 but native doesn't.
  if (state.sr.ufc && !old_underflow) {
    if (IsDenormal(factor1) || IsDenormal(factor2) || IsDenormal(factora)) {
      state.sr.ufc = old_underflow;
    }
  }

  return BackTo128Vector(res, 0);
}

// FMSUB  <Dd>, <Dn>, <Dm>, <Da>
DEF_SEM_V128_STATE(FMSUB_D, VI64 src1, VI64 src2, VI64 src3) {
  auto factor1 = FExtractVI64(src1, 0);
  auto factor2 = FExtractVI64(src2, 0);
  auto factora = FExtractVI64(src3, 0);

  auto old_underflow = state.sr.ufc;

  // auto zero = __remill_fpu_exception_test_and_clear(0, FE_ALL_EXCEPT);
  // BarrierReorder();
  auto prod = FMul64(factor1, factor2);
  // BarrierReorder();
  // auto except_mul = __remill_fpu_exception_test_and_clear(FE_ALL_EXCEPT, zero);
  // BarrierReorder();
  auto res = FSub64(factora, prod);
  // BarrierReorder();
  // auto except_add = __remill_fpu_exception_test_and_clear(FE_ALL_EXCEPT, except_mul);
  // SetFPSRStatusFlags(state, FE_ALL_EXCEPT);

  // Sets underflow for test case (0x3fffffffffffffff, 0x1) but native doesn't.
  if (state.sr.ufc && !old_underflow) {
    if (IsDenormal(factor1) || IsDenormal(factor2) || IsDenormal(factora)) {
      state.sr.ufc = old_underflow;
    }
  }

  return BackTo128Vector(res, 0);
}

DEF_SEM_V128_STATE(FDIV_Scalar64, VI64 src1, VI64 src2) {
  auto val1 = FExtractVI64(src1, 0);
  auto val2 = FExtractVI64(src2, 0);
  return BackTo128Vector(CheckedFloatBinOp(state, FDiv64, val1, val2), 0);
}

template <typename S>
uint64_t FCompare(S val1, S val2, bool signal = true) {

  uint64_t flag_n, flag_z, flag_c, flag_v;

  // Set flags for operand == NAN
  if (std::isnan(val1) || std::isnan(val2)) {

    // result = '0011';
    flag_n = 0;
    flag_z = 0;
    flag_c = 1;
    flag_v = 1;

    if (signal) {
      state.sr.ioc = true;
    }

    // Regular float compare
  } else {
    if (FCmpEq(val1, val2)) {

      // result = '0110';
      flag_n = 0;
      flag_z = 1;
      flag_c = 1;
      flag_v = 0;

    } else if (FCmpLt(val1, val2)) {

      // result = '1000';
      flag_n = 1;
      flag_z = 0;
      flag_c = 0;
      flag_v = 0;

    } else {  // FCmpGt(val1, val2)

      // result = '0010';
      flag_n = 0;
      flag_z = 0;
      flag_c = 1;
      flag_v = 0;
    }
  }

  return uint64_t(flag_n << 3 | flag_z << 2 | flag_c << 1 | flag_v);
}

DEF_SEM_U64(FCMPE_S, VI32 src1, VI32 src2) {
  auto val1 = FExtractVI32(src1, 0);
  auto val2 = FExtractVI32(src2, 0);
  return FCompare(val1, val2);
}

DEF_SEM_U64(FCMPE_SZ, VI32 src1) {
  auto val1 = FExtractVI32(src1, 0);
  float32_t float_zero = 0.0;
  return FCompare(val1, float_zero);
}

DEF_SEM_U64(FCMP_S, VI32 src1, VI32 src2) {
  auto val1 = FExtractVI32(src1, 0);
  auto val2 = FExtractVI32(src2, 0);
  return FCompare(val1, val2, false);
}

DEF_SEM_U64(FCMP_SZ, VI32 src1) {
  auto val1 = FExtractVI32(src1, 0);
  float32_t float_zero = 0.0;
  return FCompare(val1, float_zero, false);
}

DEF_SEM_U64(FCMPE_D, VI64 src1, VI64 src2) {
  auto val1 = FExtractVI64(src1, 0);
  auto val2 = FExtractVI64(src2, 0);
  return FCompare(val1, val2);
}

DEF_SEM_U64(FCMPE_DZ, VI64 src1) {
  auto val1 = FExtractVI64(src1, 0);
  float64_t float_zero = 0.0;
  return FCompare(val1, float_zero);
}

DEF_SEM_U64(FCMP_D, VI64 src1, VI64 src2) {
  auto val1 = FExtractVI64(src1, 0);
  auto val2 = FExtractVI64(src2, 0);
  return FCompare(val1, val2, false);
}

DEF_SEM_U64(FCMP_DZ, VI64 src1) {
  auto val1 = FExtractVI64(src1, 0);
  float64_t float_zero = 0.0;
  return FCompare(val1, float_zero, false);
}

DEF_SEM_V128(FABS_S, VI32 src) {
  auto val = FExtractVI32(src, 0);
  auto result = static_cast<float32_t>(fabs(val));
  return BackTo128Vector(result, 0);
}

DEF_SEM_V128(FABS_D, VI64 src) {
  auto val = FExtractVI64(src, 0);
  auto result = static_cast<float64_t>(fabs(val));
  return BackTo128Vector(result, 0);
}

DEF_SEM_V128(FNEG_S, VI32 src) {
  auto val = FExtractVI32(src, 0);
  auto result = -val;
  return BackTo128Vector(result, 0);
}

DEF_SEM_V128(FNEG_D, VI64 src) {
  auto val = FExtractVI64(src, 0);
  auto result = -val;
  return BackTo128Vector(result, 0);
}

}  // namespace

DEF_ISEL(FSUB_S_FLOATDP2) = FSUB_Scalar32;
DEF_ISEL(FSUB_D_FLOATDP2) = FSUB_Scalar64;

DEF_ISEL(FADD_S_FLOATDP2) = FADD_Scalar32;
DEF_ISEL(FADD_D_FLOATDP2) = FADD_Scalar64;

DEF_ISEL(FMUL_S_FLOATDP2) = FMUL_Scalar32;
DEF_ISEL(FMUL_D_FLOATDP2) = FMUL_Scalar64;

DEF_ISEL(FMADD_S_FLOATDP3) = FMADD_S;
DEF_ISEL(FMADD_D_FLOATDP3) = FMADD_D;

DEF_ISEL(FMSUB_S_FLOATDP3) = FMSUB_S;
DEF_ISEL(FMSUB_D_FLOATDP3) = FMSUB_D;

DEF_ISEL(FDIV_S_FLOATDP2) = FDIV_Scalar32;
DEF_ISEL(FDIV_D_FLOATDP2) = FDIV_Scalar64;

DEF_ISEL(FABS_S_FLOATDP1) = FABS_S;
DEF_ISEL(FABS_D_FLOATDP1) = FABS_D;

DEF_ISEL(FNEG_S_FLOATDP1) = FNEG_S;
DEF_ISEL(FNEG_D_FLOATDP1) = FNEG_D;

DEF_ISEL(FCMPE_S_FLOATCMP) = FCMPE_S;
DEF_ISEL(FCMPE_SZ_FLOATCMP) = FCMPE_SZ;
DEF_ISEL(FCMP_S_FLOATCMP) = FCMP_S;
DEF_ISEL(FCMP_SZ_FLOATCMP) = FCMP_SZ;

DEF_ISEL(FCMPE_D_FLOATCMP) = FCMPE_D;
DEF_ISEL(FCMPE_DZ_FLOATCMP) = FCMPE_DZ;
DEF_ISEL(FCMP_D_FLOATCMP) = FCMP_D;
DEF_ISEL(FCMP_DZ_FLOATCMP) = FCMP_DZ;
