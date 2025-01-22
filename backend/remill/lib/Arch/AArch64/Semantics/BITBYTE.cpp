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

// The post-decoder handles the rotation of the register using a `ShiftReg`
// operand for `src1`, and combines the `wmask` and `tmask` into a single
// `mask`.

// UBFM  <Wd>, <Wn>, #<immr>, #<imms>
template <typename DT, typename T>
DEF_SEM_T(UBFM, DT src1, T mask) {
  return UAnd(Read(src1), Read(mask));
}

// SBFM  <Wd>, <Wn>, #<immr>, #<imms>
template <typename DT, typename T>
DEF_SEM_T(SBFM, DT src1, T src2, T src3, T src4, T src5) {
  auto src = Read(src1);
  auto R = Read(src2);
  auto S = Read(src3);
  auto wmask = Read(src4);
  auto tmask = Read(src5);

  /* Perform bitfield move on low bits. */
  auto bot = UAnd(Ror(src, R), wmask);

  /* Determine extension bits (sign, zero or dest register). */
  constexpr auto shift_max = T(sizeof(T) * 8 - 1);
  auto top = Unsigned(SShr(Signed(UShl(src, USub(shift_max, S))), shift_max));

  /* Combine extension bits and result bits.*/
  return UOr(UAnd(top, UNot(tmask)), UAnd(bot, tmask));
}

// BFM  <Wd>, <Wn>, #<immr>, #<imms>
template <typename RT, typename S>
DEF_SEM_T(BFM, RT dst_src, RT src1, S src2, S src3, S src4) {
  auto dst_val = TruncTo<S>(Read(dst_src)); /* May be wider due to zero-extension. */
  auto src = Read(src1);
  auto R = Read(src2);
  auto wmask = Read(src3);
  auto tmask = Read(src4);

  /* Perform bitfield move on low bits.*/
  auto bot = UOr(UAnd(dst_val, UNot(wmask)), UAnd(Ror(src, R), wmask));

  /* Combine extension bits and result bits. */
  return UOr(UAnd(dst_val, UNot(tmask)), UAnd(bot, tmask));
}

}  // namespace

DEF_ISEL(UBFM_32M_BITFIELD) = UBFM<R32, I32>;  // UBFM  <Wd>, <Wn>, #<immr>, #<imms>
DEF_ISEL(UBFM_64M_BITFIELD) = UBFM<R64, I64>;  // UBFM  <Xd>, <Xn>, #<immr>, #<imms>

DEF_ISEL(SBFM_32M_BITFIELD) = SBFM<R32, I32>;  // SBFM  <Wd>, <Wn>, #<immr>, #<imms>
DEF_ISEL(SBFM_64M_BITFIELD) = SBFM<R64, I64>;  // SBFM  <Xd>, <Xn>, #<immr>, #<imms>

DEF_ISEL(BFM_32M_BITFIELD) = BFM<R32, I32>;  // BFM  <Wd>, <Wn>, #<immr>, #<imms>
DEF_ISEL(BFM_64M_BITFIELD) = BFM<R64, I64>;  // BFM  <Xd>, <Xn>, #<immr>, #<imms>

namespace {

// EXTR  <Wd>, <Wn>, <Wm>, #<lsb>
template <typename RT, typename IT>
DEF_SEM_T(EXTR, RT src1, RT src2, IT src3) {
  using T = typename BaseType<RT>::BT;
  constexpr auto size = T(sizeof(T) * 8);
  auto lsb = Read(src3);
  if (!lsb) {
    return Read(src2);
  } else {
    auto operand1 = UShl(Read(src1), USub(size, lsb));
    auto operand2 = UShr(Read(src2), lsb);
    return UOr(operand1, operand2);
  }
}

}  // namespace

DEF_ISEL(EXTR_32_EXTRACT) = EXTR<R32, I32>;  // EXTR  <Wd>, <Wn>, <Wm>, #<lsb>
DEF_ISEL(EXTR_64_EXTRACT) = EXTR<R64, I64>;  // EXTR  <Xd>, <Xn>, <Xm>, #<lsb>

namespace {

// CLZ  <Wd>, <Wn>
template <typename RT>
DEF_SEM_T(CLZ, RT src) {
  auto count = CountLeadingZeros(Read(src));
  return count;
}

}  // namespace

DEF_ISEL(CLZ_32_DP_1SRC) = CLZ<R32>;  // CLZ  <Wd>, <Wn>
DEF_ISEL(CLZ_64_DP_1SRC) = CLZ<R64>;  // CLZ  <Xd>, <Xn>

namespace {

// REV16 <Wd>, <Wn>
DEF_SEM_U32(REV16_32, R32 src) {
  uint32_t src_num = Read(src);
  uint16_t first_half = src_num >> 16;
  uint16_t second_half = src_num & 0xFFFF;
  return ((uint32_t(__builtin_bswap16(first_half))) << 16) |
         uint32_t(__builtin_bswap16(second_half));
}

// REV16 <Xd>, <Xn>
DEF_SEM_U64(REV16_64, R64 src) {
  uint64_t src_num = Read(src);
  uint16_t first_quarter = src_num >> 48;
  uint16_t second_quarter = (src_num >> 32) & 0xFFFF;
  uint16_t third_quarter = (src_num >> 16) & 0xFFFF;
  uint16_t forth_quarter = src_num & 0xFFFF;
  return ((uint64_t(__builtin_bswap16(first_quarter))) << 48) |
         ((uint64_t(__builtin_bswap16(second_quarter))) << 32) |
         ((uint64_t(__builtin_bswap16(third_quarter)) << 16)) |
         uint64_t(__builtin_bswap16(forth_quarter));
}

// REV  <Wd>, <Wn>
DEF_SEM_U32(REV32_32, R32 src) {
  return __builtin_bswap32(Read(src));
}

// REV32  <Xd>, <Xn>
DEF_SEM_U64(REV32_64, R64 src) {
  uint64_t src_num = Read(src);
  uint32_t first_half = src_num >> 32;
  uint32_t second_half = src_num & 0xFFFFFFFF;
  return ((uint64_t(__builtin_bswap32(first_half))) << uint32_t(32)) |
         uint64_t(__builtin_bswap32(second_half));
}

// REV  <Xd>, <Xn>
DEF_SEM_U64(REV64, R64 src) {
  return __builtin_bswap64(Read(src));
}

template <typename T, size_t n>
ALWAYS_INLINE static T ReverseBits(T v) {
  T rv = 0;
  _Pragma("unroll") for (size_t i = 0; i < n; ++i, v >>= 1) {
    rv = (rv << T(1)) | (v & T(1));
  }
  return rv;
}

#if !__has_builtin(__builtin_bitreverse32)
#  define __builtin_bitreverse32(x) ReverseBits<uint32_t, 32>(x)
#endif

// RBIT  <Wd>, <Wn>
DEF_SEM_U32(RBIT32, R32 src) {
  return __builtin_bitreverse32(Read(src));
}

#if !__has_builtin(__builtin_bitreverse64)
#  define __builtin_bitreverse64(x) ReverseBits<uint64_t, 64>(x)
#endif

// RBIT  <Xd>, <Xn>
DEF_SEM_U64(RBIT64, R64 src) {
  return __builtin_bitreverse64(Read(src));
}

}  // namespace

DEF_ISEL(REV16_32_DP_1SRC) = REV16_32;  // REV16  <Wd>, <Wn>
DEF_ISEL(REV16_64_DP_1SRC) = REV16_64;  // REV16  <Xd>, <Xn>
DEF_ISEL(REV_32_DP_1SRC) = REV32_32;  // REV  <Wd>, <Wn>
DEF_ISEL(REV32_64_DP_1SRC) = REV32_64;  // REV32  <Xd>, <Xn>
DEF_ISEL(REV_64_DP_1SRC) = REV64;  // REV  <Xd>, <Xn>

DEF_ISEL(RBIT_32_DP_1SRC) = RBIT32;  // RBIT  <Wd>, <Wn>
DEF_ISEL(RBIT_64_DP_1SRC) = RBIT64;  // RBIT  <Xd>, <Xn>
