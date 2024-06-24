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

template <typename RETT, typename RT, typename IT>
DEF_SEM_T(UBFM, RT src1, IT mask) {
  same_type_assert<RETT, RT>();
  return UAnd(Read(src1), Read(mask));
}

template <typename RETT, typename RT, typename IT>
DEF_SEM_T(SBFM, RT src1, IT src2, IT src3, IT src4, IT src5) {
  same_type_assert<RETT, RT>();
  using T = typename BaseType<IT>::BT;
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

template <typename RETT, typename RT, typename IT>
DEF_SEM_T(BFM, RT src1, IT src2, IT src3, IT src4) {
  same_type_assert<RETT, RT>();
  using T = typename BaseType<IT>::BT;
  auto dst_val = TruncTo<T>(Read(dst)); /* May be wider due to zero-extension. */
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

DEF_ISEL(UBFM_32M_BITFIELD) = UBFM<uint32_t, R32, I32>;
DEF_ISEL(UBFM_64M_BITFIELD) = UBFM<uint64_t, R64, I64>;

DEF_ISEL(SBFM_32M_BITFIELD) = SBFM<uint32_t, R32, I32>;
DEF_ISEL(SBFM_64M_BITFIELD) = SBFM<uint64_t, R64, I64>;

DEF_ISEL(BFM_32M_BITFIELD) = BFM<uint32_t, R32, I32>;
DEF_ISEL(BFM_64M_BITFIELD) = BFM<uint32_t, R64, I64>;

namespace {

template <typename RETT, typename RT, typename IT>
DEF_SEM_T(EXTR, RT src1, RT src2, IT src3) {
  same_type_assert<RETT, RT>();
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

DEF_ISEL(EXTR_32_EXTRACT) = EXTR<uint32_t, R32, I32>;
DEF_ISEL(EXTR_64_EXTRACT) = EXTR<uint64_t, R64, I64>;

namespace {

template <typename RETT, typename RT>
DEF_SEM_T(CLZ, RT src) {
  same_type_assert<RETT, RT>();
  auto count = CountLeadingZeros(Read(src));
  return count;
}

}  // namespace

DEF_ISEL(CLZ_32_DP_1SRC) = CLZ<uint32_t, R32>;
DEF_ISEL(CLZ_64_DP_1SRC) = CLZ<uint64_t, R64>;

namespace {

// REV16 <Wd>, <Wn>
DEF_SEM_U32(REV16_32, R32 src) {
  uint32_t src_num = Read(src);
  auto first_half = src_num >> (uint32_t) 16;
  auto second_half = src_num & 0xFFFF;
  return ((uint32_t(__builtin_bswap16(first_half))) << uint32_t(16)) |
         uint32_t(__builtin_bswap16(second_half));
}

// REV16 <Xd>, <Xn>
DEF_SEM_U64(REV16_64, R64 src) {
  uint64_t src_num = Read(src);
  uint16_t first_quarter = src_num >> (uint64_t) 48;
  uint16_t second_quarter = (src_num >> (uint64_t) 32) & 0xFFFF;
  uint16_t third_quarter = (src_num >> (uint64_t) 16) & 0xFFFF;
  uint16_t forth_quarter = src_num & 0xFFFF;
  return ((uint64_t(__builtin_bswap16(first_quarter))) << uint64_t(48)) |
         ((uint64_t(__builtin_bswap16(second_quarter))) << uint64_t(32)) |
         ((uint64_t(__builtin_bswap16(third_quarter)) << uint64_t(16))) |
         uint64_t(__builtin_bswap16(forth_quarter));
}

DEF_SEM_U32(REV32_32, R32 src) {
  return __builtin_bswap32(Read(src));
}

DEF_SEM_U64(REV32_64, R64 src) {
  uint32_t src_num = Read(src);
  auto first_half = src_num >> (uint64_t) 32;
  auto second_half = src_num & 0xFFFFFFFF;
  return ((uint32_t(__builtin_bswap32(first_half))) << uint32_t(32)) |
         uint32_t(__builtin_bswap32(second_half));
}

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

DEF_SEM_U32(RBIT32, R32 src) {
  return __builtin_bitreverse32(Read(src));
}


#if !__has_builtin(__builtin_bitreverse64)
#  define __builtin_bitreverse64(x) ReverseBits<uint64_t, 64>(x)
#endif

DEF_SEM_U64(RBIT64, R64 src) {
  return __builtin_bitreverse64(Read(src));
}

}  // namespace

DEF_ISEL(REV16_32_DP_1SRC) = REV16_32;
DEF_ISEL(REV16_64_DP_1SRC) = REV16_64;
DEF_ISEL(REV_32_DP_1SRC) = REV32_32;
DEF_ISEL(REV32_64_DP_1SRC) = REV32_64;
DEF_ISEL(REV_64_DP_1SRC) = REV64;

DEF_ISEL(RBIT_32_DP_1SRC) = RBIT32;
DEF_ISEL(RBIT_64_DP_1SRC) = RBIT64;
