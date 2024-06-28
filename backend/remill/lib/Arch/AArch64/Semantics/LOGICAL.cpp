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

namespace {

template <typename S1, typename S2>
DEF_SEM_T(ORN, S1 src1, S2 src2) {
  return UOr(Read(src1), UNot(Read(src2)));
}

template <typename S1, typename S2>
DEF_SEM_T(EOR, S1 src1, S2 src2) {
  return UXor(Read(src1), Read(src2));
}

template <typename S1, typename S2>
DEF_SEM_T(EON, S1 src1, S2 src2) {
  return UXor(Read(src1), UNot(Read(src2)));
}

template <typename S1, typename S2>
DEF_SEM(AND, S1 src1, S2 src2) {
  return UAnd(Read(src1), Read(src2));
}

template <typename S1, typename S2>
DEF_SEM(ORR, S1 src1, S2 src2) {
  return UOr(Read(src1), Read(src2));
}

template <typename S1, typename S2>
DEF_SEM(BIC, S1 src1, S2 src2) {
  return UAnd(Read(src1), UNot(Read(src2)));
}

DEF_SEM_U32U64(BICS_32, R32 src1, I32 src2) {
  uint32_t res = UAnd(Read(src1), UNot(Read(src2)));
  uint64_t flag_n, flag_z, flag_c, flag_v;
  flag_n = SignFlag(res, src1, src2);
  flag_z = ZeroFlag(res, src1, src2);
  flag_c = false;
  flag_v = false;
  uint64_t nzcv = (flag_n << 3) | (flag_z << 2) | (flag_c << 1) | flag_v;
  return {res, nzcv};
}

DEF_SEM_U64U64(BICS_64, R64 src1, I64 src2) {
  uint64_t res = UAnd(Read(src1), UNot(Read(src2)));
  uint64_t flag_n, flag_z, flag_c, flag_v;
  flag_n = SignFlag(res, src1, src2);
  flag_z = ZeroFlag(res, src1, src2);
  flag_c = false;
  flag_v = false;
  uint64_t nzcv = (flag_n << 3) | (flag_z << 2) | (flag_c << 1) | flag_v;
  return {res, nzcv};
}

}  // namespace


DEF_ISEL(ORN_32_LOG_SHIFT) = ORN<R32, I32>;  // ORN  <Wd>, <Wn>, <Wm>{, <shift> #<amount>}
DEF_ISEL(ORN_64_LOG_SHIFT) = ORN<R64, I64>;  // ORN  <Xd>, <Xn>, <Xm>{, <shift> #<amount>}

DEF_ISEL(EOR_32_LOG_SHIFT) = EOR<R32, I32>;  // EOR  <Wd>, <Wn>, <Wm>{, <shift> #<amount>}
DEF_ISEL(EOR_64_LOG_SHIFT) = EOR<R64, I64>;  // EOR  <Xd>, <Xn>, <Xm>{, <shift> #<amount>}
DEF_ISEL(EOR_32_LOG_IMM) = EOR<R32, I32>;  // EOR  <Wd|WSP>, <Wn>, #<imm>
DEF_ISEL(EOR_64_LOG_IMM) = EOR<R64, I64>;  // EOR  <Xd|SP>, <Xn>, #<imm>

DEF_ISEL(EON_32_LOG_SHIFT) = EON<R32, I32>;  // EON  <Wd>, <Wn>, <Wm>{, <shift> #<amount>}
DEF_ISEL(EON_64_LOG_SHIFT) = EON<R64, I64>;  // EON  <Xd>, <Xn>, <Xm>{, <shift> #<amount>}

DEF_ISEL(AND_32_LOG_SHIFT) = AND<R32, I32>;  // AND  <Wd>, <Wn>, <Wm>{, <shift> #<amount>}
DEF_ISEL(AND_64_LOG_SHIFT) = AND<R64, I64>;  // AND  <Xd>, <Xn>, <Xm>{, <shift> #<amount>}
DEF_ISEL(AND_32_LOG_IMM) = AND<R32, I32>;  // AND  <Wd|WSP>, <Wn>, #<imm>
DEF_ISEL(AND_64_LOG_IMM) = AND<R64, I64>;  // AND  <Xd|SP>, <Xn>, #<imm>

DEF_ISEL(ORR_32_LOG_SHIFT) = ORR<R32, I32>;  // ORR  <Wd>, <Wn>, <Wm>{, <shift> #<amount>}
DEF_ISEL(ORR_64_LOG_SHIFT) = ORR<R64, I64>;  // ORR  <Xd>, <Xn>, <Xm>{, <shift> #<amount>}
DEF_ISEL(ORR_32_LOG_IMM) = ORR<R32, I32>;  // ORR  <Wd|WSP>, <Wn>, #<imm>
DEF_ISEL(ORR_64_LOG_IMM) = ORR<R64, I64>;  // ORR  <Xd|SP>, <Xn>, #<imm>

DEF_ISEL(BIC_32_LOG_SHIFT) = BIC<R32, I32>;  // BIC  <Wd>, <Wn>, <Wm>{, <shift> #<amount>}
DEF_ISEL(BIC_64_LOG_SHIFT) = BIC<R64, I64>;  // BIC  <Xd>, <Xn>, <Xm>{, <shift> #<amount>}

DEF_ISEL(BICS_32_LOG_SHIFT) = BICS_32;  // BICS  <Wd>, <Wn>, <Wm>{, <shift> #<amount>}
DEF_ISEL(BICS_64_LOG_SHIFT) = BICS_64;  // BICS  <Xd>, <Xn>, <Xm>{, <shift> #<amount>}

namespace {

DEF_SEM_U32U64(ANDS_32, R32 src1, I32 src2) {
  uint32_t res = UAnd(Read(src1), Read(src2));
  uint64_t flag_n, flag_z, flag_c, flag_v;
  flag_n = SignFlag(res, src1, src2);
  flag_z = ZeroFlag(res, src1, src2);
  flag_c = false;
  flag_v = false;
  uint64_t nzcv = (flag_n << 3) | (flag_z << 2) | (flag_c << 1) | flag_v;
  return {res, nzcv};
}

DEF_SEM_U64U64(ANDS_64, R64 src1, I64 src2) {
  uint64_t res = UAnd(Read(src1), Read(src2));
  uint64_t flag_n, flag_z, flag_c, flag_v;
  flag_n = SignFlag(res, src1, src2);
  flag_z = ZeroFlag(res, src1, src2);
  flag_c = false;
  flag_v = false;
  uint64_t nzcv = (flag_n << 3) | (flag_z << 2) | (flag_c << 1) | flag_v;
  return {res, nzcv};
}

}  // namespace

DEF_ISEL(ANDS_32S_LOG_IMM) = ANDS_32;  // ANDS  <Wd>, <Wn>, #<imm>
DEF_ISEL(ANDS_64S_LOG_IMM) = ANDS_64;  // ANDS  <Xd>, <Xn>, #<imm>

DEF_ISEL(ANDS_32_LOG_SHIFT) = ANDS_32;  // ANDS  <Wd>, <Wn>, <Wm>{, <shift> #<amount>}
DEF_ISEL(ANDS_64_LOG_SHIFT) = ANDS_64;  // ANDS  <Xd>, <Xn>, <Xm>{, <shift> #<amount>}

namespace {

template <typename S>
DEF_SEM_T(LSLV, S src1, S src2) {
  using T = typename BaseType<S>::BT;
  constexpr auto size = T(sizeof(T) * 8);
  return UShl(Read(src1), URem(Read(src2), size));
}

template <typename S>
DEF_SEM_T(LSRV, S src1, S src2) {
  using T = typename BaseType<S>::BT;
  constexpr auto size = T(sizeof(T) * 8);
  return UShr(Read(src1), URem(Read(src2), size));
}

template <typename S>
DEF_SEM_T(ASRV, S src1, S src2) {
  using T = typename BaseType<S>::BT;
  constexpr auto size = T(sizeof(T) * 8);
  return Unsigned(SShr(Signed(Read(src1)), Signed(URem(Read(src2), size))));
}

template <typename S>
DEF_SEM_T(RORV, S src1, S src2) {
  using T = typename BaseType<S>::BT;
  constexpr auto size = T(sizeof(T) * 8);
  return Ror(Read(src1), URem(Read(src2), size));
}
}  // namespace

DEF_ISEL(LSLV_32_DP_2SRC) = LSLV<R32>;  // LSLV  <Wd>, <Wn>, <Wm>
DEF_ISEL(LSLV_64_DP_2SRC) = LSLV<R64>;  // LSLV  <Xd>, <Xn>, <Xm>

DEF_ISEL(LSRV_32_DP_2SRC) = LSRV<R32>;  // LSRV  <Wd>, <Wn>, <Wm>
DEF_ISEL(LSRV_64_DP_2SRC) = LSRV<R64>;  // LSRV  <Xd>, <Xn>, <Xm>

DEF_ISEL(ASRV_32_DP_2SRC) = ASRV<R32>;  // ASRV  <Wd>, <Wn>, <Wm>
DEF_ISEL(ASRV_64_DP_2SRC) = ASRV<R64>;  // ASRV  <Xd>, <Xn>, <Xm>

DEF_ISEL(RORV_32_DP_2SRC) = RORV<R32>;  // RORV  <Wd>, <Wn>, <Wm>
DEF_ISEL(RORV_64_DP_2SRC) = RORV<R64>;  // RORV  <Xd>, <Xn>, <Xm>