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

DEF_SEM_U64_RUN(StorePairUpdateIndex32, R32 src1, R32 src2, MVI64W dst_mem, ADDR next_addr) {
  _ecv_u32v2_t vec = {Read(src1), Read(src2)};
  UWriteMVI32(dst_mem, vec);
  return Read(next_addr);
}

DEF_SEM_U64_RUN(StorePairUpdateIndex64, R64 src1, R64 src2, MVI128W dst_mem, ADDR next_addr) {
  _ecv_u64v2_t vec = {Read(src1), Read(src2)};
  UWriteMVI64(dst_mem, vec);
  return Read(next_addr);
}

DEF_SEM_U64_RUN(StorePairUpdateIndexS, RF32 src1, RF32 src2, MVI64W dst_mem, ADDR next_addr) {
  _ecv_f32v2_t vec = {Read(src1), Read(src2)};
  FWriteMVI32(dst_mem, vec);
  return Read(next_addr);
}

DEF_SEM_U64_RUN(StorePairUpdateIndexD, RF64 src1, RF64 src2, MVI128W dst_mem, ADDR next_addr) {
  _ecv_f64v2_t vec = {Read(src1), Read(src2)};
  FWriteMVI64(dst_mem, vec);
  return Read(next_addr);
}

DEF_SEM_VOID_RUN(StorePair32, R32 src1, R32 src2, MVI64W dst) {
  _ecv_u32v2_t vec = {Read(src1), Read(src2)};
  UWriteMVI32(dst, vec);
}

DEF_SEM_VOID_RUN(StorePair64, R64 src1, R64 src2, MVI128W dst) {
  _ecv_u64v2_t vec = {Read(src1), Read(src2)};
  UWriteMVI64(dst, vec);
}

DEF_SEM_VOID_RUN(STP_S, RF32 src1, RF32 src2, MVI64W dst) {
  _ecv_f32v2_t vec = {Read(src1), Read(src2)};
  FWriteMVI32(dst, vec);
}

DEF_SEM_VOID_RUN(STP_D, RF64 src1, RF64 src2, MVI128W dst) {
  _ecv_f64v2_t vec = {Read(src1), Read(src2)};
  FWriteMVI64(dst, vec);
}

DEF_SEM_VOID_RUN(STP_Q, VI128 src1, VI128 src2, MVI256W dst) {
  _ecv_u128v2_t vec = {UExtractVI128(src1, 0), UExtractVI128(src2, 0)};
  UWriteMVI128(dst, vec);
}

DEF_SEM_U64_RUN(STP_Q_UPDATE_ADDR, VI128 src1, VI128 src2, MVI256W dst, ADDR next_addr) {
  _ecv_u128v2_t vec = {UExtractVI128(src1, 0), UExtractVI128(src2, 0)};
  UWriteMVI128(dst, vec);
  return Read(next_addr);
}

}  // namespace

DEF_ISEL(STP_32_LDSTPAIR_PRE) = StorePairUpdateIndex32;  // STP  <Wt1>, <Wt2>, [<Xn|SP>, #<imm>]!
DEF_ISEL(STP_32_LDSTPAIR_POST) = StorePairUpdateIndex32;  // STP  <Wt1>, <Wt2>, [<Xn|SP>], #<imm>

DEF_ISEL(STP_64_LDSTPAIR_PRE) = StorePairUpdateIndex64;  // STP  <Xt1>, <Xt2>, [<Xn|SP>, #<imm>]!
DEF_ISEL(STP_64_LDSTPAIR_POST) = StorePairUpdateIndex64;  // STP  <Xt1>, <Xt2>, [<Xn|SP>], #<imm>

DEF_ISEL(STP_S_LDSTPAIR_PRE) = StorePairUpdateIndexS;  // STP  <St1>, <St2>, [<Xn|SP>, #<imm>]!
DEF_ISEL(STP_S_LDSTPAIR_POST) = StorePairUpdateIndexS;  // STP  <St1>, <St2>, [<Xn|SP>], #<imm>

DEF_ISEL(STP_D_LDSTPAIR_PRE) = StorePairUpdateIndexD;  // STP  <Dt1>, <Dt2>, [<Xn|SP>, #<imm>]!
DEF_ISEL(STP_D_LDSTPAIR_POST) = StorePairUpdateIndexD;  // STP  <Dt1>, <Dt2>, [<Xn|SP>], #<imm>

DEF_ISEL(STP_32_LDSTPAIR_OFF) = StorePair32;  // STP  <Wt1>, <Wt2>, [<Xn|SP>{, #<imm>}]
DEF_ISEL(STP_64_LDSTPAIR_OFF) = StorePair64;  // STP  <Xt1>, <Xt2>, [<Xn|SP>{, #<imm>}]

DEF_ISEL(STP_S_LDSTPAIR_OFF) = STP_S;  // STP  <St1>, <St2>, [<Xn|SP>{, #<imm>}]
DEF_ISEL(STP_D_LDSTPAIR_OFF) = STP_D;  // STP  <Dt1>, <Dt2>, [<Xn|SP>{, #<imm>}]

DEF_ISEL(STP_Q_LDSTPAIR_OFF) = STP_Q;  // STP  <Qt1>, <Qt2>, [<Xn|SP>{, #<imm>}]
DEF_ISEL(STP_Q_LDSTPAIR_PRE) = STP_Q_UPDATE_ADDR;  // STP  <Qt1>, <Qt2>, [<Xn|SP>, #<imm>]!
DEF_ISEL(STP_Q_LDSTPAIR_POST) = STP_Q_UPDATE_ADDR;  // STP  <Qt1>, <Qt2>, [<Xn|SP>], #<imm>

namespace {

template <typename S, typename D>
DEF_SEM_U64_RUN(StoreUpdateIndex, S src, D dst_mem, ADDR next_addr) {
  MWriteTrunc(dst_mem, Read(src));
  return Read(next_addr);
}

DEF_SEM_U64_RUN(StoreUpdateIndex_S8, VI8 src, MVI8W dst_mem, ADDR next_addr) {
  _ecv_i8v1_t vec = {SExtractVI8(src, 0)};
  SWriteMVI8(dst_mem, vec);
  return Read(next_addr);
}

DEF_SEM_U64_RUN(StoreUpdateIndex_S16, VI16 src, MVI16W dst_mem, ADDR next_addr) {
  _ecv_i16v1_t vec = {SExtractVI16(src, 0)};
  SWriteMVI16(dst_mem, vec);
  return Read(next_addr);
}

DEF_SEM_U64_RUN(StoreUpdateIndex_F32, RF32 src, MVI32W dst_mem, ADDR next_addr) {
  FWriteMVI32(dst_mem, Read(src));
  return Read(next_addr);
}

DEF_SEM_U64_RUN(StoreUpdateIndex_F64, RF64 src, MVI64W dst_mem, ADDR next_addr) {
  FWriteMVI64(dst_mem, Read(src));
  return Read(next_addr);
}

template <typename S, typename D>
DEF_SEM_VOID_RUN(Store, S src, D dst) {
  MWriteTrunc(dst, Read(src));
}

template <typename S, typename D>
DEF_SEM_VOID_RUN(StoreToOffset, S src, D base, ADDR offset) {
  MWriteTrunc(DisplaceAddress(base, Read(offset)), Read(src));
}

DEF_SEM_VOID_RUN(StoreWordToOffset, RF32 src, MVI32W base, ADDR offset) {
  FWriteMVI32(DisplaceAddress(base, Read(offset)), Read(src));
}

DEF_SEM_VOID_RUN(StoreDoubleToOffset, RF64 src, MVI64W base, ADDR offset) {
  FWriteMVI64(DisplaceAddress(base, Read(offset)), Read(src));
}

template <typename S, typename D>  // StoreRelease<R32, M32W>
DEF_SEM_VOID_RUN(StoreRelease, S src, D dst) {
  MWriteTrunc(dst, Read(src));
  __remill_barrier_store_store(runtime_manager);
}

DEF_SEM_U64_RUN(STR_Q_UPDATE_ADDR, VI128 src, MVI128W dst, ADDR next_addr) {
  _ecv_u128v1_t vec = {UExtractVI128(src, 0)};
  UWriteMVI128(dst, vec);
  return Read(next_addr);
}

/* S1: <W|X>.s, D1: <W|X>.t, S2: Xn, D2: Xn */
template <typename S1, typename D1, typename S2,
          typename D2>  // e.g. SWP_MEMOP<R32, R32W, M32, M32W>
DEF_SEM_U32_RUN(SWP_MEMOP32, S1 src1, S2 src2_mem, D2 dst_mem) {
  static_assert(sizeof(typename BaseType<S1>::BT) == sizeof(uint32_t));
  MWriteTrunc(dst_mem, Read(src1));
  return ReadMem(src2_mem);
}

/* S1: <W|X>.s, D1: <W|X>.t, S2: Xn, D2: Xn */
template <typename S1, typename D1, typename S2,
          typename D2>  // e.g. SWP_MEMOP<R32, R32W, M32, M32W>
DEF_SEM_U64_RUN(SWP_MEMOP64, S1 src1, S2 src2_mem, D2 dst_mem) {
  static_assert(sizeof(typename BaseType<S1>::BT) == sizeof(uint64_t));
  MWriteTrunc(dst_mem, Read(src1));
  return ReadMem(src2_mem);
}

template <typename S, typename D>  // e.g. LDADD_MEMOP<R32W, M32W>
DEF_SEM_T_RUN(LDADD_MEMOP, S src, D dst_mem) {
  using T = typename BaseType<S>::BT;
  T dst_val = ReadMem(dst_mem);
  MWriteTrunc(dst_mem, UAdd(dst_val, Read(src)));
  return dst_val;
}

template <typename S, typename D>  // e.g. LDSET_MEMOP<R32W, M32W>
DEF_SEM_T_RUN(LDSET_MEMOP, S src, D dst_mem) {
  using T = typename BaseType<S>::BT;
  T dst_val = ReadMem(dst_mem);
  MWriteTrunc(dst_mem, UOr(dst_val, Read(src)));
  return dst_val;
}

}  // namespace

DEF_ISEL(STR_32_LDST_IMMPRE) = StoreUpdateIndex<R32, M32W>;  // STR  <Wt>, [<Xn|SP>, #<simm>]!
DEF_ISEL(STR_32_LDST_IMMPOST) = StoreUpdateIndex<R32, M32W>;  // STR  <Wt>, [<Xn|SP>], #<simm>

DEF_ISEL(STR_64_LDST_IMMPRE) = StoreUpdateIndex<R64, M64W>;  // STR  <Xt>, [<Xn|SP>, #<simm>]!
DEF_ISEL(STR_64_LDST_IMMPOST) = StoreUpdateIndex<R64, M64W>;  // STR  <Xt>, [<Xn|SP>], #<simm>

DEF_ISEL(STR_B_LDST_IMMPRE) = StoreUpdateIndex_S8;  // STR  <Bt>, [<Xn|SP>, #<simm>]!
DEF_ISEL(STR_B_LDST_IMMPOST) = StoreUpdateIndex_S8;  // STR  <Bt>, [<Xn|SP>], #<simm>

DEF_ISEL(STR_H_LDST_IMMPRE) = StoreUpdateIndex_S16;  // STR  <Ht>, [<Xn|SP>, #<simm>]!
DEF_ISEL(STR_H_LDST_IMMPOST) = StoreUpdateIndex_S16;  // STR  <Ht>, [<Xn|SP>], #<simm>

DEF_ISEL(STR_S_LDST_IMMPRE) = StoreUpdateIndex_F32;  // STR  <St>, [<Xn|SP>, #<simm>]!
DEF_ISEL(STR_S_LDST_IMMPOST) = StoreUpdateIndex_F32;  // STR  <St>, [<Xn|SP>], #<simm>

DEF_ISEL(STR_D_LDST_IMMPRE) = StoreUpdateIndex_F64;  // STR  <Dt>, [<Xn|SP>, #<simm>]!
DEF_ISEL(STR_D_LDST_IMMPOST) = StoreUpdateIndex_F64;  // STR  <Dt>, [<Xn|SP>], #<simm>

DEF_ISEL(STR_32_LDST_POS) = Store<R32, M32W>;  // STR  <Wt>, [<Xn|SP>{, #<pimm>}]
DEF_ISEL(STR_64_LDST_POS) = Store<R64, M64W>;  // STR  <Xt>, [<Xn|SP>{, #<pimm>}]

DEF_ISEL(STLR_SL32_LDSTEXCL) = StoreRelease<R32, M32W>;  // STLR  <Wt>, [<Xn|SP>{,#0}]
DEF_ISEL(STLR_SL64_LDSTEXCL) = StoreRelease<R64, M64W>;  // STLR  <Xt>, [<Xn|SP>{,#0}]

DEF_ISEL(STRB_32_LDST_POS) = Store<R32, M8W>;  // STRB  <Wt>, [<Xn|SP>{, #<pimm>}]
DEF_ISEL(STRB_32_LDST_IMMPOST) = StoreUpdateIndex<R32, M8W>;  // STRB  <Wt>, [<Xn|SP>], #<simm>
DEF_ISEL(STRB_32_LDST_IMMPRE) = StoreUpdateIndex<R32, M8W>;  // STRB  <Wt>, [<Xn|SP>, #<simm>]!
DEF_ISEL(STRB_32B_LDST_REGOFF) =
    StoreToOffset<R32, M8W>;  // STRB  <Wt>, [<Xn|SP>, (<Wm>|<Xm>), <extend> {<amount>}]
DEF_ISEL(STRB_32BL_LDST_REGOFF) =
    StoreToOffset<R32, M8W>;  // STRB  <Wt>, [<Xn|SP>, <Xm>{, LSL <amount>}]

DEF_ISEL(STRH_32_LDST_REGOFF) =
    StoreToOffset<R32, M16W>;  // STRH  <Wt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
DEF_ISEL(STRH_32_LDST_IMMPRE) = StoreUpdateIndex<R32, M16W>;  // STRH  <Wt>, [<Xn|SP>, #<simm>]!
DEF_ISEL(STRH_32_LDST_IMMPOST) = StoreUpdateIndex<R32, M16W>;  // STRH  <Wt>, [<Xn|SP>], #<simm>
DEF_ISEL(STRH_32_LDST_POS) = Store<R32, M16W>;

DEF_ISEL(STR_32_LDST_REGOFF) =
    StoreToOffset<R32, M32W>;  // STR  <Wt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
DEF_ISEL(STR_64_LDST_REGOFF) =
    StoreToOffset<R64, M64W>;  // STR  <Xt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
DEF_ISEL(STR_S_LDST_REGOFF) =
    StoreWordToOffset;  // STR  <St>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
DEF_ISEL(STR_D_LDST_REGOFF) =
    StoreDoubleToOffset;  // STR  <Dt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]

DEF_ISEL(SWP_32_MEMOP) = SWP_MEMOP32<R32, R32W, M32, M32W>;  // SWP  <Ws>, <Wt>, [<Xn|SP>]
DEF_ISEL(SWP_64_MEMOP) = SWP_MEMOP64<R64, R64W, M64, M64W>;  // SWP  <Xs>, <Xt>, [<Xn|SP>]

DEF_ISEL(SWPA_32_MEMOP) = SWP_MEMOP32<R32, R32W, M32, M32W>;  // SWPA  <Ws>, <Wt>, [<Xn|SP>]
DEF_ISEL(SWPA_64_MEMOP) = SWP_MEMOP64<R64, R64W, M64, M64W>;  // SWPA  <Xs>, <Xt>, [<Xn|SP>]

DEF_ISEL(SWPL_32_MEMOP) = SWP_MEMOP32<R32, R32W, M32, M32W>;  // SWPL  <Ws>, <Wt>, [<Xn|SP>]
DEF_ISEL(SWPL_64_MEMOP) = SWP_MEMOP64<R64, R64W, M64, M64W>;  // SWPL  <Xs>, <Xt>, [<Xn|SP>]

DEF_ISEL(LDADD_32_MEMOP) = LDADD_MEMOP<R32W, M32W>;  // LDADD  <Ws>, <Wt>, [<Xn|SP>]
DEF_ISEL(LDADD_64_MEMOP) = LDADD_MEMOP<R64W, M64W>;  // LDADD  <Xs>, <Xt>, [<Xn|SP>]

DEF_ISEL(LDADDA_32_MEMOP) = LDADD_MEMOP<R32W, M32W>;  // LDADDA  <Ws>, <Wt>, [<Xn|SP>]
DEF_ISEL(LDADDA_64_MEMOP) = LDADD_MEMOP<R64W, M64W>;  // LDADDA  <Xs>, <Xt>, [<Xn|SP>]

DEF_ISEL(LDADDL_32_MEMOP) = LDADD_MEMOP<R32W, M32W>;  // LDADDL  <Ws>, <Wt>, [<Xn|SP>]
DEF_ISEL(LDADDL_64_MEMOP) = LDADD_MEMOP<R64W, M64W>;  // LDADDL  <Xs>, <Xt>, [<Xn|SP>]

DEF_ISEL(LDADDAL_32_MEMOP) = LDADD_MEMOP<R32W, M32W>;  // LDADDAL  <Ws>, <Wt>, [<Xn|SP>]
DEF_ISEL(LDADDAL_64_MEMOP) = LDADD_MEMOP<R64W, M64W>;  // LDADDAL  <Xs>, <Xt>, [<Xn|SP>]

DEF_ISEL(LDSET_32_MEMOP) = LDSET_MEMOP<R32W, M32W>;  // LDSET  <Ws>, <Wt>, [<Xn|SP>]
DEF_ISEL(LDSET_64_MEMOP) = LDSET_MEMOP<R64W, M64W>;  // LDSET  <Xs>, <Xt>, [<Xn|SP>]

DEF_ISEL(LDSETA_32_MEMOP) = LDSET_MEMOP<R32W, M32W>;  // LDSETA  <Ws>, <Wt>, [<Xn|SP>]
DEF_ISEL(LDSETA_64_MEMOP) = LDSET_MEMOP<R64W, M64W>;  // LDSETA  <Xs>, <Xt>, [<Xn|SP>]

DEF_ISEL(LDSETL_32_MEMOP) = LDSET_MEMOP<R32W, M32W>;  // LDSETL  <Ws>, <Wt>, [<Xn|SP>]
DEF_ISEL(LDSETL_64_MEMOP) = LDSET_MEMOP<R64W, M64W>;  // LDSETL  <Xs>, <Xt>, [<Xn|SP>]

DEF_ISEL(LDSETAL_32_MEMOP) = LDSET_MEMOP<R32W, M32W>;  // LDSETAL  <Ws>, <Wt>, [<Xn|SP>]
DEF_ISEL(LDSETAL_64_MEMOP) = LDSET_MEMOP<R64W, M64W>;  // LDSETAL  <Xs>, <Xt>, [<Xn|SP>]

namespace {

DEF_SEM_U32U32U64_RUN(LoadPairUpdateIndex32, MVI64W src_mem, ADDR next_addr) {
  _ecv_u32v2_t vec = UReadMVI32(src_mem);
  return {vec[0], vec[1], Read(next_addr)};
}

DEF_SEM_U64U64U64_RUN(LoadPairUpdateIndex64, MVI128W src_mem, ADDR next_addr) {
  _ecv_u64v2_t vec = UReadMVI64(src_mem);
  return {vec[0], vec[1], Read(next_addr)};
}

}  // namespace

DEF_ISEL(LDP_32_LDSTPAIR_PRE) = LoadPairUpdateIndex32;  // LDP  <Wt1>, <Wt2>, [<Xn|SP>, #<imm>]!
DEF_ISEL(LDP_32_LDSTPAIR_POST) = LoadPairUpdateIndex32;  // LDP  <Wt1>, <Wt2>, [<Xn|SP>], #<imm>

DEF_ISEL(LDP_64_LDSTPAIR_PRE) = LoadPairUpdateIndex64;  // LDP  <Xt1>, <Xt2>, [<Xn|SP>, #<imm>]!
DEF_ISEL(LDP_64_LDSTPAIR_POST) = LoadPairUpdateIndex64;  // LDP  <Xt1>, <Xt2>, [<Xn|SP>], #<imm>

namespace {

DEF_SEM_U64U64_RUN(LoadPair32, R32W dst1, R32W dst2, MVI64W src_mem) {
  _ecv_u32v2_t vec = UReadMVI32(src_mem);
  return {ZExtTo<uint64_t>(vec[0]), ZExtTo<uint64_t>(vec[1])};
}

DEF_SEM_U64U64_RUN(LoadPair64, MVI128W src_mem) {
  _ecv_u64v2_t vec = UReadMVI64(src_mem);
  return {vec[0], vec[1]};
}

}  // namespace

DEF_ISEL(LDP_32_LDSTPAIR_OFF) = LoadPair32;  // LDP  <Wt1>, <Wt2>, [<Xn|SP>{, #<imm>}]
DEF_ISEL(LDP_64_LDSTPAIR_OFF) = LoadPair64;  // LDP  <Xt1>, <Xt2>, [<Xn|SP>{, #<imm>}]

namespace {

DEF_SEM_U64U64_RUN(LoadSignedPair64, MVI64W src_mem) {
  _ecv_i32v2_t vec = SReadMVI32(src_mem);
  return {ZExtTo<uint64_t>(SExtTo<int64_t>(vec[0])), ZExtTo<uint64_t>(SExtTo<int64_t>(vec[1]))};
}

DEF_SEM_U64U64U64_RUN(LoadSignedPairUpdateIndex64, MVI64W src_mem, ADDR next_addr) {
  _ecv_i32v2_t vec = SReadMVI32(src_mem);
  return {ZExtTo<uint64_t>(SExtTo<int64_t>(vec[0])), ZExtTo<uint64_t>(SExtTo<int64_t>(vec[1])),
          Read(next_addr)};
}

}  // namespace

DEF_ISEL(LDPSW_64_LDSTPAIR_OFF) = LoadSignedPair64;  // LDPSW <Xt1>, <Xt2>, [<Xn|SP>], #<imm>
DEF_ISEL(LDPSW_64_LDSTPAIR_PRE) =
    LoadSignedPairUpdateIndex64;  // LDPSW  <Xt1>, <Xt2>, [<Xn|SP>, #<imm>]!
DEF_ISEL(LDPSW_64_LDSTPAIR_POST) =
    LoadSignedPairUpdateIndex64;  // LDPSW  <Xt1>, <Xt2>, [<Xn|SP>], #<imm>

namespace {

template <typename S>  // e.g. Load<I8>
DEF_SEM_T_RUN(Load, S src) {
  return Read(src);
}

template <typename S>  // e.g. Load<M8>
DEF_SEM_T_RUN(LoadMem, S src_mem) {
  return ReadMem(src_mem);
}

template <typename S>  // e.g. LoadUpdateIndex<M8>
DEF_SEM_U32U64_RUN(LoadMemUpdateIndex_32, S src_mem, ADDR next_addr) {
  return {ReadMem(src_mem), Read(next_addr)};
}

template <typename S>  // e.g. LoadUpdateIndex<M64>
DEF_SEM_U64U64_RUN(LoadMemUpdateIndex_64, S src_mem, ADDR next_addr) {
  return {ZExtTo<uint64_t>(ReadMem(src_mem)), Read(next_addr)};
}

template <typename M>  // e.g. LoadMemFromOffset<M8>
DEF_SEM_T_RUN(LoadMemFromOffset, M base, ADDR offset) {
  return ReadMem(DisplaceAddress(base, Read(offset)));
}
}  // namespace

DEF_ISEL(LDRB_32_LDST_POS) = LoadMem<M8>;  // LDRB  <Wt>, [<Xn|SP>{, #<pimm>}]
DEF_ISEL(LDRB_32_LDST_IMMPOST) = LoadMemUpdateIndex_32<M8>;  // LDRB  <Wt>, [<Xn|SP>], #<simm>
DEF_ISEL(LDRB_32_LDST_IMMPRE) = LoadMemUpdateIndex_32<M8>;  // LDRB  <Wt>, [<Xn|SP>, #<simm>]!
DEF_ISEL(LDRB_32B_LDST_REGOFF) =
    LoadMemFromOffset<M8>;  // LDRB  <Wt>, [<Xn|SP>, (<Wm>|<Xm>), <extend> {<amount>}]
DEF_ISEL(LDRB_32BL_LDST_REGOFF) =
    LoadMemFromOffset<M8>;  // LDRB  <Wt>, [<Xn|SP>, <Xm>{, LSL <amount>}]

DEF_ISEL(LDRH_32_LDST_POS) = LoadMem<M16>;  // LDRH  <Wt>, [<Xn|SP>{, #<pimm>}]
DEF_ISEL(LDRH_32_LDST_IMMPOST) = LoadMemUpdateIndex_32<M16>;  // LDRH  <Wt>, [<Xn|SP>], #<simm>
DEF_ISEL(LDRH_32_LDST_IMMPRE) = LoadMemUpdateIndex_32<M16>;  // LDRH  <Wt>, [<Xn|SP>, #<simm>]!
DEF_ISEL(LDRH_32_LDST_REGOFF) =
    LoadMemFromOffset<M16>;  // LDRH  <Wt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]

DEF_ISEL(LDR_32_LDST_POS) = LoadMem<M32>;  // LDR  <Wt>, [<Xn|SP>{, #<pimm>}]
DEF_ISEL(LDR_32_LDST_IMMPOST) = LoadMemUpdateIndex_32<M32>;  // LDR  <Wt>, [<Xn|SP>], #<simm>
DEF_ISEL(LDR_32_LDST_IMMPRE) = LoadMemUpdateIndex_32<M32>;  // LDR  <Wt>, [<Xn|SP>, #<simm>]!
DEF_ISEL(LDR_32_LDST_REGOFF) =
    LoadMemFromOffset<M32>;  // LDR  <Wt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
DEF_ISEL(LDR_32_LOADLIT) = LoadMem<M32>;  // LDR  <Wt>, <label>

DEF_ISEL(LDR_64_LDST_POS) = LoadMem<M64>;  // LDR  <Xt>, [<Xn|SP>{, #<pimm>}]
DEF_ISEL(LDR_64_LDST_IMMPOST) = LoadMemUpdateIndex_64<M64>;  // LDR  <Xt>, [<Xn|SP>], #<simm>
DEF_ISEL(LDR_64_LDST_IMMPRE) = LoadMemUpdateIndex_64<M64>;  // LDR  <Xt>, [<Xn|SP>, #<simm>]!
DEF_ISEL(LDR_64_LDST_REGOFF) =
    LoadMemFromOffset<M64>;  // LDR  <Xt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
DEF_ISEL(LDR_64_LOADLIT) = LoadMem<M64>;  // LDRSW  <Xt>, <label>

DEF_ISEL(LDURB_32_LDST_UNSCALED) = LoadMem<M8>;  // LDURB  <Wt>, [<Xn|SP>{, #<simm>}]
DEF_ISEL(LDURH_32_LDST_UNSCALED) = LoadMem<M16>;  // LDURH  <Wt>, [<Xn|SP>{, #<simm>}]
DEF_ISEL(LDUR_32_LDST_UNSCALED) = LoadMem<M32>;  // LDUR  <Wt>, [<Xn|SP>{, #<simm>}]
DEF_ISEL(LDUR_64_LDST_UNSCALED) = LoadMem<M64>;  // LDUR  <Xt>, [<Xn|SP>{, #<simm>}]

DEF_ISEL(STURB_32_LDST_UNSCALED) = Store<R32, M8W>;  // STURB  <Wt>, [<Xn|SP>{, #<simm>}]
DEF_ISEL(STURH_32_LDST_UNSCALED) = Store<R32, M16W>;  // STURH  <Wt>, [<Xn|SP>{, #<simm>}]
DEF_ISEL(STUR_32_LDST_UNSCALED) = Store<R32, M32W>;  // STUR  <Wt>, [<Xn|SP>{, #<simm>}]
DEF_ISEL(STUR_64_LDST_UNSCALED) = Store<R64, M64W>;  // STUR  <Xt>, [<Xn|SP>{, #<simm>}]

DEF_ISEL(MOVZ_32_MOVEWIDE) = Load<I32>;  // MOVZ  <Wd>, #<imm>{, LSL #<shift>}
DEF_ISEL(MOVZ_64_MOVEWIDE) = Load<I64>;  // MOVZ  <Xd>, #<imm>{, LSL #<shift>}


namespace {

template <typename S>  // e.g. LDXR<R32W, M32>
DEF_SEM_U32U64_RUN(LDXR_32, S src_mem, R64W monitor) {
  return {ReadMem(src_mem), AddressOf(src_mem)};
}

template <typename S>  // e.g. LDXR<R32W, M32>
DEF_SEM_U64U64_RUN(LDXR_64, S src_mem, R64W monitor) {
  return {ReadMem(src_mem), AddressOf(src_mem)};
}

template <typename S>  // e.g. LDAXR<R32W, M32>
DEF_SEM_U32U64_RUN(LDAXR_32, S src_mem, R64W monitor) {
  __remill_barrier_load_store(runtime_manager);
  return {ReadMem(src_mem), AddressOf(src_mem)};
}

template <typename S>  // e.g. LDAXR<R32W, M32>
DEF_SEM_U64U64_RUN(LDAXR_64, S src_mem, R64W monitor) {
  __remill_barrier_load_store(runtime_manager);
  return {ReadMem(src_mem), AddressOf(src_mem)};
}

template <typename S, typename D>  // e.g. STLXR<R32, M32W>
DEF_SEM_U32U64_RUN(STLXR, S src1, D dst, R64 monitor) {
  auto old_addr = Read(monitor);
  uint32_t check;
  if (old_addr == AddressOf(dst)) {
    MWriteZExt(dst, Read(src1));
    check = 0;  // Store succeeded.
  } else {
    check = 1;  // Store failed.
  }
  __remill_barrier_store_store(runtime_manager);
  return {check, 0_u64};
}

template <typename S, typename D>  // e.g. STXR<R32, M32W>
DEF_SEM_U32U64_RUN(STXR, S src1, D dst, R64 monitor) {
  auto old_addr = Read(monitor);
  uint32_t check;
  if (old_addr == AddressOf(dst)) {
    MWriteZExt(dst, Read(src1));
    check = 0;  // Store succeeded.
  } else {
    check = 1;  // Store failed.
  }
  __remill_barrier_store_store(runtime_manager);
  return {check, 0_u64};
}

}  // namespace

DEF_ISEL(LDXR_LR32_LDSTEXCL) =
    LDXR_32<M32>;  // LDAXR  <Wt>, [<Xn|SP>{,#0}] // LDXR  <Wt>, [<Xn|SP>{,#0}]
DEF_ISEL(LDXR_LR64_LDSTEXCL) =
    LDXR_64<M64>;  // LDAXR  <Xt>, [<Xn|SP>{,#0}]  // LDXR  <Xt>, [<Xn|SP>{,#0}]
DEF_ISEL(LDAXR_LR32_LDSTEXCL) = LDAXR_32<M32>;  // LDAXR  <Wt>, [<Xn|SP>{,#0}]
DEF_ISEL(LDAXR_LR64_LDSTEXCL) = LDAXR_64<M64>;  // LDAXR  <Xt>, [<Xn|SP>{,#0}]
DEF_ISEL(STLXR_SR32_LDSTEXCL) = STLXR<R32, M32W>;  // STLXR  <Ws>, <Wt>, [<Xn|SP>{,#0}]
DEF_ISEL(STLXR_SR64_LDSTEXCL) = STLXR<R64, M64W>;  // STLXR  <Ws>, <Xt>, [<Xn|SP>{,#0}]
DEF_ISEL(STXR_SR32_LDSTEXCL) = STXR<R32, M32W>;  // STXR  <Ws>, <Wt>, [<Xn|SP>{,#0}]
DEF_ISEL(STXR_SR64_LDSTEXCL) = STXR<R64, M64W>;  // STXR  <Ws>, <Xt>, [<Xn|SP>{,#0}]

namespace {

template <typename S, typename InterType>  // e.g. LoadSExt<M8, int32_t>
DEF_SEM_U32_RUN(LoadSExt32, S src_mem) {
  return static_cast<uint32_t>(SExtTo<InterType>(ReadMem(src_mem)));
}

template <typename S, typename InterType>  // e.g. LoadSExt<M8, int32_t>
DEF_SEM_U64_RUN(LoadSExt, S src_mem) {
  return static_cast<uint64_t>(SExtTo<InterType>(ReadMem(src_mem)));
}

template <typename S, typename InterType>  // e.g. LoadSExtUpdateIndex<M8, int32_t>
DEF_SEM_U32U64_RUN(LoadSExtUpdateIndex32, S src_mem, ADDR next_addr) {
  return {static_cast<uint32_t>(SExtTo<InterType>(ReadMem(src_mem))), Read(next_addr)};
}

template <typename S, typename InterType>  // e.g. LoadSExtUpdateIndex<M8, int32_t>
DEF_SEM_U64U64_RUN(LoadSExtUpdateIndex64, S src_mem, ADDR next_addr) {
  return {static_cast<uint64_t>(SExtTo<InterType>(ReadMem(src_mem))), Read(next_addr)};
}

template <typename M, typename InterType>  // e.g. LoadSExtFromOffset<M8, int32_t>
DEF_SEM_U32_RUN(LoadSExtFromOffset32, M base, ADDR offset) {
  return static_cast<uint32_t>(SExtTo<InterType>(ReadMem(DisplaceAddress(base, Read(offset)))));
}

template <typename M, typename InterType>  // e.g. LoadSExtFromOffset<M8, int32_t>
DEF_SEM_U64_RUN(LoadSExtFromOffset64, M base, ADDR offset) {
  return static_cast<uint64_t>(SExtTo<InterType>(ReadMem(DisplaceAddress(base, Read(offset)))));
}

}  // namespace

DEF_ISEL(LDURSB_32_LDST_UNSCALED) = LoadSExt<M8, int32_t>;  // LDURSB  <Wt>, [<Xn|SP>{, #<simm>}]
DEF_ISEL(LDURSH_32_LDST_UNSCALED) = LoadSExt<M16, int32_t>;  // LDURSH  <Wt>, [<Xn|SP>{, #<simm>}]
DEF_ISEL(LDURSH_64_LDST_UNSCALED) = LoadSExt<M16, int64_t>;  // LDURSH  <Xt>, [<Xn|SP>{, #<simm>}]
DEF_ISEL(LDURSW_64_LDST_UNSCALED) = LoadSExt<M32, int64_t>;  // LDURSW  <Xt>, [<Xn|SP>{, #<simm>}]

DEF_ISEL(LDRSB_32_LDST_POS) = LoadSExt<M8, int32_t>;  // LDRSB  <Wt>, [<Xn|SP>{, #<pimm>}]
DEF_ISEL(LDRSB_64_LDST_POS) = LoadSExt<M8, int64_t>;  // LDRSB  <Xt>, [<Xn|SP>{, #<pimm>}]
DEF_ISEL(LDRSB_32_LDST_IMMPOST) =
    LoadSExtUpdateIndex32<M8, int32_t>;  // LDRSB  <Wt>, [<Xn|SP>], #<simm>
DEF_ISEL(LDRSB_64_LDST_IMMPOST) =
    LoadSExtUpdateIndex64<M8, int64_t>;  // LDRSB  <Xt>, [<Xn|SP>], #<simm>
DEF_ISEL(LDRSB_32_LDST_IMMPRE) =
    LoadSExtUpdateIndex32<M8, int32_t>;  // LDRSB  <Wt>, [<Xn|SP>, #<simm>]!
DEF_ISEL(LDRSB_64_LDST_IMMPRE) =
    LoadSExtUpdateIndex64<M8, int64_t>;  // LDRSB  <Xt>, [<Xn|SP>, #<simm>]!
DEF_ISEL(LDRSB_32B_LDST_REGOFF) =
    LoadSExtFromOffset32<M8, int32_t>;  // LDRSB  <Wt>, [<Xn|SP>, (<Wm>|<Xm>), <extend> {<amount>}]
DEF_ISEL(LDRSB_32BL_LDST_REGOFF) =
    LoadSExtFromOffset32<M8, int32_t>;  // LDRSB  <Wt>, [<Xn|SP>, <Xm>{, LSL <amount>}]
DEF_ISEL(LDRSB_64B_LDST_REGOFF) =
    LoadSExtFromOffset64<M8, int64_t>;  // LDRSB  <Xt>, [<Xn|SP>, (<Wm>|<Xm>), <extend> {<amount>}]
DEF_ISEL(LDRSB_64BL_LDST_REGOFF) =
    LoadSExtFromOffset64<M8, int64_t>;  // LDRSB  <Xt>, [<Xn|SP>, <Xm>{, LSL <amount>}]

DEF_ISEL(LDRSH_32_LDST_POS) = LoadSExt<M16, int32_t>;  // LDRH  <Wt>, [<Xn|SP>{, #<pimm>}]
DEF_ISEL(LDRSH_64_LDST_POS) = LoadSExt<M16, int64_t>;  // LDRSH  <Xt>, [<Xn|SP>{, #<pimm>}]
DEF_ISEL(LDRSH_32_LDST_IMMPOST) =
    LoadSExtUpdateIndex32<M16, int32_t>;  // LDRH  <Wt>, [<Xn|SP>], #<simm>
DEF_ISEL(LDRSH_64_LDST_IMMPOST) =
    LoadSExtUpdateIndex64<M16, int64_t>;  // LDRSH  <Xt>, [<Xn|SP>], #<simm>
DEF_ISEL(LDRSH_32_LDST_IMMPRE) =
    LoadSExtUpdateIndex32<M16, int32_t>;  // LDRSH  <Wt>, [<Xn|SP>, #<simm>]!
DEF_ISEL(LDRSH_64_LDST_IMMPRE) =
    LoadSExtUpdateIndex64<M16, int64_t>;  // LDRSH  <Xt>, [<Xn|SP>, #<simm>]!
DEF_ISEL(LDRSH_32_LDST_REGOFF) = LoadSExtFromOffset32<
    M16, int32_t>;  // LDRSH  <Wt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
DEF_ISEL(LDRSH_64_LDST_REGOFF) = LoadSExtFromOffset64<
    M16, int64_t>;  // LDRSH  <Xt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]

DEF_ISEL(LDRSW_64_LDST_POS) = LoadSExt<M32, int64_t>;  // LDRSW  <Xt>, [<Xn|SP>{, #<pimm>}]
DEF_ISEL(LDRSW_64_LDST_IMMPOST) =
    LoadSExtUpdateIndex64<M32, int64_t>;  // LDRSW  <Xt>, [<Xn|SP>], #<simm>
DEF_ISEL(LDRSW_64_LDST_IMMPRE) =
    LoadSExtUpdateIndex64<M32, int64_t>;  // LDRSW  <Xt>, [<Xn|SP>, #<simm>]!
DEF_ISEL(LDRSW_64_LDST_REGOFF) = LoadSExtFromOffset64<
    M32, int64_t>;  // LDRSW  <Xt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
DEF_ISEL(LDRSW_64_LOADLIT) = LoadSExt<M32, int64_t>;  // LDRSW  <Xt>, <label>

namespace {

template <typename D, typename S>
DEF_SEM_T(MoveWithKeep, S src, I64 imm, I8 shift_) {
  auto shift = ZExtTo<uint64_t>(Read(shift_));
  auto val = UShl(Read(imm), shift);
  auto mask = UNot(UShl((0xFFFFULL), shift));
  auto reg = ZExtTo<uint64_t>(Read(src));
  return UOr(UAnd(reg, mask), val);
}

DEF_SEM_F32(FMOV_Imm32, F32 imm) {
  auto val = Read(imm);
  return val;
}

DEF_SEM_F64(FMOV_Imm64, F64 imm) {
  auto val = Read(imm);
  return val;
}

DEF_SEM_F32(FMOV_I32ToF32, R32 src) {
  auto val = Read(src);
  return *reinterpret_cast<float32_t *>(&val);
}

DEF_SEM_U32(FMOV_F32ToI32, RF32 src) {
  auto float_val = Read(src);
  return *reinterpret_cast<uint32_t *>(&float_val);
}

DEF_SEM_F64(FMOV_I64ToF64, R64 src) {
  auto val = Read(src);
  return *reinterpret_cast<float64_t *>(&val);
}

DEF_SEM_U64(FMOV_F64ToI64, RF64 src) {
  auto float_val = Read(src);
  return *reinterpret_cast<uint64_t *>(&float_val);
}

DEF_SEM_F32(FMOV_S, RF32 src) {
  return Read(src);
}

DEF_SEM_F64(FMOV_D, RF64 src) {
  return Read(src);
}
}  // namespace

DEF_ISEL(MOVK_32_MOVEWIDE) = MoveWithKeep<R32W, R32>;  // MOVK  <Wd>, #<imm>{, LSL #<shift>}
DEF_ISEL(MOVK_64_MOVEWIDE) = MoveWithKeep<R64W, R64>;  // MOVK  <Xd>, #<imm>{, LSL #<shift>}

// Shifting and negating of the immediate happens in the post-decoder.
DEF_ISEL(MOVN_32_MOVEWIDE) = Load<I32>;  // MOVN  <Wd>, #<imm>{, LSL #<shift>}
DEF_ISEL(MOVN_64_MOVEWIDE) = Load<I64>;  // MOVN  <Xd>, #<imm>{, LSL #<shift>}

DEF_ISEL(FMOV_H_FLOATIMM) = FMOV_Imm32;  // FMOV  <Hd>, #<imm>
DEF_ISEL(FMOV_S_FLOATIMM) = FMOV_Imm32;  // FMOV  <Sd>, #<imm>
DEF_ISEL(FMOV_D_FLOATIMM) = FMOV_Imm64;  // FMOV  <Dd>, #<imm>

DEF_ISEL(FMOV_32S_FLOAT2INT) = FMOV_F32ToI32;  // FMOV  <Wd>, <Sn>
DEF_ISEL(FMOV_S32_FLOAT2INT) = FMOV_I32ToF32;  // FMOV  <Sd>, <Wn>

DEF_ISEL(FMOV_64D_FLOAT2INT) = FMOV_F64ToI64;  // FMOV  <Xd>, <Dn>
DEF_ISEL(FMOV_D64_FLOAT2INT) = FMOV_I64ToF64;  // FMOV  <Dd>, <Xn>

DEF_ISEL(FMOV_S_FLOATDP1) = FMOV_S;  // FMOV  <Sd>, <Sn>
DEF_ISEL(FMOV_D_FLOATDP1) = FMOV_D;  // FMOV  <Dd>, <Dn>

namespace {

DEF_SEM_U64(ADRP, PC label) {
  addr_t label_addr = Read(label);

  // clear the bottom 12 bits of label_addr
  // to make this page aligned
  // the Post decoding already made the label page aligned
  // and added the label to PC
  // the semantics just needs to fix up for PC not being page aligned
  auto label_page = UAnd(UNot(static_cast<uint64_t>(4095)), label_addr);
  return label_page;
}

}  // namespace

DEF_ISEL(ADRP_ONLY_PCRELADDR) = ADRP;  // ADRP  <Xd>, <label>

DEF_ISEL(ADR_ONLY_PCRELADDR) = Load<I64>;  // ADR  <Xd>, <label>

namespace {

// DEF_SEM_U8_RUN(LDR_B, MVI8 src) {
//   return UReadMVI8(src)[0];
// }

// DEF_SEM_U16_RUN(LDR_H, MVI16 src) {
//   return UReadMVI16(src)[0];
// }

DEF_SEM_F32_RUN(LDR_S, MVI32 src_mem) {
  return FReadMVI32(src_mem)[0];
}

DEF_SEM_F64_RUN(LDR_D, MVI64 src_mem) {
  return FReadMVI64(src_mem)[0];
}

DEF_SEM_U128_RUN(LDR_Q, MVI128 src_mem) {
  return UReadMVI128(src_mem)[0];
}

// DEF_SEM(LDR_B_UpdateIndex, VI128W dst, MVI8 src, ADDR next_addr) {
//   UWriteVI8(dst, UReadVI8(src));
//   Write(dst_reg, Read(next_addr));
// }

// DEF_SEM(LDR_H_UpdateIndex, VI128W dst, MVI16 src, ADDR next_addr) {
//   UWriteVI16(dst, UReadVI16(src));
//   Write(dst_reg, Read(next_addr));
// }

DEF_SEM_F32U64_RUN(LDR_S_UpdateIndex, MVI32 src_mem, ADDR next_addr) {
  return {FReadMVI32(src_mem)[0], Read(next_addr)};
}

DEF_SEM_F64U64_RUN(LDR_D_UpdateIndex, MVI64 src_mem, ADDR next_addr) {
  return {FReadMVI64(src_mem)[0], Read(next_addr)};
}

DEF_SEM_U128U64_RUN(LDR_Q_UpdateIndex, MVI128 src_mem, ADDR next_addr) {
  return {UReadMVI128(src_mem)[0], Read(next_addr)};
}

// DEF_SEM(LDR_B_FromOffset, VI128W dst, MVI8 src, ADDR offset) {
//   UWriteVI8(dst, UReadVI8(DisplaceAddress(src, Read(offset))));
// }

// DEF_SEM(LDR_H_FromOffset, VI128W dst, MVI16 src, ADDR offset) {
//   UWriteVI16(dst, UReadVI16(DisplaceAddress(src, Read(offset))));
// }

DEF_SEM_F32_RUN(LDR_S_FromOffset, MVI32 src_mem, ADDR offset) {
  return FReadMVI32(DisplaceAddress(src_mem, Read(offset)))[0];
}

DEF_SEM_F64_RUN(LDR_D_FromOffset, MVI64 src_mem, ADDR offset) {
  return FReadMVI64(DisplaceAddress(src_mem, Read(offset)))[0];
}

DEF_SEM_U128_RUN(LDR_Q_FromOffset, MVI128 src, ADDR offset) {
  return UReadMVI128(DisplaceAddress(src, Read(offset)))[0];
}

}  // namespace

// DEF_ISEL(LDR_B_LDST_POS) = LDR_B;  // LDR  <Bt>, [<Xn|SP>{, #<pimm>}]
// DEF_ISEL(LDR_H_LDST_POS) = LDR_H;  // LDR  <Ht>, [<Xn|SP>{, #<pimm>}]
DEF_ISEL(LDR_S_LDST_POS) = LDR_S;  // LDR  <St>, [<Xn|SP>{, #<pimm>}]
DEF_ISEL(LDR_D_LDST_POS) = LDR_D;  // LDR  <Dt>, [<Xn|SP>{, #<pimm>}]
DEF_ISEL(LDR_Q_LDST_POS) = LDR_Q;  // LDR  <Qt>, [<Xn|SP>{, #<pimm>}]

// DEF_ISEL(LDUR_B_LDST_UNSCALED) = LDR_B;  // LDUR  <Bt>, [<Xn|SP>{, #<simm>}]
// DEF_ISEL(LDUR_H_LDST_UNSCALED) = LDR_H;  // LDUR  <Ht>, [<Xn|SP>{, #<simm>}]
DEF_ISEL(LDUR_S_LDST_UNSCALED) = LDR_S;  // LDUR  <St>, [<Xn|SP>{, #<simm>}]
DEF_ISEL(LDUR_D_LDST_UNSCALED) = LDR_D;  // LDUR  <Dt>, [<Xn|SP>{, #<simm>}]
DEF_ISEL(LDUR_Q_LDST_UNSCALED) = LDR_Q;  // LDUR  <Qt>, [<Xn|SP>{, #<simm>}]

DEF_ISEL(LDR_S_LOADLIT) = LDR_S;  // LDR  <St>, <label>
DEF_ISEL(LDR_D_LOADLIT) = LDR_D;  // LDR  <Dt>, <label>
DEF_ISEL(LDR_Q_LOADLIT) = LDR_Q;  // LDR  <Qt>, <label>

// DEF_ISEL(LDR_B_LDST_IMMPRE) = LDR_B_UpdateIndex;  // LDR  <Bt>, [<Xn|SP>, #<simm>]!
// DEF_ISEL(LDR_H_LDST_IMMPRE) = LDR_H_UpdateIndex;  // LDR  <Ht>, [<Xn|SP>, #<simm>]!
DEF_ISEL(LDR_S_LDST_IMMPRE) = LDR_S_UpdateIndex;  // LDR  <St>, [<Xn|SP>, #<simm>]!
DEF_ISEL(LDR_D_LDST_IMMPRE) = LDR_D_UpdateIndex;  // LDR  <Dt>, [<Xn|SP>, #<simm>]!
DEF_ISEL(LDR_Q_LDST_IMMPRE) = LDR_Q_UpdateIndex;  // LDR  <Qt>, [<Xn|SP>, #<simm>]!

// DEF_ISEL(LDR_B_LDST_IMMPOST) = LDR_B_UpdateIndex;  // LDR  <Bt>, [<Xn|SP>], #<simm>
// DEF_ISEL(LDR_H_LDST_IMMPOST) = LDR_H_UpdateIndex;  // LDR  <Ht>, [<Xn|SP>], #<simm>
DEF_ISEL(LDR_S_LDST_IMMPOST) = LDR_S_UpdateIndex;  // LDR  <St>, [<Xn|SP>], #<simm>
DEF_ISEL(LDR_D_LDST_IMMPOST) = LDR_D_UpdateIndex;  // LDR  <Dt>, [<Xn|SP>], #<simm>
DEF_ISEL(LDR_Q_LDST_IMMPOST) = LDR_Q_UpdateIndex;  // LDR  <Qt>, [<Xn|SP>], #<simm>

// DEF_ISEL(LDR_B_LDST_REGOFF) =
//     LDR_B_FromOffset;  // LDR  <Bt>, [<Xn|SP>, (<Wm>|<Xm>), <extend> {<amount>}]
// DEF_ISEL(LDR_BL_LDST_REGOFF) =
//     LDR_B_FromOffset;  // LDR  <Bt>, [<Xn|SP>, (<Wm>|<Xm>), <extend> {<amount>}]
// DEF_ISEL(LDR_H_LDST_REGOFF) =
//     LDR_H_FromOffset;  // LDR  <Ht>, [<Xn|SP>, (<Wm>|<Xm>), <extend> {<amount>}]
DEF_ISEL(LDR_S_LDST_REGOFF) =
    LDR_S_FromOffset;  // LDR  <St>, [<Xn|SP>, (<Wm>|<Xm>), <extend> {<amount>}]
DEF_ISEL(LDR_D_LDST_REGOFF) =
    LDR_D_FromOffset;  // LDR  <Dt>, [<Xn|SP>, (<Wm>|<Xm>), <extend> {<amount>}]
DEF_ISEL(LDR_Q_LDST_REGOFF) =
    LDR_Q_FromOffset;  // LDR  <Qt>, [<Xn|SP>, (<Wm>|<Xm>), <extend> {<amount>}]

namespace {

// DEF_SEM(LDP_S, VI128W dst1, VI128W dst2, MVI64 src) {
//   auto src_vec = FReadVI32(src);
//   FWriteVI32(dst1, FExtractVI32(src_vec, 0));
//   FWriteVI32(dst2, FExtractVI32(src_vec, 1));
// }

// DEF_SEM(LDP_D, VI128W dst1, VI128W dst2, MVI128W src) {
//   auto src_vec = FReadVI64(src);
//   FWriteVI64(dst1, FExtractVI64(src_vec, 0));
//   FWriteVI64(dst2, FExtractVI64(src_vec, 1));
// }

// DEF_SEM(LDP_Q, VI128W dst1, VI128W dst2, MV256 src) {
//   auto src_vec = UReadVI128(src);
//   UWriteVI128(dst1, UExtractVI128(src_vec, 0));
//   UWriteVI128(dst2, UExtractVI128(src_vec, 1));
// }

// DEF_SEM(LDP_S_UpdateIndex, VI128W dst1, VI128W dst2, MVI64 src, ADDR next_addr) {
//   auto src_vec = FReadVI32(src);
//   FWriteVI32(dst1, FExtractVI32(src_vec, 0));
//   FWriteVI32(dst2, FExtractVI32(src_vec, 1));
//   Write(dst_reg, Read(next_addr));
// }

// DEF_SEM(LDP_D_UpdateIndex, VI128W dst1, VI128W dst2, MVI128W src, ADDR next_addr) {
//   auto src_vec = FReadVI64(src);
//   FWriteVI64(dst1, FExtractVI64(src_vec, 0));
//   FWriteVI64(dst2, FExtractVI64(src_vec, 1));
//   Write(dst_reg, Read(next_addr));
// }

// DEF_SEM(LDP_Q_UpdateIndex, VI128W dst1, VI128W dst2, MV256 src, ADDR next_addr) {
//   auto src_vec = UReadVI128(src);
//   UWriteVI128(dst1, UExtractVI128(src_vec, 0));
//   UWriteVI128(dst2, UExtractVI128(src_vec, 1));
//   Write(dst_reg, Read(next_addr));
// }

}  // namespace

// DEF_ISEL(LDP_S_LDSTPAIR_OFF) = LDP_S;  // LDP  <St1>, <St2>, [<Xn|SP>{, #<imm>}]
// DEF_ISEL(LDP_D_LDSTPAIR_OFF) = LDP_D;  // LDP  <Dt1>, <Dt2>, [<Xn|SP>{, #<imm>}]
// DEF_ISEL(LDP_Q_LDSTPAIR_OFF) = LDP_Q;  // LDP  <Qt1>, <Qt2>, [<Xn|SP>{, #<imm>}]

// DEF_ISEL(LDP_S_LDSTPAIR_POST) = LDP_S_UpdateIndex;  // LDP  <St1>, <St2>, [<Xn|SP>], #<imm>
// DEF_ISEL(LDP_D_LDSTPAIR_POST) = LDP_D_UpdateIndex;  // LDP  <Dt1>, <Dt2>, [<Xn|SP>], #<imm>
// DEF_ISEL(LDP_Q_LDSTPAIR_POST) = LDP_Q_UpdateIndex;  // LDP  <Qt1>, <Qt2>, [<Xn|SP>], #<imm>

// DEF_ISEL(LDP_S_LDSTPAIR_PRE) = LDP_S_UpdateIndex;  // LDP  <St1>, <St2>, [<Xn|SP>, #<imm>]!
// DEF_ISEL(LDP_D_LDSTPAIR_PRE) = LDP_D_UpdateIndex;  // LDP  <Dt1>, <Dt2>, [<Xn|SP>, #<imm>]!
// DEF_ISEL(LDP_Q_LDSTPAIR_PRE) = LDP_Q_UpdateIndex;  // LDP  <Qt1>, <Qt2>, [<Xn|SP>, #<imm>]!

namespace {

// DEF_SEM(STR_B, VI8 src, MVI8W dst) {
//   UWriteVI8(dst, UReadVI8(src));
// }

// DEF_SEM(STR_H, VI16 src, MVI16W dst) {
//   UWriteVI16(dst, UReadVI16(src));
// }

// DEF_SEM(STR_S, VI32 src, MVI32W dst) {
//   FWriteVI32(dst, FReadVI32(src));
// }

// DEF_SEM(STR_D, VI64 src, MVI64W dst) {
//   FWriteVI64(dst, FReadVI64(src));
// }

// DEF_SEM(STR_Q, VI128 src, MVI128W dst) {
//   UWriteVI128(dst, UReadVI128(src));
// }

// DEF_SEM(STR_Q_UpdateIndex, VI128 src, MVI128W dst, ADDR next_addr) {
//   UWriteVI128(dst, UReadVI128(src));
//   Write(dst_reg, Read(next_addr));
// }

// DEF_SEM(STR_Q_FromOffset, VI128 src, MVI128W dst, ADDR offset) {
//   UWriteVI128(DisplaceAddress(dst, Read(offset)), UReadVI128(src));
// }
}  // namespace

// DEF_ISEL(STR_B_LDST_POS) = STR_B;  // STR  <Bt>, [<Xn|SP>{, #<pimm>}]
// DEF_ISEL(STR_H_LDST_POS) = STR_H;  // STR  <Ht>, [<Xn|SP>{, #<pimm>}]
// DEF_ISEL(STR_S_LDST_POS) = STR_S;  // STR  <St>, [<Xn|SP>{, #<pimm>}]
// DEF_ISEL(STR_D_LDST_POS) = STR_D;  // STR  <Dt>, [<Xn|SP>{, #<pimm>}]
// DEF_ISEL(STR_Q_LDST_POS) = STR_Q;  // STR  <Qt>, [<Xn|SP>{, #<pimm>}]

// DEF_ISEL(STUR_B_LDST_UNSCALED) = STR_B;  // STUR  <Bt>, [<Xn|SP>{, #<simm>}]
// DEF_ISEL(STUR_H_LDST_UNSCALED) = STR_H;  // STUR  <Ht>, [<Xn|SP>{, #<simm>}]
// DEF_ISEL(STUR_S_LDST_UNSCALED) = STR_S;  // STUR  <St>, [<Xn|SP>{, #<simm>}]
// DEF_ISEL(STUR_D_LDST_UNSCALED) = STR_D;  // STUR  <Dt>, [<Xn|SP>{, #<simm>}]
// DEF_ISEL(STUR_Q_LDST_UNSCALED) = STR_Q;  // STUR  <Qt>, [<Xn|SP>{, #<simm>}]

// DEF_ISEL(STR_Q_LDST_REGOFF) =
//     STR_Q_FromOffset;  // STR  <Qt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]

// DEF_ISEL(STR_Q_LDST_IMMPRE) = STR_Q_UpdateIndex;  // STR  <Qt>, [<Xn|SP>, #<simm>]!
// DEF_ISEL(STR_Q_LDST_IMMPOST) = STR_Q_UpdateIndex;  // STR  <Qt>, [<Xn|SP>], #<simm>

namespace {

// template <typename D, typename S>
// DEF_SEM(LoadAcquire, D dst, S src) {
//   __remill_barrier_load_store(runtime_manager);
//   WriteZExt(dst, Read(src));
// }

}  // namespace

// DEF_ISEL(LDARB_LR32_LDSTEXCL) = LoadAcquire<R32W, M8>;  // LDARB  <Wt>, [<Xn|SP>{,#0}]
// DEF_ISEL(LDARH_LR32_LDSTEXCL) = LoadAcquire<R32W, M16>;  // LDARH  <Wt>, [<Xn|SP>{,#0}]
// DEF_ISEL(LDAR_LR32_LDSTEXCL) = LoadAcquire<R32W, M32>;  // LDAR  <Wt>, [<Xn|SP>{,#0}]
// DEF_ISEL(LDAR_LR64_LDSTEXCL) = LoadAcquire<R64W, M64>;  // LDAR  <Xt>, [<Xn|SP>{,#0}]

namespace {

// #define MAKE_ST1(esize) \
//   template <typename D> \
//   DEF_SEM(ST1_SINGLE_##esize, V##esize src1, D dst) { \
//     auto elems1 = UReadV##esize(src1); \
//     UWriteV##esize(dst, elems1); \
//   }

// MAKE_ST1(64)
// MAKE_ST1(128)

// #undef MAKE_ST1

}  // namespace

// DEF_ISEL(ST1_ASISDLSE_R1_1V_8B) = ST1_SINGLE_64<MVI64W>;  // ST1  { <Vt>.<T> }, [<Xn|SP>]
// DEF_ISEL(ST1_ASISDLSE_R1_1V_16B) = ST1_SINGLE_128<MVI128W>;  // ST1  { <Vt>.<T> }, [<Xn|SP>]

// DEF_ISEL(ST1_ASISDLSE_R1_1V_4H) = ST1_SINGLE_64<MVI64W>;  // ST1  { <Vt>.<T> }, [<Xn|SP>]
// DEF_ISEL(ST1_ASISDLSE_R1_1V_8H) = ST1_SINGLE_128<MVI128W>;  // ST1  { <Vt>.<T> }, [<Xn|SP>]

// DEF_ISEL(ST1_ASISDLSE_R1_1V_2S) = ST1_SINGLE_64<MVI64W>;  // ST1  { <Vt>.<T> }, [<Xn|SP>]
// DEF_ISEL(ST1_ASISDLSE_R1_1V_4S) = ST1_SINGLE_128<MVI128W>;  // ST1  { <Vt>.<T> }, [<Xn|SP>]

// DEF_ISEL(ST1_ASISDLSE_R1_1V_1D) = ST1_SINGLE_64<MVI64W>;  // ST1  { <Vt>.<T> }, [<Xn|SP>]
// DEF_ISEL(ST1_ASISDLSE_R1_1V_2D) = ST1_SINGLE_128<MVI128W>;  // ST1  { <Vt>.<T> }, [<Xn|SP>]

namespace {

// #define MAKE_LD1(esize) \
//   template <typename S> \
//   DEF_SEM(LD1_SINGLE_##esize, VI128W dst1, S src) { \
//     auto elems1 = UReadV##esize(src); \
//     UWriteV##esize(dst1, elems1); \
//   }

// MAKE_LD1(8)
// MAKE_LD1(16)
// MAKE_LD1(32)
// MAKE_LD1(64)

// #undef MAKE_LD1

}  // namespace

// DEF_ISEL(LD1_ASISDLSE_R1_1V_8B) = LD1_SINGLE_8<MVI64>;  // LD1  { <Vt>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD1_ASISDLSE_R1_1V_16B) = LD1_SINGLE_8<MVI128W>;  // LD1  { <Vt>.<T> }, [<Xn|SP>]

// DEF_ISEL(LD1_ASISDLSE_R1_1V_4H) = LD1_SINGLE_16<MVI64>;  // LD1  { <Vt>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD1_ASISDLSE_R1_1V_8H) = LD1_SINGLE_16<MVI128W>;  // LD1  { <Vt>.<T> }, [<Xn|SP>]

// DEF_ISEL(LD1_ASISDLSE_R1_1V_2S) = LD1_SINGLE_32<MVI64>;  // LD1  { <Vt>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD1_ASISDLSE_R1_1V_4S) = LD1_SINGLE_32<MVI128W>;  // LD1  { <Vt>.<T> }, [<Xn|SP>]

// DEF_ISEL(LD1_ASISDLSE_R1_1V_1D) = LD1_SINGLE_64<MVI64>;  // LD1  { <Vt>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD1_ASISDLSE_R1_1V_2D) = LD1_SINGLE_64<MVI128W>;  // LD1  { <Vt>.<T> }, [<Xn|SP>]

namespace {

// #define MAKE_LD1(esize) \
//   template <typename S> \
//   DEF_SEM(LD1_PAIR_##esize, VI128W dst1, VI128W dst2, S src) { \
//     auto elems1 = UReadV##esize(src); \
//     auto elems2 = UReadV##esize(GetElementPtr(src, 1U)); \
//     UWriteV##esize(dst1, elems1); \
//     UWriteV##esize(dst2, elems2); \
//   }

// MAKE_LD1(8)
// MAKE_LD1(16)
// MAKE_LD1(32)
// MAKE_LD1(64)

// #undef MAKE_LD1

}  // namespace

// DEF_ISEL(LD1_ASISDLSE_R2_2V_8B) = LD1_PAIR_8<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD1_ASISDLSE_R2_2V_16B) = LD1_PAIR_8<MVI128W>;  // LD1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]

// DEF_ISEL(LD1_ASISDLSE_R2_2V_4H) = LD1_PAIR_16<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD1_ASISDLSE_R2_2V_8H) = LD1_PAIR_16<MVI128W>;  // LD1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]

// DEF_ISEL(LD1_ASISDLSE_R2_2V_2S) = LD1_PAIR_32<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD1_ASISDLSE_R2_2V_4S) = LD1_PAIR_32<MVI128W>;  // LD1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]

// DEF_ISEL(LD1_ASISDLSE_R2_2V_1D) = LD1_PAIR_64<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD1_ASISDLSE_R2_2V_2D) = LD1_PAIR_64<MVI128W>;  // LD1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]

namespace {

// #define MAKE_ST1(esize) \
//   template <typename D> \
//   DEF_SEM(ST1_PAIR_##esize, V##esize src1, V##esize src2, D dst) { \
//     auto elems1 = UReadV##esize(src1); \
//     auto elems2 = UReadV##esize(src2); \
//     UWriteV##esize(dst, elems1); \
//     UWriteV##esize(GetElementPtr(dst, 1U), elems2); \
//   }

// MAKE_ST1(64)
// MAKE_ST1(128)

// #undef MAKE_ST1

}  //namespace

// DEF_ISEL(ST1_ASISDLSE_R2_2V_8B) = ST1_PAIR_64<MVI64W>;  // ST1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]
// DEF_ISEL(ST1_ASISDLSE_R2_2V_16B) =
//     ST1_PAIR_128<MVI128W>;  // ST1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]

// DEF_ISEL(ST1_ASISDLSE_R2_2V_4H) = ST1_PAIR_64<MVI64W>;  // ST1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]
// DEF_ISEL(ST1_ASISDLSE_R2_2V_8H) = ST1_PAIR_128<MVI128W>;  // ST1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]

// DEF_ISEL(ST1_ASISDLSE_R2_2V_2S) = ST1_PAIR_64<MVI64W>;  // ST1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]
// DEF_ISEL(ST1_ASISDLSE_R2_2V_4S) = ST1_PAIR_128<MVI128W>;  // ST1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]

// DEF_ISEL(ST1_ASISDLSE_R2_2V_1D) = ST1_PAIR_64<MVI64W>;  // ST1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]
// DEF_ISEL(ST1_ASISDLSE_R2_2V_2D) = ST1_PAIR_128<MVI128W>;  // ST1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]

namespace {

// #define MAKE_ST1_POSTINDEX(esize) \
//   template <typename D> \
//   DEF_SEM(ST1_PAIR_POSTINDEX_##esize, V##esize src1, V##esize src2, D dst, R64W addr_reg, \
//           ADDR next_addr) { \
//     ST1_PAIR_##esize(runtime_manager, state, src1, src2, dst); \
//     Write(addr_reg, Read(next_addr)); \
//   }

// MAKE_ST1_POSTINDEX(64)
// MAKE_ST1_POSTINDEX(128)

// #undef MAKE_ST1_POSTINDEX

}  // namespace

// DEF_ISEL(ST1_ASISDLSEP_I2_I2_8B) =
//     ST1_PAIR_POSTINDEX_64<MVI64W>;  // ST1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(ST1_ASISDLSEP_I2_I2_16B) =
//     ST1_PAIR_POSTINDEX_128<MVI128W>;  // ST1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>

// DEF_ISEL(ST1_ASISDLSEP_I2_I2_4H) =
//     ST1_PAIR_POSTINDEX_64<MVI64W>;  // ST1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(ST1_ASISDLSEP_I2_I2_8H) =
//     ST1_PAIR_POSTINDEX_128<MVI128W>;  // ST1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>

// DEF_ISEL(ST1_ASISDLSEP_I2_I2_2S) =
//     ST1_PAIR_POSTINDEX_64<MVI64W>;  // ST1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(ST1_ASISDLSEP_I2_I2_4S) =
//     ST1_PAIR_POSTINDEX_128<MVI128W>;  // ST1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>

// DEF_ISEL(ST1_ASISDLSEP_I2_I2_1D) =
//     ST1_PAIR_POSTINDEX_64<MVI64W>;  // ST1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(ST1_ASISDLSEP_I2_I2_2D) =
//     ST1_PAIR_POSTINDEX_128<MVI128W>;  // ST1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>

namespace {
// #define MAKE_ST1_UNIT(esize) \
//   DEF_SEM(ST1_UNIT_V##esize, VI128 src, I32 index, M##esize##W dst_mem) { \
//     auto src_v = UReadV##esize(src); \
//     uint##esize##_t elem = UExtractV##esize(src_v, Read(index)); \
//     WriteTrunc(dst_mem, elem); \
// \
//   }  // namespace

// MAKE_ST1_UNIT(8)
// MAKE_ST1_UNIT(16)
// MAKE_ST1_UNIT(32)
// MAKE_ST1_UNIT(64)

// #undef MAKE_ST1_UNIT

}  // namespace

// ST1  { <Vt>.B }[<index>], [<Xn|SP>]
// DEF_ISEL(ST1_ASISDLSO_B1_1B) = ST1_UNIT_VI8;  // ST1  { <Vt>.B }[<index>], [<Xn|SP>]
// // ST1  { <Vt>.H }[<index>], [<Xn|SP>]
// DEF_ISEL(ST1_ASISDLSO_H1_1H) = ST1_UNIT_VI16;  // ST1  { <Vt>.H }[<index>], [<Xn|SP>]
// // ST1  { <Vt>.S }[<index>], [<Xn|SP>]
// DEF_ISEL(ST1_ASISDLSO_S1_1S) = ST1_UNIT_VI32;  // ST1  { <Vt>.S }[<index>], [<Xn|SP>]
// // ST1  { <Vt>.D }[<index>], [<Xn|SP>]
// DEF_ISEL(ST1_ASISDLSO_D1_1D) = ST1_UNIT_VI64;  // ST1  { <Vt>.D }[<index>], [<Xn|SP>]

namespace {
// #define MAKE_ST1_UNIT_POSTINDEX(esize) \
//   DEF_SEM(ST1_UNIT_POSTINDEX_V##esize, VI128 src, I32 index, M##esize##W dst_mem, \
//           ADDR next_addr) { \
//     auto src_v = UReadV##esize(src); \
//     uint##esize##_t elem = UExtractV##esize(src_v, Read(index)); \
//     WriteTrunc(dst_mem, elem); \
//     Write(dst_reg, Read(next_addr)); \
// \
//   }  // namespace

// MAKE_ST1_UNIT_POSTINDEX(8)
// MAKE_ST1_UNIT_POSTINDEX(16)
// MAKE_ST1_UNIT_POSTINDEX(32)
// MAKE_ST1_UNIT_POSTINDEX(64)

// #undef MAKE_ST1_UNIT_POSTINDEX

}  // namespace

// ST1  { <Vt>.B }[<index>], [<Xn|SP>], #1
// DEF_ISEL(ST1_ASISDLSOP_B1_I1B) = ST1_UNIT_POSTINDEX_VI8;  // ST1  { <Vt>.B }[<index>], [<Xn|SP>], #1
// // ST1  { <Vt>.B }[<index>], [<Xn|SP>], <Xm>
// DEF_ISEL(ST1_ASISDLSOP_BX1_R1B) =
//     ST1_UNIT_POSTINDEX_VI8;  // ST1  { <Vt>.B }[<index>], [<Xn|SP>], <Xm>
// // ST1  { <Vt>.H }[<index>], [<Xn|SP>], #2
// DEF_ISEL(ST1_ASISDLSOP_H1_I1H) =
//     ST1_UNIT_POSTINDEX_VI16;  // ST1  { <Vt>.H }[<index>], [<Xn|SP>], #2
// // ST1  { <Vt>.H }[<index>], [<Xn|SP>], <Xm>
// DEF_ISEL(ST1_ASISDLSOP_HX1_R1H) =
//     ST1_UNIT_POSTINDEX_VI16;  // ST1  { <Vt>.H }[<index>], [<Xn|SP>], <Xm>
// // ST1  { <Vt>.S }[<index>], [<Xn|SP>], #4
// DEF_ISEL(ST1_ASISDLSOP_S1_I1S) =
//     ST1_UNIT_POSTINDEX_VI32;  // ST1  { <Vt>.S }[<index>], [<Xn|SP>], #4
// // ST1  { <Vt>.S }[<index>], [<Xn|SP>], <Xm>
// DEF_ISEL(ST1_ASISDLSOP_SX1_R1S) =
//     ST1_UNIT_POSTINDEX_VI32;  // ST1  { <Vt>.S }[<index>], [<Xn|SP>], <Xm>
// // ST1  { <Vt>.D }[<index>], [<Xn|SP>], #8
// DEF_ISEL(ST1_ASISDLSOP_D1_I1D) =
//     ST1_UNIT_POSTINDEX_VI64;  // ST1  { <Vt>.D }[<index>], [<Xn|SP>], #8
// // ST1  { <Vt>.D }[<index>], [<Xn|SP>], <Xm>
// DEF_ISEL(ST1_ASISDLSOP_DX1_R1D) =
//     ST1_UNIT_POSTINDEX_VI64;  // ST1  { <Vt>.D }[<index>], [<Xn|SP>], <Xm>

namespace {

// #define MAKE_LD1(esize) \
//   template <typename S> \
//   DEF_SEM(LD1_TRIPLE_##esize, VI128W dst1, VI128W dst2, VI128W dst3, S src) { \
//     auto elems1 = UReadV##esize(src); \
//     auto elems2 = UReadV##esize(GetElementPtr(src, 1U)); \
//     auto elems3 = UReadV##esize(GetElementPtr(src, 2U)); \
//     UWriteV##esize(dst1, elems1); \
//     UWriteV##esize(dst2, elems2); \
//     UWriteV##esize(dst3, elems3); \
//   }

// MAKE_LD1(8)
// MAKE_LD1(16)
// MAKE_LD1(32)
// MAKE_LD1(64)

// #undef MAKE_LD1

}  // namespace

// DEF_ISEL(LD1_ASISDLSE_R3_3V_8B) =
//     LD1_TRIPLE_8<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD1_ASISDLSE_R3_3V_16B) =
//     LD1_TRIPLE_8<MVI128W>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>]

// DEF_ISEL(LD1_ASISDLSE_R3_3V_4H) =
//     LD1_TRIPLE_16<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD1_ASISDLSE_R3_3V_8H) =
//     LD1_TRIPLE_16<MVI128W>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>]

// DEF_ISEL(LD1_ASISDLSE_R3_3V_2S) =
//     LD1_TRIPLE_32<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD1_ASISDLSE_R3_3V_4S) =
//     LD1_TRIPLE_32<MVI128W>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>]

// DEF_ISEL(LD1_ASISDLSE_R3_3V_1D) =
//     LD1_TRIPLE_64<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD1_ASISDLSE_R3_3V_2D) =
//     LD1_TRIPLE_64<MVI128W>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>]

namespace {

// #define MAKE_LD1(esize) \
//   template <typename S> \
//   DEF_SEM(LD1_QUAD_##esize, VI128W dst1, VI128W dst2, VI128W dst3, VI128W dst4, S src) { \
//     auto elems1 = UReadV##esize(src); \
//     auto elems2 = UReadV##esize(GetElementPtr(src, 1U)); \
//     auto elems3 = UReadV##esize(GetElementPtr(src, 2U)); \
//     auto elems4 = UReadV##esize(GetElementPtr(src, 3U)); \
//     UWriteV##esize(dst1, elems1); \
//     UWriteV##esize(dst2, elems2); \
//     UWriteV##esize(dst3, elems3); \
//     UWriteV##esize(dst4, elems4); \
//   }

// MAKE_LD1(8)
// MAKE_LD1(16)
// MAKE_LD1(32)
// MAKE_LD1(64)

// #undef MAKE_LD1

}  // namespace

// DEF_ISEL(LD1_ASISDLSE_R4_4V_8B) =
//     LD1_QUAD_8<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD1_ASISDLSE_R4_4V_16B) =
//     LD1_QUAD_8<MVI128W>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>]

// DEF_ISEL(LD1_ASISDLSE_R4_4V_4H) =
//     LD1_QUAD_16<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD1_ASISDLSE_R4_4V_8H) =
//     LD1_QUAD_16<MVI128W>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>]

// DEF_ISEL(LD1_ASISDLSE_R4_4V_2S) =
//     LD1_QUAD_32<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD1_ASISDLSE_R4_4V_4S) =
//     LD1_QUAD_32<MVI128W>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>]

// DEF_ISEL(LD1_ASISDLSE_R4_4V_1D) =
//     LD1_QUAD_64<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD1_ASISDLSE_R4_4V_2D) =
//     LD1_QUAD_64<MVI128W>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>]

namespace {

// #define MAKE_LD1_POSTINDEX(esize) \
//   template <typename S> \
//   DEF_SEM(LD1_SINGLE_POSTINDEX_##esize, VI128W dst1, S src, R64W addr_reg, ADDR next_addr) { \
//     LD1_SINGLE_##esize(runtime_manager, state, dst1, src); \
//     Write(addr_reg, Read(next_addr)); \
//   }

// MAKE_LD1_POSTINDEX(8)
// MAKE_LD1_POSTINDEX(16)
// MAKE_LD1_POSTINDEX(32)
// MAKE_LD1_POSTINDEX(64)

// #undef MAKE_LD1_POSTINDEX

}  // namespace

// DEF_ISEL(LD1_ASISDLSEP_I1_I1_8B) =
//     LD1_SINGLE_POSTINDEX_8<MVI64>;  // LD1  { <Vt>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD1_ASISDLSEP_I1_I1_16B) =
//     LD1_SINGLE_POSTINDEX_8<MVI128W>;  // LD1  { <Vt>.<T> }, [<Xn|SP>], <imm>

// DEF_ISEL(LD1_ASISDLSEP_I1_I1_4H) =
//     LD1_SINGLE_POSTINDEX_16<MVI64>;  // LD1  { <Vt>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD1_ASISDLSEP_I1_I1_8H) =
//     LD1_SINGLE_POSTINDEX_16<MVI128W>;  // LD1  { <Vt>.<T> }, [<Xn|SP>], <imm>

// DEF_ISEL(LD1_ASISDLSEP_I1_I1_2S) =
//     LD1_SINGLE_POSTINDEX_32<MVI64>;  // LD1  { <Vt>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD1_ASISDLSEP_I1_I1_4S) =
//     LD1_SINGLE_POSTINDEX_32<MVI128W>;  // LD1  { <Vt>.<T> }, [<Xn|SP>], <imm>

// DEF_ISEL(LD1_ASISDLSEP_I1_I1_1D) =
//     LD1_SINGLE_POSTINDEX_64<MVI64>;  // LD1  { <Vt>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD1_ASISDLSEP_I1_I1_2D) =
//     LD1_SINGLE_POSTINDEX_64<MVI128W>;  // LD1  { <Vt>.<T> }, [<Xn|SP>], <imm>

namespace {

// #define MAKE_LD1_POSTINDEX(esize) \
//   template <typename S> \
//   DEF_SEM(LD1_PAIR_POSTINDEX_##esize, VI128W dst1, VI128W dst2, S src, R64W addr_reg, \
//           ADDR next_addr) { \
//     LD1_PAIR_##esize(runtime_manager, state, dst1, dst2, src); \
//     Write(addr_reg, Read(next_addr)); \
//   }

// MAKE_LD1_POSTINDEX(8)
// MAKE_LD1_POSTINDEX(16)
// MAKE_LD1_POSTINDEX(32)
// MAKE_LD1_POSTINDEX(64)

// #undef MAKE_LD1_POSTINDEX

}  // namespace

// DEF_ISEL(LD1_ASISDLSEP_I2_I2_8B) =
//     LD1_PAIR_POSTINDEX_8<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD1_ASISDLSEP_I2_I2_16B) =
//     LD1_PAIR_POSTINDEX_8<MVI128W>;  // LD1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>

// DEF_ISEL(LD1_ASISDLSEP_I2_I2_4H) =
//     LD1_PAIR_POSTINDEX_16<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD1_ASISDLSEP_I2_I2_8H) =
//     LD1_PAIR_POSTINDEX_16<MVI128W>;  // LD1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>

// DEF_ISEL(LD1_ASISDLSEP_I2_I2_2S) =
//     LD1_PAIR_POSTINDEX_32<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD1_ASISDLSEP_I2_I2_4S) =
//     LD1_PAIR_POSTINDEX_32<MVI128W>;  // LD1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>

// DEF_ISEL(LD1_ASISDLSEP_I2_I2_1D) =
//     LD1_PAIR_POSTINDEX_64<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD1_ASISDLSEP_I2_I2_2D) =
//     LD1_PAIR_POSTINDEX_64<MVI128W>;  // LD1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>

namespace {

// #define MAKE_LD1_POSTINDEX(esize) \
//   template <typename S> \
//   DEF_SEM(LD1_TRIPLE_POSTINDEX_##esize, VI128W dst1, VI128W dst2, VI128W dst3, S src, \
//           R64W addr_reg, ADDR next_addr) { \
//     LD1_TRIPLE_##esize(runtime_manager, state, dst1, dst2, dst3, src); \
//     Write(addr_reg, Read(next_addr)); \
//   }

// MAKE_LD1_POSTINDEX(8)
// MAKE_LD1_POSTINDEX(16)
// MAKE_LD1_POSTINDEX(32)
// MAKE_LD1_POSTINDEX(64)

// #undef MAKE_LD1_POSTINDEX

}  // namespace

// DEF_ISEL(LD1_ASISDLSEP_I3_I3_8B) =
//     LD1_TRIPLE_POSTINDEX_8<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD1_ASISDLSEP_I3_I3_16B) =
//     LD1_TRIPLE_POSTINDEX_8<MVI128W>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>], <imm>

// DEF_ISEL(LD1_ASISDLSEP_I3_I3_4H) =
//     LD1_TRIPLE_POSTINDEX_16<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD1_ASISDLSEP_I3_I3_8H) =
//     LD1_TRIPLE_POSTINDEX_16<MVI128W>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>], <imm>

// DEF_ISEL(LD1_ASISDLSEP_I3_I3_2S) =
//     LD1_TRIPLE_POSTINDEX_32<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD1_ASISDLSEP_I3_I3_4S) =
//     LD1_TRIPLE_POSTINDEX_32<MVI128W>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>], <imm>

// DEF_ISEL(LD1_ASISDLSEP_I3_I3_1D) =
//     LD1_TRIPLE_POSTINDEX_64<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD1_ASISDLSEP_I3_I3_2D) =
//     LD1_TRIPLE_POSTINDEX_64<MVI128W>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>], <imm>

namespace {

// #define MAKE_LD1_POSTINDEX(esize) \
//   template <typename S> \
//   DEF_SEM(LD1_QUAD_POSTINDEX_##esize, VI128W dst1, VI128W dst2, VI128W dst3, VI128W dst4, S src, \
//           R64W addr_reg, ADDR next_addr) { \
//     LD1_QUAD_##esize(runtime_manager, state, dst1, dst2, dst3, dst4, src); \
//     Write(addr_reg, Read(next_addr)); \
//   }

// MAKE_LD1_POSTINDEX(8)
// MAKE_LD1_POSTINDEX(16)
// MAKE_LD1_POSTINDEX(32)
// MAKE_LD1_POSTINDEX(64)

// #undef MAKE_LD1_POSTINDEX

}  // namespace

// DEF_ISEL(LD1_ASISDLSEP_I4_I4_8B) = LD1_QUAD_POSTINDEX_8<
//     MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD1_ASISDLSEP_I4_I4_16B) = LD1_QUAD_POSTINDEX_8<
//     MVI128W>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>], <imm>

// DEF_ISEL(LD1_ASISDLSEP_I4_I4_4H) = LD1_QUAD_POSTINDEX_16<
//     MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD1_ASISDLSEP_I4_I4_8H) = LD1_QUAD_POSTINDEX_16<
//     MVI128W>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>], <imm>

// DEF_ISEL(LD1_ASISDLSEP_I4_I4_2S) = LD1_QUAD_POSTINDEX_32<
//     MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD1_ASISDLSEP_I4_I4_4S) = LD1_QUAD_POSTINDEX_32<
//     MVI128W>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>], <imm>

// DEF_ISEL(LD1_ASISDLSEP_I4_I4_1D) = LD1_QUAD_POSTINDEX_64<
//     MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD1_ASISDLSEP_I4_I4_2D) = LD1_QUAD_POSTINDEX_64<
//     MVI128W>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>], <imm>

namespace {

// #define MAKE_LD2(size) \
//   template <typename S> \
//   DEF_SEM(LD2_##size, VI128W dst1, VI128W dst2, S src) { \
//     auto vec = UReadV##size(src); \
//     auto dst1_vec = UClearV##size(UReadV##size(dst1)); \
//     auto dst2_vec = UClearV##size(UReadV##size(dst2)); \
//     _Pragma("unroll") for (size_t i = 0, j = 0; i < NumVectorElems(vec); j++) { \
//       dst1_vec = UInsertV##size(dst1_vec, j, UExtractV##size(vec, i++)); \
//       dst2_vec = UInsertV##size(dst2_vec, j, UExtractV##size(vec, i++)); \
//     } \
//     UWriteV##size(dst1, dst1_vec); \
//     UWriteV##size(dst2, dst2_vec); \
//   }

// MAKE_LD2(8)
// MAKE_LD2(16)
// MAKE_LD2(32)
// MAKE_LD2(64)

// #undef MAKE_LD2

// #define MAKE_LD2(size) \
//   template <typename S> \
//   DEF_SEM(LD2_##size##_POSTINDEX, VI128W dst1, VI128W dst2, S src, R64W addr_reg, \
//           ADDR next_addr) { \
//     LD2_##size(runtime_manager, state, dst1, dst2, src); \
//     Write(addr_reg, Read(next_addr)); \
//   }

// MAKE_LD2(8)
// MAKE_LD2(16)
// MAKE_LD2(32)
// MAKE_LD2(64)

// #undef MAKE_LD2

}  // namespace

// DEF_ISEL(LD2_ASISDLSE_R2_8B) = LD2_8<MVI128W>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD2_ASISDLSE_R2_16B) = LD2_8<MV256>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD2_ASISDLSE_R2_4H) = LD2_16<MVI128W>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD2_ASISDLSE_R2_8H) = LD2_16<MV256>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD2_ASISDLSE_R2_2S) = LD2_32<MVI128W>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD2_ASISDLSE_R2_4S) = LD2_32<MV256>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD2_ASISDLSE_R2_2D) = LD2_64<MV256>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]

// DEF_ISEL(LD2_ASISDLSEP_I2_I_8B) =
//     LD2_8_POSTINDEX<MVI128W>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD2_ASISDLSEP_I2_I_16B) =
//     LD2_8_POSTINDEX<MV256>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD2_ASISDLSEP_I2_I_4H) =
//     LD2_16_POSTINDEX<MVI128W>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD2_ASISDLSEP_I2_I_8H) =
//     LD2_16_POSTINDEX<MV256>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD2_ASISDLSEP_I2_I_2S) =
//     LD2_32_POSTINDEX<MVI128W>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD2_ASISDLSEP_I2_I_4S) =
//     LD2_32_POSTINDEX<MV256>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD2_ASISDLSEP_I2_I_2D) =
//     LD2_64_POSTINDEX<MV256>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>

// DEF_ISEL(LD2_ASISDLSEP_R2_R_8B) =
//     LD2_8_POSTINDEX<MVI128W>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <Xm>
// DEF_ISEL(LD2_ASISDLSEP_R2_R_16B) =
//     LD2_8_POSTINDEX<MV256>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <Xm>
// DEF_ISEL(LD2_ASISDLSEP_R2_R_4H) =
//     LD2_16_POSTINDEX<MVI128W>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <Xm>
// DEF_ISEL(LD2_ASISDLSEP_R2_R_8H) =
//     LD2_16_POSTINDEX<MV256>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <Xm>
// DEF_ISEL(LD2_ASISDLSEP_R2_R_2S) =
//     LD2_32_POSTINDEX<MVI128W>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <Xm>
// DEF_ISEL(LD2_ASISDLSEP_R2_R_4S) =
//     LD2_32_POSTINDEX<MV256>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <Xm>
// DEF_ISEL(LD2_ASISDLSEP_R2_R_2D) =
//     LD2_64_POSTINDEX<MV256>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <Xm>

namespace {

// #define MAKE_LD3(size) \
//   template <typename S, size_t count> \
//   DEF_SEM(LD3_##size, VI128W dst1, VI128W dst2, VI128W dst3, S src) { \
//     auto dst1_vec = UClearV##size(UReadV##size(dst1)); \
//     auto dst2_vec = UClearV##size(UReadV##size(dst2)); \
//     auto dst3_vec = UClearV##size(UReadV##size(dst3)); \
//     _Pragma("unroll") for (size_t i = 0; i < count; ++i) { \
//       auto val = Read(src); \
//       src = GetElementPtr(src, 1); \
//       dst1_vec = UInsertV##size(dst1_vec, i, val); \
//       val = Read(src); \
//       src = GetElementPtr(src, 1); \
//       dst2_vec = UInsertV##size(dst2_vec, i, val); \
//       val = Read(src); \
//       src = GetElementPtr(src, 1); \
//       dst3_vec = UInsertV##size(dst3_vec, i, val); \
//     } \
//     UWriteV##size(dst1, dst1_vec); \
//     UWriteV##size(dst2, dst2_vec); \
//     UWriteV##size(dst3, dst3_vec); \
//   }

// MAKE_LD3(8)
// MAKE_LD3(16)
// MAKE_LD3(32)
// MAKE_LD3(64)

// #undef MAKE_LD3

}  // namespace

// DEF_ISEL(LD3_ASISDLSE_R3_8B) = LD3_8<M8, 8>;  // LD3  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD3_ASISDLSE_R3_16B) =
//     LD3_8<M8, 16>;  // LD3  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD3_ASISDLSE_R3_4H) =
//     LD3_16<M16, 4>;  // LD3  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD3_ASISDLSE_R3_8H) =
//     LD3_16<M16, 8>;  // LD3  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD3_ASISDLSE_R3_2S) =
//     LD3_32<M32, 2>;  // LD3  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD3_ASISDLSE_R3_4S) =
//     LD3_32<M32, 4>;  // LD3  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD3_ASISDLSE_R3_2D) =
//     LD3_64<M64, 2>;  // LD3  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>]

namespace {

// #define MAKE_LD4(size) \
//   template <typename S, size_t count> \
//   DEF_SEM(LD4_##size, VI128W dst1, VI128W dst2, VI128W dst3, VI128W dst4, S src) { \
//     auto dst1_vec = UClearV##size(UReadV##size(dst1)); \
//     auto dst2_vec = UClearV##size(UReadV##size(dst2)); \
//     auto dst3_vec = UClearV##size(UReadV##size(dst3)); \
//     auto dst4_vec = UClearV##size(UReadV##size(dst4)); \
//     _Pragma("unroll") for (size_t i = 0; i < count; ++i) { \
//       auto val = Read(src); \
//       src = GetElementPtr(src, 1); \
//       dst1_vec = UInsertV##size(dst1_vec, i, val); \
//       val = Read(src); \
//       src = GetElementPtr(src, 1); \
//       dst2_vec = UInsertV##size(dst2_vec, i, val); \
//       val = Read(src); \
//       src = GetElementPtr(src, 1); \
//       dst3_vec = UInsertV##size(dst3_vec, i, val); \
//       val = Read(src); \
//       src = GetElementPtr(src, 1); \
//       dst4_vec = UInsertV##size(dst4_vec, i, val); \
//     } \
//     UWriteV##size(dst1, dst1_vec); \
//     UWriteV##size(dst2, dst2_vec); \
//     UWriteV##size(dst3, dst3_vec); \
//     UWriteV##size(dst4, dst4_vec); \
//   }

// MAKE_LD4(8)
// MAKE_LD4(16)
// MAKE_LD4(32)
// MAKE_LD4(64)

// #undef MAKE_LD4

}  // namespace

// DEF_ISEL(LD4_ASISDLSE_R4_8B) =
//     LD4_8<M8, 8>;  // LD4  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD4_ASISDLSE_R4_16B) =
//     LD4_8<M8, 16>;  // LD4  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD4_ASISDLSE_R4_4H) =
//     LD4_16<M16, 4>;  // LD4  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD4_ASISDLSE_R4_8H) =
//     LD4_16<M16, 8>;  // LD4  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD4_ASISDLSE_R4_2S) =
//     LD4_32<M32, 2>;  // LD4  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD4_ASISDLSE_R4_4S) =
//     LD4_32<M32, 4>;  // LD4  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD4_ASISDLSE_R4_2D) =
//     LD4_64<M64, 2>;  // LD4  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>]

namespace {

// #define INS_VEC(size) \
//   template <typename T> \
//   DEF_SEM(INS_##size, VI128W dst, I64 idx, T src) { \
//     auto vec = UReadV##size(dst); \
//     auto index = Read(idx); \
//     auto val = Read(src); \
//     vec = UInsertV##size(vec, index, TruncTo<uint##size##_t>(val)); \
//     UWriteV##size(dst, vec); \
//   }

// INS_VEC(8)
// INS_VEC(16)
// INS_VEC(32)
// INS_VEC(64)

// #undef INS_VEC

}  // namespace

// DEF_ISEL(INS_ASIMDINS_IR_R_B) = INS_8<R32>;  // INS  <Vd>.<Ts>[<index>], <R><n>
// DEF_ISEL(INS_ASIMDINS_IR_R_H) = INS_16<R32>;  // INS  <Vd>.<Ts>[<index>], <R><n>
// DEF_ISEL(INS_ASIMDINS_IR_R_S) = INS_32<R32>;  // INS  <Vd>.<Ts>[<index>], <R><n>
// DEF_ISEL(INS_ASIMDINS_IR_R_D) = INS_64<R64>;  // INS  <Vd>.<Ts>[<index>], <R><n>

namespace {

// LD1R  { <Vt>.<T> }, [<Xn|SP>]
// #define MAKE_LD1R(elem_size) \
//   template <typename D, typename T> \
//   DEF_SEM(LD1R_##elem_size, D dst, T mem) { \
//     auto mem_val = Read(mem); \
//     auto tmp_v = UReadV##elem_size(dst); \
//     _Pragma("unroll") for (auto &elem : tmp_v.elems) { \
//       elem = mem_val; \
//     } \
//     UWriteV##elem_size(dst, tmp_v); \
// \
//   }  // namespace

// MAKE_LD1R(8)
// MAKE_LD1R(16)
// MAKE_LD1R(32)
// MAKE_LD1R(64)

}  // namespace

// DEF_ISEL(LD1R_ASISDLSO_R1_8B) = LD1R_8<VI64W, M8>;  // LD1R  { <Vt>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD1R_ASISDLSO_R1_16B) = LD1R_8<VI128W, M8>;  // LD1R  { <Vt>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD1R_ASISDLSO_R1_4H) = LD1R_16<VI64W, M16>;  // LD1R  { <Vt>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD1R_ASISDLSO_R1_8H) = LD1R_16<VI128W, M16>;  // LD1R  { <Vt>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD1R_ASISDLSO_R1_2S) = LD1R_32<VI64W, M32>;  // LD1R  { <Vt>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD1R_ASISDLSO_R1_4S) = LD1R_32<VI128W, M32>;  // LD1R  { <Vt>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD1R_ASISDLSO_R1_1D) = LD1R_64<VI64W, M64>;  // LD1R  { <Vt>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD1R_ASISDLSO_R1_2D) = LD1R_64<VI128W, M64>;  // LD1R  { <Vt>.<T> }, [<Xn|SP>]

// MOV  <Vd>.<Ts>[<index1>], <Vn>.<Ts>[<index2>]
namespace {

// #define INS_MOV_VEC(size) \
//   DEF_SEM(INS_MOV_##size, VI128W dst, I64 idx1, VI128 src, I64 idx2) { \
//     auto vec = UReadV##size(dst); \
//     auto index_1 = Read(idx1); \
//     auto index_2 = Read(idx2); \
//     auto src_vec = UReadV##size(src); \
//     vec = UInsertV##size(vec, index_1, TruncTo<uint##size##_t>(src_vec.elems[index_2])); \
//     UWriteV##size(dst, vec); \
//   }

// INS_MOV_VEC(8)
// INS_MOV_VEC(16)
// INS_MOV_VEC(32)
// INS_MOV_VEC(64)

// #undef INS_MOV_VEC

}  // namespace

// DEF_ISEL(MOV_INS_ASIMDINS_IV_V_B) = INS_MOV_8;  // MOV  <Vd>.<Ts>[<index1>], <Vn>.<Ts>[<index2>]
// DEF_ISEL(MOV_INS_ASIMDINS_IV_V_H) = INS_MOV_16;  // MOV  <Vd>.<Ts>[<index1>], <Vn>.<Ts>[<index2>]
// DEF_ISEL(MOV_INS_ASIMDINS_IV_V_S) = INS_MOV_32;  // MOV  <Vd>.<Ts>[<index1>], <Vn>.<Ts>[<index2>]
// DEF_ISEL(MOV_INS_ASIMDINS_IV_V_D) = INS_MOV_64;  // MOV  <Vd>.<Ts>[<index1>], <Vn>.<Ts>[<index2>]

namespace {

// #define EXTRACT_VEC(prefix, size, ext_op) \
//   template <typename D, typename T> \
//   DEF_SEM(prefix##MovFromVec##size, D dst, VI128 src, I64 index) { \
//     WriteZExt(dst, ext_op<T>(prefix##ExtractV##size(prefix##ReadV##size(src), Read(index)))); \
//   }

// EXTRACT_VEC(U, 8, ZExtTo)
// EXTRACT_VEC(U, 16, ZExtTo)
// EXTRACT_VEC(U, 32, ZExtTo)
// EXTRACT_VEC(U, 64, ZExtTo)

// EXTRACT_VEC(S, 8, SExtTo)
// EXTRACT_VEC(S, 16, SExtTo)
// EXTRACT_VEC(S, 32, SExtTo)

// #undef EXTRACT_VEC

}  // namespace

// DEF_ISEL(UMOV_ASIMDINS_W_W_B) = UMovFromVec8<R32W, uint32_t>;  // UMOV  <Wd>, <Vn>.<Ts>[<index>]
// DEF_ISEL(UMOV_ASIMDINS_W_W_H) = UMovFromVec16<R32W, uint32_t>;  // UMOV  <Wd>, <Vn>.<Ts>[<index>]
// DEF_ISEL(UMOV_ASIMDINS_W_W_S) = UMovFromVec32<R32W, uint32_t>;  // UMOV  <Wd>, <Vn>.<Ts>[<index>]
// DEF_ISEL(UMOV_ASIMDINS_X_X_D) = UMovFromVec64<R64W, uint64_t>;  // UMOV  <Xd>, <Vn>.<Ts>[<index>]

// DEF_ISEL(SMOV_ASIMDINS_W_W_B) = SMovFromVec8<R32W, int32_t>;  // UMOV  <Wd>, <Vn>.<Ts>[<index>]
// DEF_ISEL(SMOV_ASIMDINS_W_W_H) = SMovFromVec16<R32W, int32_t>;  // UMOV  <Wd>, <Vn>.<Ts>[<index>]

// DEF_ISEL(SMOV_ASIMDINS_X_X_B) = SMovFromVec8<R64W, int64_t>;  // UMOV  <Xd>, <Vn>.<Ts>[<index>]
// DEF_ISEL(SMOV_ASIMDINS_X_X_H) = SMovFromVec16<R64W, int64_t>;  // UMOV  <Xd>, <Vn>.<Ts>[<index>]
// DEF_ISEL(SMOV_ASIMDINS_X_X_S) = SMovFromVec32<R64W, int64_t>;  // UMOV  <Xd>, <Vn>.<Ts>[<index>]

namespace {

// DEF_SEM(MOVI_D2, VI128W dst, I64 src) {
//   auto imm = Read(src);
//   auto res = UClearVI64(UReadVI64(dst));
//   res = UInsertVI64(res, 0, imm);
//   res = UInsertVI64(res, 1, imm);
//   UWriteVI64(dst, res);
// }

// template <typename V, typename VNW>
// DEF_SEM(MOVI_N_B, VNW dst, I8 src) {
//   auto imm = Read(src);
//   V res = {};
//   _Pragma("unroll") for (auto &elem : res.elems) {
//     elem = imm;
//   }
//   UWriteVI8(dst, res);
// }

// template <typename V, typename VNW>
// DEF_SEM(MOVI_L_HL, VNW dst, I16 src) {
//   auto imm = Read(src);
//   V res = {};
//   _Pragma("unroll") for (auto &elem : res.elems) {
//     elem = imm;
//   }
//   UWriteVI16(dst, res);
// }

// template <typename V, typename VNW>
// DEF_SEM(MOVI_L_SL, VNW dst, I32 src) {
//   auto imm = Read(src);
//   V res = {};
//   _Pragma("unroll") for (auto &elem : res.elems) {
//     elem = imm;
//   }
//   UWriteVI32(dst, res);
// }

// DEF_SEM(MOVI_DS, VI128W dst, I64 src) {
//   auto imm = Read(src);
//   auto res = UClearVI64(UReadVI64(dst));
//   res = UInsertVI64(res, 0, imm);
//   UWriteVI64(dst, res);
// }

// template <typename V, typename VNW>
// DEF_SEM(BIC_L_HL, VNW dst, I16 src) {
//   auto imm = Read(src);
//   auto src_vec = UReadVI16(dst);
//   V res = {};
//   _Pragma("unroll") for (int i = 0; i < NumVectorElems(src_vec); i++) {
//     res.elems[i] = src_vec.elems[i] & (~imm);
//   }
//   UWriteVI16(dst, res);
// }

// template <typename V, typename VNW>
// DEF_SEM(BIC_L_SL, VNW dst, I32 src) {
//   auto imm = Read(src);
//   auto src_vec = UReadVI32(dst);
//   V res = {};
//   _Pragma("unroll") for (int i = 0; i < NumVectorElems(src_vec); i++) {
//     res.elems[i] = src_vec.elems[i] & (~imm);
//   }
//   UWriteVI32(dst, res);
// }

}  // namespace

// DEF_ISEL(MOVI_ASIMDIMM_D2_D) = MOVI_D2;  // MOVI  <Vd>.2D, #<imm>
// DEF_ISEL(MOVI_ASIMDIMM_N_B_8B) = MOVI_N_B<uint8vI8_t, VI64W>;  // MOVI  <Vd>.<T>, #<imm8>{, LSL #0}
// DEF_ISEL(MOVI_ASIMDIMM_N_B_16B) =
//     MOVI_N_B<uint8vI16_t, VI128W>;  // MOVI  <Vd>.<T>, #<imm8>{, LSL #0}
// DEF_ISEL(MOVI_ASIMDIMM_L_HL_4H) =
//     MOVI_L_HL<uint16v4_t, VI64W>;  // MOVI  <Vd>.<T>, #<imm8>{, LSL #<amount>}
// DEF_ISEL(MOVI_ASIMDIMM_L_HL_8H) =
//     MOVI_L_HL<uint16vI8_t, VI128W>;  // MOVI  <Vd>.<T>, #<imm8>{, LSL #<amount>}
// DEF_ISEL(MOVI_ASIMDIMM_L_SL_2S) =
//     MOVI_L_SL<uint32v2_t, VI64W>;  // MOVI  <Vd>.<T>, #<imm8>{, LSL #<amount>}
// DEF_ISEL(MOVI_ASIMDIMM_L_SL_4S) =
//     MOVI_L_SL<uint32v4_t, VI128W>;  // MOVI  <Vd>.<T>, #<imm8>{, LSL #<amount>}
// DEF_ISEL(MOVI_ASIMDIMM_M_SM_2S) =
//     MOVI_L_SL<uint32v2_t, VI64W>;  // MOVI  <Vd>.<T>, #<imm8>, MSL #<amount>
// DEF_ISEL(MOVI_ASIMDIMM_M_SM_4S) =
//     MOVI_L_SL<uint32v4_t, VI128W>;  // MOVI  <Vd>.<T>, #<imm8>, MSL #<amount>
// DEF_ISEL(MOVI_ASIMDIMM_D_DS) = MOVI_DS;  // MOVI  <Dd>, #<imm>

// DEF_ISEL(MVNI_ASIMDIMM_L_HL_4H) =
//     MOVI_L_HL<uint16v4_t, VI64W>;  // MVNI  <Vd>.<T>, #<imm8>{, LSL #<amount>}
// DEF_ISEL(MVNI_ASIMDIMM_L_HL_8H) =
//     MOVI_L_HL<uint16vI8_t, VI128W>;  // MVNI  <Vd>.<T>, #<imm8>{, LSL #<amount>}
// DEF_ISEL(MVNI_ASIMDIMM_L_SL_2S) =
//     MOVI_L_SL<uint32v2_t, VI64W>;  // MVNI  <Vd>.<T>, #<imm8>{, LSL #<amount>}
// DEF_ISEL(MVNI_ASIMDIMM_L_SL_4S) =
//     MOVI_L_SL<uint32v4_t, VI128W>;  // MVNI  <Vd>.<T>, #<imm8>{, LSL #<amount>}
// DEF_ISEL(MVNI_ASIMDIMM_M_SM_2S) =
//     MOVI_L_SL<uint32v2_t, VI64W>;  // MOVI  <Vd>.<T>, #<imm8>, MSL #<amount>
// DEF_ISEL(MVNI_ASIMDIMM_M_SM_4S) =
//     MOVI_L_SL<uint32v4_t, VI128W>;  // MOVI  <Vd>.<T>, #<imm8>, MSL #<amount>

// DEF_ISEL(BIC_ASIMDIMM_L_HL_4H) =
//     BIC_L_HL<uint16v4_t, VI64W>;  // MVNI  <Vd>.<T>, #<imm8>{, LSL #<amount>}
// DEF_ISEL(BIC_ASIMDIMM_L_HL_8H) =
//     BIC_L_HL<uint16vI8_t, VI128W>;  // MVNI  <Vd>.<T>, #<imm8>{, LSL #<amount>}
// DEF_ISEL(BIC_ASIMDIMM_L_SL_2S) =
//     BIC_L_SL<uint32v2_t, VI64W>;  // MVNI  <Vd>.<T>, #<imm8>{, LSL #<amount>}
// DEF_ISEL(BIC_ASIMDIMM_L_SL_4S) =
//     BIC_L_SL<uint32v4_t, VI128W>;  // MVNI  <Vd>.<T>, #<imm8>{, LSL #<amount>}

/* casa instruction semantics (FIXME: no atomic) */
namespace {
// template <typename S, typename D>
// DEF_SEM(CAS, S src1, S src2, D dst) {
//   using T = typename BaseType<S>::BT;
//   T org_val = Read(dst);
//   T cmp_val = Read(src1);
//   auto cond_eq = UCmpEq(org_val, cmp_val);
//   WriteTrunc(src1, org_val);
//   auto new_val = Select<T>(cond_eq, Read(src2), org_val);
//   WriteTrunc(dst, new_val);
// }
}  // namespace

// DEF_ISEL(CAS_C32_LDSTEXCL) = CAS<R32W, M32W>;  // CAS  <Ws>, <Wt>, [<Xn|SP>{,#0}]
// DEF_ISEL(CAS_C64_LDSTEXCL) = CAS<R64W, M64W>;  // CAS  <Xs>, <Xt>, [<Xn|SP>{,#0}]

// DEF_ISEL(CASA_C32_LDSTEXCL) = CAS<R32W, M32W>;  // CAS  <Ws>, <Wt>, [<Xn|SP>{,#0}]
// DEF_ISEL(CASA_C64_LDSTEXCL) = CAS<R64W, M64W>;  // CAS  <Xs>, <Xt>, [<Xn|SP>{,#0}]

// DEF_ISEL(CASAL_C32_LDSTEXCL) = CAS<R32W, M32W>;  // CAS  <Ws>, <Wt>, [<Xn|SP>{,#0}]
// DEF_ISEL(CASAL_C64_LDSTEXCL) = CAS<R64W, M64W>;  // CAS  <Xs>, <Xt>, [<Xn|SP>{,#0}]

// DEF_ISEL(CASL_C32_LDSTEXCL) = CAS<R32W, M32W>;  // CAS  <Ws>, <Wt>, [<Xn|SP>{,#0}]
// DEF_ISEL(CASL_C64_LDSTEXCL) = CAS<R64W, M64W>;  // CAS  <Xs>, <Xt>, [<Xn|SP>{,#0}]

namespace {

// template <typename D>
// DEF_SEM(DC_ZVA, D dst_mem) {
//   auto bs = state.sr.dczid_el0.qword & 0b1111; /* get BS field */
//   for (size_t i = 0; i < static_cast<size_t>(pow(2.0, static_cast<double>(bs))); i++) {
//     Write_Dc_Zva(dst_mem, sizeof(uint32_t) * i, 0);
//   }
// }

}  // namespace

// DEF_ISEL(DC_SYS_CR_SYSTEM) = DC_ZVA<M64W>;  // DC  <dc_op>, <Xt>

namespace {

// #define MAKE_CNT(total_size, elem_num) \
//   DEF_SEM(CNT_SIMD_V##total_size, V##total_size##W dst, V##total_size src) { \
//     auto d0 = UExtractV##total_size(UReadV##total_size(src), 0); \
//     uint8v##elem_num##_t tmp_v = {}; \
//     uint##total_size##_t cnt = d0 - ((d0 >> 1) & 0x5555555555555555); \
//     cnt = (cnt & 0x3333333333333333) + ((cnt >> 2) & 0x3333333333333333); \
//     cnt = (cnt + (cnt >> 4)) & 0x0f0f0f0f0f0f0f0f; \
//     _Pragma("unroll") for (int i = 0; i < elem_num; i++) { \
//       tmp_v.elems[i] = (uint8_t) ((cnt >> i * 8) & 0xff); \
//     } \
//     UWriteVI8(dst, tmp_v); \
//   }

// MAKE_CNT(64, 8)
// MAKE_CNT(128, 8)

// #undef MAKE_CNT

}  // namespace

// DEF_ISEL(CNT_ASIMDMISC_R_8B) = CNT_SIMD_VI64;  // CNT  <Vd>.<T>, <Vn>.<T>
// DEF_ISEL(CNT_ASIMDMISC_R_16B) = CNT_SIMD_VI128;  // CNT  <Vd>.<T>, <Vn>.<T>
