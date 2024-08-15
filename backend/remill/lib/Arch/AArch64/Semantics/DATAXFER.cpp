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

DEF_SEM_VOID_RUN(StorePairUpdateIndex32, R32 src1, R32 src2, MVI64 dst_mem) {
  _ecv_u32v2_t vec = {Read(src1), Read(src2)};
  UWriteMVI32(dst_mem, vec);
}

DEF_SEM_VOID_RUN(StorePairUpdateIndex64, R64 src1, R64 src2, MVI128 dst_mem) {
  _ecv_u64v2_t vec = {Read(src1), Read(src2)};
  UWriteMVI64(dst_mem, vec);
}

DEF_SEM_VOID_RUN(StorePairUpdateIndexS, RF32 src1, RF32 src2, MVI64 dst_mem) {
  _ecv_f32v2_t vec = {Read(src1), Read(src2)};
  FWriteMVI32(dst_mem, vec);
}

DEF_SEM_VOID_RUN(StorePairUpdateIndexD, RF64 src1, RF64 src2, MVI128 dst_mem) {
  _ecv_f64v2_t vec = {Read(src1), Read(src2)};
  FWriteMVI64(dst_mem, vec);
}

DEF_SEM_VOID_RUN(StorePair32, R32 src1, R32 src2, MVI64 dst) {
  _ecv_u32v2_t vec = {Read(src1), Read(src2)};
  UWriteMVI32(dst, vec);
}

DEF_SEM_VOID_RUN(StorePair64, R64 src1, R64 src2, MVI128 dst) {
  _ecv_u64v2_t vec = {Read(src1), Read(src2)};
  UWriteMVI64(dst, vec);
}

DEF_SEM_VOID_RUN(STP_S, RF32 src1, RF32 src2, MVI64 dst) {
  _ecv_f32v2_t vec = {Read(src1), Read(src2)};
  FWriteMVI32(dst, vec);
}

DEF_SEM_VOID_RUN(STP_D, RF64 src1, RF64 src2, MVI128 dst) {
  _ecv_f64v2_t vec = {Read(src1), Read(src2)};
  FWriteMVI64(dst, vec);
}

DEF_SEM_VOID_RUN(STP_Q, R128 src1, R128 src2, MVI256 dst) {
  _ecv_u128v2_t vec = {src1, src2};
  UWriteMVI128(dst, vec);
}

DEF_SEM_VOID_RUN(STP_Q_UPDATE_ADDR, R128 src1, R128 src2, MVI256 dst) {
  _ecv_u128v2_t vec = {src1, src2};
  UWriteMVI128(dst, vec);
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
DEF_SEM_VOID_RUN(StoreUpdateIndex, S src, D dst_mem) {
  MWriteTrunc(dst_mem, Read(src));
}

// DEF_SEM_VOID_RUN(StoreUpdateIndex_S8, R8 src, MVI8 dst_mem) {
//   SWriteMVI8(dst_mem, Read(src));
// }

// DEF_SEM_VOID_RUN(StoreUpdateIndex_S16, R16 src, MVI16 dst_mem) {
//   SWriteMVI16(dst_mem, Read(src));
// }

DEF_SEM_VOID_RUN(StoreUpdateIndex_F32, RF32 src, MVI32 dst_mem) {
  FWriteMVI32(dst_mem, Read(src));
}

DEF_SEM_VOID_RUN(StoreUpdateIndex_F64, RF64 src, MVI64 dst_mem) {
  FWriteMVI64(dst_mem, Read(src));
}

template <typename S, typename D>
DEF_SEM_VOID_RUN(Store, S src, D dst) {
  MWriteTrunc(dst, Read(src));
}

template <typename S, typename D>
DEF_SEM_VOID_RUN(StoreToOffset, S src, D base, ADDR offset) {
  MWriteTrunc(DisplaceAddress(base, Read(offset)), Read(src));
}

DEF_SEM_VOID_RUN(StoreWordToOffset, RF32 src, MVI32 base, ADDR offset) {
  FWriteMVI32(DisplaceAddress(base, Read(offset)), Read(src));
}

DEF_SEM_VOID_RUN(StoreDoubleToOffset, RF64 src, MVI64 base, ADDR offset) {
  FWriteMVI64(DisplaceAddress(base, Read(offset)), Read(src));
}

template <typename S, typename D>  // StoreRelease<R32, M32W>
DEF_SEM_VOID_RUN(StoreRelease, S src, D dst) {
  MWriteTrunc(dst, Read(src));
  __remill_barrier_store_store(runtime_manager);
}

DEF_SEM_VOID_RUN(STR_Q_UPDATE_ADDR, R128 src, MVI128 dst) {
  UWriteMVI128(dst, Read(src));
}

template <typename S, typename D>  // e.g. SWP_MEMOP<R32, M32W>
DEF_SEM_T_RUN(SWP_MEMOP, S src1, D dst_src_mem) {
  auto mem_val = ReadMem(dst_src_mem);
  MWriteTrunc(dst_src_mem, Read(src1));
  return mem_val;
}

template <typename S, typename D>  // e.g. LDADD_MEMOP<R32, M32>
DEF_SEM_T_RUN(LDADD_MEMOP, S src, D dst_src_mem) {
  auto mem_val = ReadMem(dst_src_mem);
  MWriteTrunc(dst_src_mem, UAdd(mem_val, Read(src)));
  return mem_val;
}

template <typename S, typename D>  // e.g. LDSET_MEMOP<R32, M32W>
DEF_SEM_T_RUN(LDSET_MEMOP, S src, D dst_src_mem) {
  auto mem_val = ReadMem(dst_src_mem);
  MWriteTrunc(dst_src_mem, UOr(mem_val, Read(src)));
  return mem_val;
}

}  // namespace

DEF_ISEL(STR_32_LDST_IMMPRE) = StoreUpdateIndex<R32, M32W>;  // STR  <Wt>, [<Xn|SP>, #<simm>]!
DEF_ISEL(STR_32_LDST_IMMPOST) = StoreUpdateIndex<R32, M32W>;  // STR  <Wt>, [<Xn|SP>], #<simm>

DEF_ISEL(STR_64_LDST_IMMPRE) = StoreUpdateIndex<R64, M64W>;  // STR  <Xt>, [<Xn|SP>, #<simm>]!
DEF_ISEL(STR_64_LDST_IMMPOST) = StoreUpdateIndex<R64, M64W>;  // STR  <Xt>, [<Xn|SP>], #<simm>

// DEF_ISEL(STR_B_LDST_IMMPRE) = StoreUpdateIndex_S8;  // STR  <Bt>, [<Xn|SP>, #<simm>]!
// DEF_ISEL(STR_B_LDST_IMMPOST) = StoreUpdateIndex_S8;  // STR  <Bt>, [<Xn|SP>], #<simm>

// DEF_ISEL(STR_H_LDST_IMMPRE) = StoreUpdateIndex_S16;  // STR  <Ht>, [<Xn|SP>, #<simm>]!
// DEF_ISEL(STR_H_LDST_IMMPOST) = StoreUpdateIndex_S16;  // STR  <Ht>, [<Xn|SP>], #<simm>

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

DEF_ISEL(SWP_32_MEMOP) = SWP_MEMOP<R32, M32W>;  // SWP  <Ws>, <Wt>, [<Xn|SP>]
DEF_ISEL(SWP_64_MEMOP) = SWP_MEMOP<R64, M64W>;  // SWP  <Xs>, <Xt>, [<Xn|SP>]

DEF_ISEL(SWPA_32_MEMOP) = SWP_MEMOP<R32, M32W>;  // SWPA  <Ws>, <Wt>, [<Xn|SP>]
DEF_ISEL(SWPA_64_MEMOP) = SWP_MEMOP<R64, M64W>;  // SWPA  <Xs>, <Xt>, [<Xn|SP>]

DEF_ISEL(SWPL_32_MEMOP) = SWP_MEMOP<R32, M32W>;  // SWPL  <Ws>, <Wt>, [<Xn|SP>]
DEF_ISEL(SWPL_64_MEMOP) = SWP_MEMOP<R64, M64W>;  // SWPL  <Xs>, <Xt>, [<Xn|SP>]

DEF_ISEL(LDADD_32_MEMOP) = LDADD_MEMOP<R32, M32W>;  // LDADD  <Ws>, <Wt>, [<Xn|SP>]
DEF_ISEL(LDADD_64_MEMOP) = LDADD_MEMOP<R64, M64W>;  // LDADD  <Xs>, <Xt>, [<Xn|SP>]

DEF_ISEL(LDADDA_32_MEMOP) = LDADD_MEMOP<R32, M32W>;  // LDADDA  <Ws>, <Wt>, [<Xn|SP>]
DEF_ISEL(LDADDA_64_MEMOP) = LDADD_MEMOP<R64, M64W>;  // LDADDA  <Xs>, <Xt>, [<Xn|SP>]

DEF_ISEL(LDADDL_32_MEMOP) = LDADD_MEMOP<R32, M32W>;  // LDADDL  <Ws>, <Wt>, [<Xn|SP>]
DEF_ISEL(LDADDL_64_MEMOP) = LDADD_MEMOP<R64, M64W>;  // LDADDL  <Xs>, <Xt>, [<Xn|SP>]

DEF_ISEL(LDADDAL_32_MEMOP) = LDADD_MEMOP<R32, M32W>;  // LDADDAL  <Ws>, <Wt>, [<Xn|SP>]
DEF_ISEL(LDADDAL_64_MEMOP) = LDADD_MEMOP<R64, M64W>;  // LDADDAL  <Xs>, <Xt>, [<Xn|SP>]

DEF_ISEL(LDSET_32_MEMOP) = LDSET_MEMOP<R32, M32W>;  // LDSET  <Ws>, <Wt>, [<Xn|SP>]
DEF_ISEL(LDSET_64_MEMOP) = LDSET_MEMOP<R64, M64W>;  // LDSET  <Xs>, <Xt>, [<Xn|SP>]

DEF_ISEL(LDSETA_32_MEMOP) = LDSET_MEMOP<R32, M32W>;  // LDSETA  <Ws>, <Wt>, [<Xn|SP>]
DEF_ISEL(LDSETA_64_MEMOP) = LDSET_MEMOP<R64, M64W>;  // LDSETA  <Xs>, <Xt>, [<Xn|SP>]

DEF_ISEL(LDSETL_32_MEMOP) = LDSET_MEMOP<R32, M32W>;  // LDSETL  <Ws>, <Wt>, [<Xn|SP>]
DEF_ISEL(LDSETL_64_MEMOP) = LDSET_MEMOP<R64, M64W>;  // LDSETL  <Xs>, <Xt>, [<Xn|SP>]

DEF_ISEL(LDSETAL_32_MEMOP) = LDSET_MEMOP<R32, M32W>;  // LDSETAL  <Ws>, <Wt>, [<Xn|SP>]
DEF_ISEL(LDSETAL_64_MEMOP) = LDSET_MEMOP<R64, M64W>;  // LDSETAL  <Xs>, <Xt>, [<Xn|SP>]

namespace {

DEF_SEM_U32U32_RUN(LoadPairUpdateIndex32, MVI64 src_mem) {
  _ecv_u32v2_t vec = UReadMVI32(src_mem);
  return {vec[0], vec[1]};
}

DEF_SEM_U64U64_RUN(LoadPairUpdateIndex64, MVI128 src_mem) {
  _ecv_u64v2_t vec = UReadMVI64(src_mem);
  return U64U64{vec[0], vec[1]};
}

}  // namespace

DEF_ISEL(LDP_32_LDSTPAIR_PRE) = LoadPairUpdateIndex32;  // LDP  <Wt1>, <Wt2>, [<Xn|SP>, #<imm>]!
DEF_ISEL(LDP_32_LDSTPAIR_POST) = LoadPairUpdateIndex32;  // LDP  <Wt1>, <Wt2>, [<Xn|SP>], #<imm>

DEF_ISEL(LDP_64_LDSTPAIR_PRE) = LoadPairUpdateIndex64;  // LDP  <Xt1>, <Xt2>, [<Xn|SP>, #<imm>]!
DEF_ISEL(LDP_64_LDSTPAIR_POST) = LoadPairUpdateIndex64;  // LDP  <Xt1>, <Xt2>, [<Xn|SP>], #<imm>

namespace {

DEF_SEM_U32U32_RUN(LoadPair32, MVI64 src_mem) {
  _ecv_u32v2_t vec = UReadMVI32(src_mem);
  return {vec[0], vec[1]};
}

DEF_SEM_U64U64_RUN(LoadPair64, MVI128 src_mem) {
  _ecv_u64v2_t vec = UReadMVI64(src_mem);
  return {vec[0], vec[1]};
}

}  // namespace

DEF_ISEL(LDP_32_LDSTPAIR_OFF) = LoadPair32;  // LDP  <Wt1>, <Wt2>, [<Xn|SP>{, #<imm>}]
DEF_ISEL(LDP_64_LDSTPAIR_OFF) = LoadPair64;  // LDP  <Xt1>, <Xt2>, [<Xn|SP>{, #<imm>}]

namespace {

DEF_SEM_U64U64_RUN(LoadSignedPair64, MVI64 src_mem) {
  _ecv_i32v2_t vec = SReadMVI32(src_mem);
  return {ZExtTo<uint64_t>(SExtTo<int64_t>(vec[0])), ZExtTo<uint64_t>(SExtTo<int64_t>(vec[1]))};
}

DEF_SEM_U64U64_RUN(LoadSignedPairUpdateIndex64, MVI64 src_mem) {
  _ecv_i32v2_t vec = SReadMVI32(src_mem);
  return {ZExtTo<uint64_t>(SExtTo<int64_t>(vec[0])), ZExtTo<uint64_t>(SExtTo<int64_t>(vec[1]))};
}

}  // namespace

DEF_ISEL(LDPSW_64_LDSTPAIR_OFF) = LoadSignedPair64;  // LDPSW <Xt1>, <Xt2>, [<Xn|SP>], #<imm>
DEF_ISEL(LDPSW_64_LDSTPAIR_PRE) =
    LoadSignedPairUpdateIndex64;  // LDPSW  <Xt1>, <Xt2>, [<Xn|SP>, #<imm>]!
DEF_ISEL(LDPSW_64_LDSTPAIR_POST) =
    LoadSignedPairUpdateIndex64;  // LDPSW  <Xt1>, <Xt2>, [<Xn|SP>], #<imm>

namespace {

template <typename S>  // e.g. Load<I8>
DEF_SEM_T(Load, S src) {
  return Read(src);
}

template <typename S>  // e.g. Load<M8>
DEF_SEM_T_RUN(LoadMem, S src_mem) {
  return ReadMem(src_mem);
}

template <typename S>  // e.g. LoadUpdateIndex<M8>
DEF_SEM_U32_RUN(LoadMemUpdateIndex_32, S src_mem) {
  return ReadMem(src_mem);
}

template <typename S>  // e.g. LoadUpdateIndex<M64>
DEF_SEM_U64_RUN(LoadMemUpdateIndex_64, S src_mem) {
  return ReadMem(src_mem);
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

template <typename S>  // e.g. LDXR<R32, M32>
DEF_SEM_U32U64_RUN(LDXR_32, S src_mem) {
  return {ReadMem(src_mem), AddressOf(src_mem)};
}

template <typename S>  // e.g. LDXR<R32, M32>
DEF_SEM_U64U64_RUN(LDXR_64, S src_mem) {
  return {ReadMem(src_mem), AddressOf(src_mem)};
}

template <typename S>  // e.g. LDAXR<R32, M32>
DEF_SEM_U32U64_RUN(LDAXR_32, S src_mem) {
  __remill_barrier_load_store(runtime_manager);
  return {ReadMem(src_mem), AddressOf(src_mem)};
}

template <typename S>  // e.g. LDAXR<R32, M32>
DEF_SEM_U64U64_RUN(LDAXR_64, S src_mem) {
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
DEF_SEM_U32_RUN(LoadSExtUpdateIndex32, S src_mem) {
  return static_cast<uint32_t>(SExtTo<InterType>(ReadMem(src_mem)));
}

template <typename S, typename InterType>  // e.g. LoadSExtUpdateIndex<M8, int32_t>
DEF_SEM_U64_RUN(LoadSExtUpdateIndex64, S src_mem) {
  return static_cast<uint64_t>(SExtTo<InterType>(ReadMem(src_mem)));
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

DEF_ISEL(MOVK_32_MOVEWIDE) = MoveWithKeep<R32, R32>;  // MOVK  <Wd>, #<imm>{, LSL #<shift>}
DEF_ISEL(MOVK_64_MOVEWIDE) = MoveWithKeep<R64, R64>;  // MOVK  <Xd>, #<imm>{, LSL #<shift>}

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

// DEF_SEM(LDR_B_UpdateIndex, VI128 dst, MVI8 src, ADDR next_addr) {
//   UWriteVI8(dst, UReadVI8(src));
//   Write(dst_reg, Read(next_addr));
// }

// DEF_SEM(LDR_H_UpdateIndex, VI128 dst, MVI16 src, ADDR next_addr) {
//   UWriteVI16(dst, UReadVI16(src));
//   Write(dst_reg, Read(next_addr));
// }

DEF_SEM_F32_RUN(LDR_S_UpdateIndex, MVI32 src_mem) {
  return FReadMVI32(src_mem)[0];
}

DEF_SEM_F64_RUN(LDR_D_UpdateIndex, MVI64 src_mem) {
  return FReadMVI64(src_mem)[0];
}

DEF_SEM_U128_RUN(LDR_Q_UpdateIndex, MVI128 src_mem) {
  return UReadMVI128(src_mem)[0];
}

// DEF_SEM(LDR_B_FromOffset, VI128 dst, MVI8 src, ADDR offset) {
//   UWriteVI8(dst, UReadVI8(DisplaceAddress(src, Read(offset))));
// }

// DEF_SEM(LDR_H_FromOffset, VI128 dst, MVI16 src, ADDR offset) {
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

DEF_SEM_F32F32_RUN(LDP_S, MVI64 src) {
  _ecv_f32v2_t src_vec = FReadMVI32(src);
  return {src_vec[0], src_vec[1]};
}

DEF_SEM_F64F64_RUN(LDP_D, MVI128 src) {
  _ecv_f64v2_t src_vec = FReadMVI64(src);
  return {src_vec[0], src_vec[1]};
}

DEF_SEM_V128V128_RUN(LDP_Q, MVI256 src) {
  _ecv_u128v2_t src_vec = UReadMVI128(src);
  return {src_vec[0], src_vec[1]};
}

DEF_SEM_F32F32_RUN(LDP_S_UpdateIndex, MVI64 src) {
  _ecv_f32v2_t src_vec = FReadMVI32(src);
  return {src_vec[0], src_vec[1]};
}

DEF_SEM_F64F64_RUN(LDP_D_UpdateIndex, MVI128 src) {
  _ecv_f64v2_t src_vec = FReadMVI64(src);
  return {src_vec[0], src_vec[1]};
}

DEF_SEM_V128V128_RUN(LDP_Q_UpdateIndex, MVI256 src) {
  _ecv_u128v2_t src_vec = UReadMVI128(src);
  return {src_vec[0], src_vec[1]};
}

}  // namespace

DEF_ISEL(LDP_S_LDSTPAIR_OFF) = LDP_S;  // LDP  <St1>, <St2>, [<Xn|SP>{, #<imm>}]
DEF_ISEL(LDP_D_LDSTPAIR_OFF) = LDP_D;  // LDP  <Dt1>, <Dt2>, [<Xn|SP>{, #<imm>}]
DEF_ISEL(LDP_Q_LDSTPAIR_OFF) = LDP_Q;  // LDP  <Qt1>, <Qt2>, [<Xn|SP>{, #<imm>}]

DEF_ISEL(LDP_S_LDSTPAIR_POST) = LDP_S_UpdateIndex;  // LDP  <St1>, <St2>, [<Xn|SP>], #<imm>
DEF_ISEL(LDP_D_LDSTPAIR_POST) = LDP_D_UpdateIndex;  // LDP  <Dt1>, <Dt2>, [<Xn|SP>], #<imm>
DEF_ISEL(LDP_Q_LDSTPAIR_POST) = LDP_Q_UpdateIndex;  // LDP  <Qt1>, <Qt2>, [<Xn|SP>], #<imm>

DEF_ISEL(LDP_S_LDSTPAIR_PRE) = LDP_S_UpdateIndex;  // LDP  <St1>, <St2>, [<Xn|SP>, #<imm>]!
DEF_ISEL(LDP_D_LDSTPAIR_PRE) = LDP_D_UpdateIndex;  // LDP  <Dt1>, <Dt2>, [<Xn|SP>, #<imm>]!
DEF_ISEL(LDP_Q_LDSTPAIR_PRE) = LDP_Q_UpdateIndex;  // LDP  <Qt1>, <Qt2>, [<Xn|SP>, #<imm>]!

namespace {

DEF_SEM_VOID_RUN(STR_B, R8 src, MVI8 dst) {
  UWriteMVI8(dst, Read(src));
}

DEF_SEM_VOID_RUN(STR_H, R16 src, MVI16 dst) {
  UWriteMVI16(dst, Read(src));
}

DEF_SEM_VOID_RUN(STR_S, RF32 src, MVI32 dst) {
  FWriteMVI32(dst, src);
}

DEF_SEM_VOID_RUN(STR_D, RF64 src, MVI64 dst) {
  FWriteMVI64(dst, src);
}

DEF_SEM_VOID_RUN(STR_Q, R128 src, MVI128 dst) {
  UWriteMVI128(dst, Read(src));
}

DEF_SEM_VOID_RUN(STR_Q_UpdateIndex, R128 src, MVI128 dst) {
  UWriteMVI128(dst, Read(src));
}

DEF_SEM_VOID_RUN(STR_Q_FromOffset, R128 src, MVI128 dst, ADDR offset) {
  UWriteMVI128(DisplaceAddress(dst, Read(offset)), Read(src));
}
}  // namespace

DEF_ISEL(STR_B_LDST_POS) = STR_B;  // STR  <Bt>, [<Xn|SP>{, #<pimm>}]
DEF_ISEL(STR_H_LDST_POS) = STR_H;  // STR  <Ht>, [<Xn|SP>{, #<pimm>}]
DEF_ISEL(STR_S_LDST_POS) = STR_S;  // STR  <St>, [<Xn|SP>{, #<pimm>}]
DEF_ISEL(STR_D_LDST_POS) = STR_D;  // STR  <Dt>, [<Xn|SP>{, #<pimm>}]
DEF_ISEL(STR_Q_LDST_POS) = STR_Q;  // STR  <Qt>, [<Xn|SP>{, #<pimm>}]

DEF_ISEL(STUR_B_LDST_UNSCALED) = STR_B;  // STUR  <Bt>, [<Xn|SP>{, #<simm>}]
DEF_ISEL(STUR_H_LDST_UNSCALED) = STR_H;  // STUR  <Ht>, [<Xn|SP>{, #<simm>}]
DEF_ISEL(STUR_S_LDST_UNSCALED) = STR_S;  // STUR  <St>, [<Xn|SP>{, #<simm>}]
DEF_ISEL(STUR_D_LDST_UNSCALED) = STR_D;  // STUR  <Dt>, [<Xn|SP>{, #<simm>}]
DEF_ISEL(STUR_Q_LDST_UNSCALED) = STR_Q;  // STUR  <Qt>, [<Xn|SP>{, #<simm>}]

DEF_ISEL(STR_Q_LDST_REGOFF) =
    STR_Q_FromOffset;  // STR  <Qt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]

DEF_ISEL(STR_Q_LDST_IMMPRE) = STR_Q_UpdateIndex;  // STR  <Qt>, [<Xn|SP>, #<simm>]!
DEF_ISEL(STR_Q_LDST_IMMPOST) = STR_Q_UpdateIndex;  // STR  <Qt>, [<Xn|SP>], #<simm>

namespace {

template <typename S>
DEF_SEM_T_RUN(LoadAcquire, S src) {
  __remill_barrier_load_store(runtime_manager);
  return ReadMem(src);
}

}  // namespace

DEF_ISEL(LDARB_LR32_LDSTEXCL) = LoadAcquire<M8>;  // LDARB  <Wt>, [<Xn|SP>{,#0}]
DEF_ISEL(LDARH_LR32_LDSTEXCL) = LoadAcquire<M16>;  // LDARH  <Wt>, [<Xn|SP>{,#0}]
DEF_ISEL(LDAR_LR32_LDSTEXCL) = LoadAcquire<M32>;  // LDAR  <Wt>, [<Xn|SP>{,#0}]
DEF_ISEL(LDAR_LR64_LDSTEXCL) = LoadAcquire<M64>;  // LDAR  <Xt>, [<Xn|SP>{,#0}]

namespace {

#define MAKE_ST1(esize) \
  template <typename D> \
  DEF_SEM_VOID_RUN(ST1_SINGLE_##esize, VI##esize src1, D dst) { \
    UWriteMVI##esize(dst, UReadVI##esize(src1)); \
  }

MAKE_ST1(64)
MAKE_ST1(128)

#undef MAKE_ST1

}  // namespace

DEF_ISEL(ST1_ASISDLSE_R1_1V_8B) = ST1_SINGLE_64<MVI64>;  // ST1  { <Vt>.<T> }, [<Xn|SP>]
DEF_ISEL(ST1_ASISDLSE_R1_1V_16B) = ST1_SINGLE_128<MVI128>;  // ST1  { <Vt>.<T> }, [<Xn|SP>]

DEF_ISEL(ST1_ASISDLSE_R1_1V_4H) = ST1_SINGLE_64<MVI64>;  // ST1  { <Vt>.<T> }, [<Xn|SP>]
DEF_ISEL(ST1_ASISDLSE_R1_1V_8H) = ST1_SINGLE_128<MVI128>;  // ST1  { <Vt>.<T> }, [<Xn|SP>]

DEF_ISEL(ST1_ASISDLSE_R1_1V_2S) = ST1_SINGLE_64<MVI64>;  // ST1  { <Vt>.<T> }, [<Xn|SP>]
DEF_ISEL(ST1_ASISDLSE_R1_1V_4S) = ST1_SINGLE_128<MVI128>;  // ST1  { <Vt>.<T> }, [<Xn|SP>]

DEF_ISEL(ST1_ASISDLSE_R1_1V_1D) = ST1_SINGLE_64<MVI64>;  // ST1  { <Vt>.<T> }, [<Xn|SP>]
DEF_ISEL(ST1_ASISDLSE_R1_1V_2D) = ST1_SINGLE_128<MVI128>;  // ST1  { <Vt>.<T> }, [<Xn|SP>]

namespace {

#define MAKE_LD1(esize) \
  template <typename S> \
  DEF_SEM_T_RUN(LD1_SINGLE_##esize, S src) { \
    return UReadMVI##esize(src); \
  }

MAKE_LD1(8)
MAKE_LD1(16)
MAKE_LD1(32)
MAKE_LD1(64)

}  // namespace

DEF_ISEL(LD1_ASISDLSE_R1_1V_8B) = LD1_SINGLE_8<MVI64>;  // LD1  { <Vt>.<T> }, [<Xn|SP>]
DEF_ISEL(LD1_ASISDLSE_R1_1V_16B) = LD1_SINGLE_8<MVI128>;  // LD1  { <Vt>.<T> }, [<Xn|SP>]

DEF_ISEL(LD1_ASISDLSE_R1_1V_4H) = LD1_SINGLE_16<MVI64>;  // LD1  { <Vt>.<T> }, [<Xn|SP>]
DEF_ISEL(LD1_ASISDLSE_R1_1V_8H) = LD1_SINGLE_16<MVI128>;  // LD1  { <Vt>.<T> }, [<Xn|SP>]

DEF_ISEL(LD1_ASISDLSE_R1_1V_2S) = LD1_SINGLE_32<MVI64>;  // LD1  { <Vt>.<T> }, [<Xn|SP>]
DEF_ISEL(LD1_ASISDLSE_R1_1V_4S) = LD1_SINGLE_32<MVI128>;  // LD1  { <Vt>.<T> }, [<Xn|SP>]

DEF_ISEL(LD1_ASISDLSE_R1_1V_1D) = LD1_SINGLE_64<MVI64>;  // LD1  { <Vt>.<T> }, [<Xn|SP>]
DEF_ISEL(LD1_ASISDLSE_R1_1V_2D) = LD1_SINGLE_64<MVI128>;  // LD1  { <Vt>.<T> }, [<Xn|SP>]

namespace {

#define MAKE_LD1(esize) \
  template <typename S> \
  DEF_SEM_T_RUN(LD1_PAIR_##esize, S src) { \
    auto elems1 = UReadMVI##esize(src); \
    auto elems2 = UReadMVI##esize(GetElementPtr(src, 1U)); \
    return TPair<decltype(elems1)>{elems1, elems2}; \
  }

MAKE_LD1(8)
MAKE_LD1(16)
MAKE_LD1(32)
MAKE_LD1(64)

#undef MAKE_LD1

}  // namespace

DEF_ISEL(LD1_ASISDLSE_R2_2V_8B) = LD1_PAIR_8<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]
DEF_ISEL(LD1_ASISDLSE_R2_2V_16B) = LD1_PAIR_8<MVI128>;  // LD1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]

DEF_ISEL(LD1_ASISDLSE_R2_2V_4H) = LD1_PAIR_16<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]
DEF_ISEL(LD1_ASISDLSE_R2_2V_8H) = LD1_PAIR_16<MVI128>;  // LD1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]

DEF_ISEL(LD1_ASISDLSE_R2_2V_2S) = LD1_PAIR_32<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]
DEF_ISEL(LD1_ASISDLSE_R2_2V_4S) = LD1_PAIR_32<MVI128>;  // LD1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]

DEF_ISEL(LD1_ASISDLSE_R2_2V_1D) = LD1_PAIR_64<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]
DEF_ISEL(LD1_ASISDLSE_R2_2V_2D) = LD1_PAIR_64<MVI128>;  // LD1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]

namespace {

#define MAKE_ST1(esize) \
  template <typename D> \
  DEF_SEM_VOID_RUN(ST1_PAIR_##esize, VI##esize src1, VI##esize src2, D dst) { \
    UWriteMVI##esize(dst, UReadVI##esize(src1)); \
    UWriteMVI##esize(GetElementPtr(dst, 1U), UReadVI##esize(src2)); \
  }

MAKE_ST1(64)
MAKE_ST1(128)

#undef MAKE_ST1

}  //namespace

DEF_ISEL(ST1_ASISDLSE_R2_2V_8B) = ST1_PAIR_64<MVI64>;  // ST1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]
DEF_ISEL(ST1_ASISDLSE_R2_2V_16B) = ST1_PAIR_128<MVI128>;  // ST1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]

DEF_ISEL(ST1_ASISDLSE_R2_2V_4H) = ST1_PAIR_64<MVI64>;  // ST1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]
DEF_ISEL(ST1_ASISDLSE_R2_2V_8H) = ST1_PAIR_128<MVI128>;  // ST1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]

DEF_ISEL(ST1_ASISDLSE_R2_2V_2S) = ST1_PAIR_64<MVI64>;  // ST1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]
DEF_ISEL(ST1_ASISDLSE_R2_2V_4S) = ST1_PAIR_128<MVI128>;  // ST1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]

DEF_ISEL(ST1_ASISDLSE_R2_2V_1D) = ST1_PAIR_64<MVI64>;  // ST1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]
DEF_ISEL(ST1_ASISDLSE_R2_2V_2D) = ST1_PAIR_128<MVI128>;  // ST1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]

namespace {

#define MAKE_ST1_POSTINDEX(esize) \
  template <typename D> \
  DEF_SEM_VOID_RUN(ST1_PAIR_POSTINDEX_##esize, VI##esize src1, VI##esize src2, D dst) { \
    ST1_PAIR_##esize(runtime_manager, src1, src2, dst); \
  }

MAKE_ST1_POSTINDEX(64)
MAKE_ST1_POSTINDEX(128)

#undef MAKE_ST1_POSTINDEX

}  // namespace

DEF_ISEL(ST1_ASISDLSEP_I2_I2_8B) =
    ST1_PAIR_POSTINDEX_64<MVI64>;  // ST1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>
DEF_ISEL(ST1_ASISDLSEP_I2_I2_16B) =
    ST1_PAIR_POSTINDEX_128<MVI128>;  // ST1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>

DEF_ISEL(ST1_ASISDLSEP_I2_I2_4H) =
    ST1_PAIR_POSTINDEX_64<MVI64>;  // ST1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>
DEF_ISEL(ST1_ASISDLSEP_I2_I2_8H) =
    ST1_PAIR_POSTINDEX_128<MVI128>;  // ST1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>

DEF_ISEL(ST1_ASISDLSEP_I2_I2_2S) =
    ST1_PAIR_POSTINDEX_64<MVI64>;  // ST1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>
DEF_ISEL(ST1_ASISDLSEP_I2_I2_4S) =
    ST1_PAIR_POSTINDEX_128<MVI128>;  // ST1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>

DEF_ISEL(ST1_ASISDLSEP_I2_I2_1D) =
    ST1_PAIR_POSTINDEX_64<MVI64>;  // ST1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>
DEF_ISEL(ST1_ASISDLSEP_I2_I2_2D) =
    ST1_PAIR_POSTINDEX_128<MVI128>;  // ST1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>

namespace {

#define MAKE_ST1_UNIT(esize) \
  DEF_SEM_VOID_RUN(ST1_UNIT_VI##esize, VI128 src, I32 index, M##esize##W dst_mem) { \
    uint##esize##_t elem = UExtractVI##esize(UReadVI##esize(src), Read(index)); \
    MWriteTrunc(dst_mem, elem); \
\
  }  // namespace

MAKE_ST1_UNIT(8)
MAKE_ST1_UNIT(16)
MAKE_ST1_UNIT(32)
MAKE_ST1_UNIT(64)

#undef MAKE_ST1_UNIT

}  // namespace

// ST1  { <Vt>.B }[<index>], [<Xn|SP>]
DEF_ISEL(ST1_ASISDLSO_B1_1B) = ST1_UNIT_VI8;  // ST1  { <Vt>.B }[<index>], [<Xn|SP>]
// ST1  { <Vt>.H }[<index>], [<Xn|SP>]
DEF_ISEL(ST1_ASISDLSO_H1_1H) = ST1_UNIT_VI16;  // ST1  { <Vt>.H }[<index>], [<Xn|SP>]
// ST1  { <Vt>.S }[<index>], [<Xn|SP>]
DEF_ISEL(ST1_ASISDLSO_S1_1S) = ST1_UNIT_VI32;  // ST1  { <Vt>.S }[<index>], [<Xn|SP>]
// ST1  { <Vt>.D }[<index>], [<Xn|SP>]
DEF_ISEL(ST1_ASISDLSO_D1_1D) = ST1_UNIT_VI64;  // ST1  { <Vt>.D }[<index>], [<Xn|SP>]

namespace {

#define MAKE_ST1_UNIT_POSTINDEX(esize) \
  DEF_SEM_VOID_RUN(ST1_UNIT_POSTINDEX_VI##esize, VI128 src, I32 index, M##esize##W dst_mem) { \
    uint##esize##_t elem = UExtractVI##esize(UReadVI##esize(src), Read(index)); \
    MWriteTrunc(dst_mem, elem); \
  }  // namespace

MAKE_ST1_UNIT_POSTINDEX(8)
MAKE_ST1_UNIT_POSTINDEX(16)
MAKE_ST1_UNIT_POSTINDEX(32)
MAKE_ST1_UNIT_POSTINDEX(64)

// #undef MAKE_ST1_UNIT_POSTINDEX

}  // namespace

// ST1  { <Vt>.B }[<index>], [<Xn|SP>], #1
DEF_ISEL(ST1_ASISDLSOP_B1_I1B) = ST1_UNIT_POSTINDEX_VI8;  // ST1  { <Vt>.B }[<index>], [<Xn|SP>], #1
// ST1  { <Vt>.B }[<index>], [<Xn|SP>], <Xm>
DEF_ISEL(ST1_ASISDLSOP_BX1_R1B) =
    ST1_UNIT_POSTINDEX_VI8;  // ST1  { <Vt>.B }[<index>], [<Xn|SP>], <Xm>
// ST1  { <Vt>.H }[<index>], [<Xn|SP>], #2
DEF_ISEL(ST1_ASISDLSOP_H1_I1H) =
    ST1_UNIT_POSTINDEX_VI16;  // ST1  { <Vt>.H }[<index>], [<Xn|SP>], #2
// ST1  { <Vt>.H }[<index>], [<Xn|SP>], <Xm>
DEF_ISEL(ST1_ASISDLSOP_HX1_R1H) =
    ST1_UNIT_POSTINDEX_VI16;  // ST1  { <Vt>.H }[<index>], [<Xn|SP>], <Xm>
// ST1  { <Vt>.S }[<index>], [<Xn|SP>], #4
DEF_ISEL(ST1_ASISDLSOP_S1_I1S) =
    ST1_UNIT_POSTINDEX_VI32;  // ST1  { <Vt>.S }[<index>], [<Xn|SP>], #4
// ST1  { <Vt>.S }[<index>], [<Xn|SP>], <Xm>
DEF_ISEL(ST1_ASISDLSOP_SX1_R1S) =
    ST1_UNIT_POSTINDEX_VI32;  // ST1  { <Vt>.S }[<index>], [<Xn|SP>], <Xm>
// ST1  { <Vt>.D }[<index>], [<Xn|SP>], #8
DEF_ISEL(ST1_ASISDLSOP_D1_I1D) =
    ST1_UNIT_POSTINDEX_VI64;  // ST1  { <Vt>.D }[<index>], [<Xn|SP>], #8
// ST1  { <Vt>.D }[<index>], [<Xn|SP>], <Xm>
DEF_ISEL(ST1_ASISDLSOP_DX1_R1D) =
    ST1_UNIT_POSTINDEX_VI64;  // ST1  { <Vt>.D }[<index>], [<Xn|SP>], <Xm>

namespace {

// #define MAKE_LD1(esize) \
//   template <typename S> \
//   DEF_SEM(LD1_TRIPLE_##esize, VI128 dst1, VI128 dst2, VI128 dst3, S src) { \
//     auto elems1 = UReadVI##esize(src); \
//     auto elems2 = UReadVI##esize(GetElementPtr(src, 1U)); \
//     auto elems3 = UReadVI##esize(GetElementPtr(src, 2U)); \
//     UWriteVI##esize(dst1, elems1); \
//     UWriteVI##esize(dst2, elems2); \
//     UWriteVI##esize(dst3, elems3); \
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
//     LD1_TRIPLE_8<MVI128>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>]

// DEF_ISEL(LD1_ASISDLSE_R3_3V_4H) =
//     LD1_TRIPLE_16<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD1_ASISDLSE_R3_3V_8H) =
//     LD1_TRIPLE_16<MVI128>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>]

// DEF_ISEL(LD1_ASISDLSE_R3_3V_2S) =
//     LD1_TRIPLE_32<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD1_ASISDLSE_R3_3V_4S) =
//     LD1_TRIPLE_32<MVI128>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>]

// DEF_ISEL(LD1_ASISDLSE_R3_3V_1D) =
//     LD1_TRIPLE_64<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD1_ASISDLSE_R3_3V_2D) =
//     LD1_TRIPLE_64<MVI128>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>]

namespace {

// #define MAKE_LD1(esize) \
//   template <typename S> \
//   DEF_SEM(LD1_QUAD_##esize, VI128 dst1, VI128 dst2, VI128 dst3, VI128 dst4, S src) { \
//     auto elems1 = UReadVI##esize(src); \
//     auto elems2 = UReadVI##esize(GetElementPtr(src, 1U)); \
//     auto elems3 = UReadVI##esize(GetElementPtr(src, 2U)); \
//     auto elems4 = UReadVI##esize(GetElementPtr(src, 3U)); \
//     UWriteVI##esize(dst1, elems1); \
//     UWriteVI##esize(dst2, elems2); \
//     UWriteVI##esize(dst3, elems3); \
//     UWriteVI##esize(dst4, elems4); \
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
//     LD1_QUAD_8<MVI128>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>]

// DEF_ISEL(LD1_ASISDLSE_R4_4V_4H) =
//     LD1_QUAD_16<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD1_ASISDLSE_R4_4V_8H) =
//     LD1_QUAD_16<MVI128>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>]

// DEF_ISEL(LD1_ASISDLSE_R4_4V_2S) =
//     LD1_QUAD_32<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD1_ASISDLSE_R4_4V_4S) =
//     LD1_QUAD_32<MVI128>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>]

// DEF_ISEL(LD1_ASISDLSE_R4_4V_1D) =
//     LD1_QUAD_64<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD1_ASISDLSE_R4_4V_2D) =
//     LD1_QUAD_64<MVI128>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>]

namespace {

#define MAKE_LD1_POSTINDEX(esize) \
  template <typename S> \
  DEF_SEM_T_RUN(LD1_SINGLE_POSTINDEX_##esize, S src) { \
    return LD1_SINGLE_##esize(runtime_manager, src); \
  }

MAKE_LD1_POSTINDEX(8)
MAKE_LD1_POSTINDEX(16)
MAKE_LD1_POSTINDEX(32)
MAKE_LD1_POSTINDEX(64)

#undef MAKE_LD1_POSTINDEX

}  // namespace

DEF_ISEL(LD1_ASISDLSEP_I1_I1_8B) =
    LD1_SINGLE_POSTINDEX_8<MVI64>;  // LD1  { <Vt>.<T> }, [<Xn|SP>], <imm>
DEF_ISEL(LD1_ASISDLSEP_I1_I1_16B) =
    LD1_SINGLE_POSTINDEX_8<MVI128>;  // LD1  { <Vt>.<T> }, [<Xn|SP>], <imm>

DEF_ISEL(LD1_ASISDLSEP_I1_I1_4H) =
    LD1_SINGLE_POSTINDEX_16<MVI64>;  // LD1  { <Vt>.<T> }, [<Xn|SP>], <imm>
DEF_ISEL(LD1_ASISDLSEP_I1_I1_8H) =
    LD1_SINGLE_POSTINDEX_16<MVI128>;  // LD1  { <Vt>.<T> }, [<Xn|SP>], <imm>

DEF_ISEL(LD1_ASISDLSEP_I1_I1_2S) =
    LD1_SINGLE_POSTINDEX_32<MVI64>;  // LD1  { <Vt>.<T> }, [<Xn|SP>], <imm>
DEF_ISEL(LD1_ASISDLSEP_I1_I1_4S) =
    LD1_SINGLE_POSTINDEX_32<MVI128>;  // LD1  { <Vt>.<T> }, [<Xn|SP>], <imm>

DEF_ISEL(LD1_ASISDLSEP_I1_I1_1D) =
    LD1_SINGLE_POSTINDEX_64<MVI64>;  // LD1  { <Vt>.<T> }, [<Xn|SP>], <imm>
DEF_ISEL(LD1_ASISDLSEP_I1_I1_2D) =
    LD1_SINGLE_POSTINDEX_64<MVI128>;  // LD1  { <Vt>.<T> }, [<Xn|SP>], <imm>

namespace {

// #define MAKE_LD1_POSTINDEX(esize) \
//   template <typename S> \
//   DEF_SEM(LD1_PAIR_POSTINDEX_##esize, VI128 dst1, VI128 dst2, S src, R64 addr_reg, \
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
//     LD1_PAIR_POSTINDEX_8<MVI128>;  // LD1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>

// DEF_ISEL(LD1_ASISDLSEP_I2_I2_4H) =
//     LD1_PAIR_POSTINDEX_16<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD1_ASISDLSEP_I2_I2_8H) =
//     LD1_PAIR_POSTINDEX_16<MVI128>;  // LD1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>

// DEF_ISEL(LD1_ASISDLSEP_I2_I2_2S) =
//     LD1_PAIR_POSTINDEX_32<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD1_ASISDLSEP_I2_I2_4S) =
//     LD1_PAIR_POSTINDEX_32<MVI128>;  // LD1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>

// DEF_ISEL(LD1_ASISDLSEP_I2_I2_1D) =
//     LD1_PAIR_POSTINDEX_64<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD1_ASISDLSEP_I2_I2_2D) =
//     LD1_PAIR_POSTINDEX_64<MVI128>;  // LD1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>

namespace {

// #define MAKE_LD1_POSTINDEX(esize) \
//   template <typename S> \
//   DEF_SEM(LD1_TRIPLE_POSTINDEX_##esize, VI128 dst1, VI128 dst2, VI128 dst3, S src, \
//           R64 addr_reg, ADDR next_addr) { \
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
//     LD1_TRIPLE_POSTINDEX_8<MVI128>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>], <imm>

// DEF_ISEL(LD1_ASISDLSEP_I3_I3_4H) =
//     LD1_TRIPLE_POSTINDEX_16<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD1_ASISDLSEP_I3_I3_8H) =
//     LD1_TRIPLE_POSTINDEX_16<MVI128>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>], <imm>

// DEF_ISEL(LD1_ASISDLSEP_I3_I3_2S) =
//     LD1_TRIPLE_POSTINDEX_32<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD1_ASISDLSEP_I3_I3_4S) =
//     LD1_TRIPLE_POSTINDEX_32<MVI128>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>], <imm>

// DEF_ISEL(LD1_ASISDLSEP_I3_I3_1D) =
//     LD1_TRIPLE_POSTINDEX_64<MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD1_ASISDLSEP_I3_I3_2D) =
//     LD1_TRIPLE_POSTINDEX_64<MVI128>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>], <imm>

namespace {

// #define MAKE_LD1_POSTINDEX(esize) \
//   template <typename S> \
//   DEF_SEM(LD1_QUAD_POSTINDEX_##esize, VI128 dst1, VI128 dst2, VI128 dst3, VI128 dst4, S src, \
//           R64 addr_reg, ADDR next_addr) { \
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
//     MVI128>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>], <imm>

// DEF_ISEL(LD1_ASISDLSEP_I4_I4_4H) = LD1_QUAD_POSTINDEX_16<
//     MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD1_ASISDLSEP_I4_I4_8H) = LD1_QUAD_POSTINDEX_16<
//     MVI128>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>], <imm>

// DEF_ISEL(LD1_ASISDLSEP_I4_I4_2S) = LD1_QUAD_POSTINDEX_32<
//     MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD1_ASISDLSEP_I4_I4_4S) = LD1_QUAD_POSTINDEX_32<
//     MVI128>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>], <imm>

// DEF_ISEL(LD1_ASISDLSEP_I4_I4_1D) = LD1_QUAD_POSTINDEX_64<
//     MVI64>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD1_ASISDLSEP_I4_I4_2D) = LD1_QUAD_POSTINDEX_64<
//     MVI128>;  // LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>], <imm>

namespace {

// #define MAKE_LD2(size) \
//   template <typename S> \
//   DEF_SEM(LD2_##size, VI128 dst1, VI128 dst2, S src) { \
//     auto vec = UReadVI##size(src); \
//     auto dst1_vec = UClearVI##size(UReadVI##size(dst1)); \
//     auto dst2_vec = UClearVI##size(UReadVI##size(dst2)); \
//     _Pragma("unroll") for (size_t i = 0, j = 0; i < NumVectorElems(vec); j++) { \
//       dst1_vec = UInsertVI##size(dst1_vec, j, UExtractVI##size(vec, i++)); \
//       dst2_vec = UInsertVI##size(dst2_vec, j, UExtractVI##size(vec, i++)); \
//     } \
//     UWriteVI##size(dst1, dst1_vec); \
//     UWriteVI##size(dst2, dst2_vec); \
//   }

// MAKE_LD2(8)
// MAKE_LD2(16)
// MAKE_LD2(32)
// MAKE_LD2(64)

// #undef MAKE_LD2

// #define MAKE_LD2(size) \
//   template <typename S> \
//   DEF_SEM(LD2_##size##_POSTINDEX, VI128 dst1, VI128 dst2, S src, R64 addr_reg, \
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

// DEF_ISEL(LD2_ASISDLSE_R2_8B) = LD2_8<MVI128>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD2_ASISDLSE_R2_16B) = LD2_8<MV256>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD2_ASISDLSE_R2_4H) = LD2_16<MVI128>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD2_ASISDLSE_R2_8H) = LD2_16<MV256>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD2_ASISDLSE_R2_2S) = LD2_32<MVI128>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD2_ASISDLSE_R2_4S) = LD2_32<MV256>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]
// DEF_ISEL(LD2_ASISDLSE_R2_2D) = LD2_64<MV256>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]

// DEF_ISEL(LD2_ASISDLSEP_I2_I_8B) =
//     LD2_8_POSTINDEX<MVI128>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD2_ASISDLSEP_I2_I_16B) =
//     LD2_8_POSTINDEX<MV256>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD2_ASISDLSEP_I2_I_4H) =
//     LD2_16_POSTINDEX<MVI128>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD2_ASISDLSEP_I2_I_8H) =
//     LD2_16_POSTINDEX<MV256>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD2_ASISDLSEP_I2_I_2S) =
//     LD2_32_POSTINDEX<MVI128>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD2_ASISDLSEP_I2_I_4S) =
//     LD2_32_POSTINDEX<MV256>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>
// DEF_ISEL(LD2_ASISDLSEP_I2_I_2D) =
//     LD2_64_POSTINDEX<MV256>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>

// DEF_ISEL(LD2_ASISDLSEP_R2_R_8B) =
//     LD2_8_POSTINDEX<MVI128>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <Xm>
// DEF_ISEL(LD2_ASISDLSEP_R2_R_16B) =
//     LD2_8_POSTINDEX<MV256>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <Xm>
// DEF_ISEL(LD2_ASISDLSEP_R2_R_4H) =
//     LD2_16_POSTINDEX<MVI128>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <Xm>
// DEF_ISEL(LD2_ASISDLSEP_R2_R_8H) =
//     LD2_16_POSTINDEX<MV256>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <Xm>
// DEF_ISEL(LD2_ASISDLSEP_R2_R_2S) =
//     LD2_32_POSTINDEX<MVI128>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <Xm>
// DEF_ISEL(LD2_ASISDLSEP_R2_R_4S) =
//     LD2_32_POSTINDEX<MV256>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <Xm>
// DEF_ISEL(LD2_ASISDLSEP_R2_R_2D) =
//     LD2_64_POSTINDEX<MV256>;  // LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <Xm>

namespace {

// #define MAKE_LD3(size) \
//   template <typename S, size_t count> \
//   DEF_SEM(LD3_##size, VI128 dst1, VI128 dst2, VI128 dst3, S src) { \
//     auto dst1_vec = UClearVI##size(UReadVI##size(dst1)); \
//     auto dst2_vec = UClearVI##size(UReadVI##size(dst2)); \
//     auto dst3_vec = UClearVI##size(UReadVI##size(dst3)); \
//     _Pragma("unroll") for (size_t i = 0; i < count; ++i) { \
//       auto val = Read(src); \
//       src = GetElementPtr(src, 1); \
//       dst1_vec = UInsertVI##size(dst1_vec, i, val); \
//       val = Read(src); \
//       src = GetElementPtr(src, 1); \
//       dst2_vec = UInsertVI##size(dst2_vec, i, val); \
//       val = Read(src); \
//       src = GetElementPtr(src, 1); \
//       dst3_vec = UInsertVI##size(dst3_vec, i, val); \
//     } \
//     UWriteVI##size(dst1, dst1_vec); \
//     UWriteVI##size(dst2, dst2_vec); \
//     UWriteVI##size(dst3, dst3_vec); \
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
//   DEF_SEM(LD4_##size, VI128 dst1, VI128 dst2, VI128 dst3, VI128 dst4, S src) { \
//     auto dst1_vec = UClearVI##size(UReadVI##size(dst1)); \
//     auto dst2_vec = UClearVI##size(UReadVI##size(dst2)); \
//     auto dst3_vec = UClearVI##size(UReadVI##size(dst3)); \
//     auto dst4_vec = UClearVI##size(UReadVI##size(dst4)); \
//     _Pragma("unroll") for (size_t i = 0; i < count; ++i) { \
//       auto val = Read(src); \
//       src = GetElementPtr(src, 1); \
//       dst1_vec = UInsertVI##size(dst1_vec, i, val); \
//       val = Read(src); \
//       src = GetElementPtr(src, 1); \
//       dst2_vec = UInsertVI##size(dst2_vec, i, val); \
//       val = Read(src); \
//       src = GetElementPtr(src, 1); \
//       dst3_vec = UInsertVI##size(dst3_vec, i, val); \
//       val = Read(src); \
//       src = GetElementPtr(src, 1); \
//       dst4_vec = UInsertVI##size(dst4_vec, i, val); \
//     } \
//     UWriteVI##size(dst1, dst1_vec); \
//     UWriteVI##size(dst2, dst2_vec); \
//     UWriteVI##size(dst3, dst3_vec); \
//     UWriteVI##size(dst4, dst4_vec); \
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

#define INS_VEC(size) \
  template <typename T> \
  DEF_SEM_V128(INS_##size, VI128 dst_src, I64 idx, T src) { \
    auto index = Read(idx); \
    auto val = Read(src); \
    auto dst_src_vec = UReadVI##size(dst_src); \
    dst_src_vec[index] = TruncTo<uint##size##_t>(val); \
    return *reinterpret_cast<_ecv_u128v1_t *>(&dst_src_vec); \
  }  // namespace

INS_VEC(8)
INS_VEC(16)
INS_VEC(32)
INS_VEC(64)

#undef INS_VEC

}  // namespace

DEF_ISEL(INS_ASIMDINS_IR_R_B) = INS_8<R32>;  // INS  <Vd>.<Ts>[<index>], <R><n>
DEF_ISEL(INS_ASIMDINS_IR_R_H) = INS_16<R32>;  // INS  <Vd>.<Ts>[<index>], <R><n>
DEF_ISEL(INS_ASIMDINS_IR_R_S) = INS_32<R32>;  // INS  <Vd>.<Ts>[<index>], <R><n>
DEF_ISEL(INS_ASIMDINS_IR_R_D) = INS_64<R64>;  // INS  <Vd>.<Ts>[<index>], <R><n>

namespace {

// LD1R  { <Vt>.<T> }, [<Xn|SP>]
#define MAKE_LD1R(elem_size) \
  template <typename T, typename MT> \
  DEF_SEM_T_RUN(LD1R_##elem_size, T dst_src, MT mem) { \
    auto mem_val = ReadMem(mem); \
    auto dst_src_vec = UReadVI##elem_size(dst_src); \
    _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(dst_src_vec); i++) { \
      dst_src_vec[i] = mem_val; \
    } \
    return dst_src_vec; \
  }  // namespace

MAKE_LD1R(8)
MAKE_LD1R(16)
MAKE_LD1R(32)
MAKE_LD1R(64)

#undef MAKE_LD1R

}  // namespace

DEF_ISEL(LD1R_ASISDLSO_R1_8B) = LD1R_8<VI64, M8>;  // LD1R  { <Vt>.<T> }, [<Xn|SP>]
DEF_ISEL(LD1R_ASISDLSO_R1_16B) = LD1R_8<VI128, M8>;  // LD1R  { <Vt>.<T> }, [<Xn|SP>]
DEF_ISEL(LD1R_ASISDLSO_R1_4H) = LD1R_16<VI64, M16>;  // LD1R  { <Vt>.<T> }, [<Xn|SP>]
DEF_ISEL(LD1R_ASISDLSO_R1_8H) = LD1R_16<VI128, M16>;  // LD1R  { <Vt>.<T> }, [<Xn|SP>]
DEF_ISEL(LD1R_ASISDLSO_R1_2S) = LD1R_32<VI64, M32>;  // LD1R  { <Vt>.<T> }, [<Xn|SP>]
DEF_ISEL(LD1R_ASISDLSO_R1_4S) = LD1R_32<VI128, M32>;  // LD1R  { <Vt>.<T> }, [<Xn|SP>]
DEF_ISEL(LD1R_ASISDLSO_R1_1D) = LD1R_64<VI64, M64>;  // LD1R  { <Vt>.<T> }, [<Xn|SP>]
DEF_ISEL(LD1R_ASISDLSO_R1_2D) = LD1R_64<VI128, M64>;  // LD1R  { <Vt>.<T> }, [<Xn|SP>]

// MOV  <Vd>.<Ts>[<index1>], <Vn>.<Ts>[<index2>]
namespace {

#define INS_MOV_VEC(size) \
  DEF_SEM_V128(INS_MOV_##size, VI128 dst_src, I64 idx1, VI128 src, I64 idx2) { \
    auto index_1 = Read(idx1); \
    auto index_2 = Read(idx2); \
    auto dst_src_vec = UReadVI##size(dst_src); \
    auto src_vec = UReadVI##size(src); \
    dst_src_vec[index_1] = TruncTo<uint##size##_t>(src_vec[index_2]); \
    return dst_src_vec; \
  }

INS_MOV_VEC(8)
INS_MOV_VEC(16)
INS_MOV_VEC(32)
INS_MOV_VEC(64)

#undef INS_MOV_VEC

}  // namespace

DEF_ISEL(MOV_INS_ASIMDINS_IV_V_B) = INS_MOV_8;  // MOV  <Vd>.<Ts>[<index1>], <Vn>.<Ts>[<index2>]
DEF_ISEL(MOV_INS_ASIMDINS_IV_V_H) = INS_MOV_16;  // MOV  <Vd>.<Ts>[<index1>], <Vn>.<Ts>[<index2>]
DEF_ISEL(MOV_INS_ASIMDINS_IV_V_S) = INS_MOV_32;  // MOV  <Vd>.<Ts>[<index1>], <Vn>.<Ts>[<index2>]
DEF_ISEL(MOV_INS_ASIMDINS_IV_V_D) = INS_MOV_64;  // MOV  <Vd>.<Ts>[<index1>], <Vn>.<Ts>[<index2>]

namespace {

#define EXTRACT_VEC(prefix, size, ext_op) \
  template <typename T> \
  DEF_SEM_T(prefix##MovFromVec##size, VI128 src, I64 index) { \
    return ext_op<T>(prefix##ExtractVI##size(prefix##ReadVI##size(src), Read(index))); \
  }

EXTRACT_VEC(U, 8, ZExtTo)
EXTRACT_VEC(U, 16, ZExtTo)
EXTRACT_VEC(U, 32, ZExtTo)
EXTRACT_VEC(U, 64, ZExtTo)

EXTRACT_VEC(S, 8, SExtTo)
EXTRACT_VEC(S, 16, SExtTo)
EXTRACT_VEC(S, 32, SExtTo)

#undef EXTRACT_VEC

}  // namespace

DEF_ISEL(UMOV_ASIMDINS_W_W_B) = UMovFromVec8<uint32_t>;  // UMOV  <Wd>, <Vn>.<Ts>[<index>]
DEF_ISEL(UMOV_ASIMDINS_W_W_H) = UMovFromVec16<uint32_t>;  // UMOV  <Wd>, <Vn>.<Ts>[<index>]
DEF_ISEL(UMOV_ASIMDINS_W_W_S) = UMovFromVec32<uint32_t>;  // UMOV  <Wd>, <Vn>.<Ts>[<index>]
DEF_ISEL(UMOV_ASIMDINS_X_X_D) = UMovFromVec64<uint64_t>;  // UMOV  <Xd>, <Vn>.<Ts>[<index>]

DEF_ISEL(SMOV_ASIMDINS_W_W_B) = SMovFromVec8<int32_t>;  // UMOV  <Wd>, <Vn>.<Ts>[<index>]
DEF_ISEL(SMOV_ASIMDINS_W_W_H) = SMovFromVec16<int32_t>;  // UMOV  <Wd>, <Vn>.<Ts>[<index>]

DEF_ISEL(SMOV_ASIMDINS_X_X_B) = SMovFromVec8<int64_t>;  // UMOV  <Xd>, <Vn>.<Ts>[<index>]
DEF_ISEL(SMOV_ASIMDINS_X_X_H) = SMovFromVec16<int64_t>;  // UMOV  <Xd>, <Vn>.<Ts>[<index>]
DEF_ISEL(SMOV_ASIMDINS_X_X_S) = SMovFromVec32<int64_t>;  // UMOV  <Xd>, <Vn>.<Ts>[<index>]

namespace {

DEF_SEM_V128(MOVI_D2, I64 src) {
  _ecv_u64v2_t dst_vec = {Read(src), Read(src)};
  return dst_vec;
}

template <typename V, typename VI>
DEF_SEM_T(MOVI_N_B, I8 src) {
  auto imm = Read(src);
  V res = {};
  _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(res); i++) {
    res[i] = imm;
  }
  return *reinterpret_cast<VI *>(&res);
}

template <typename V, typename VI>
DEF_SEM_T(MOVI_L_HL, I16 src) {
  auto imm = Read(src);
  V res = {};
  _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(res); i++) {
    res[i] = imm;
  }
  return *reinterpret_cast<VI *>(&res);
}

template <typename V, typename VI>
DEF_SEM_T(MOVI_L_SL, I32 src) {
  auto imm = Read(src);
  V res = {};
  _Pragma("unroll") for (size_t i = 0; i < GetVectorElemsNum(res); i++) {
    res[i] = imm;
  }
  return *reinterpret_cast<VI *>(&res);
}

DEF_SEM_U64(MOVI_DS, I64 src) {
  return Read(src);
}

template <typename V, typename VI>
DEF_SEM_T(BIC_L_HL, VI dst_src, I16 src) {
  auto imm = Read(src);
  auto src_vec = *reinterpret_cast<V *>(&dst_src);
  V res = {};
  _Pragma("unroll") for (int i = 0; i < GetVectorElemsNum(res); i++) {
    res[i] = src_vec[i] & (~imm);
  }
  return *reinterpret_cast<VI *>(&res);
}

template <typename V, typename VI>
DEF_SEM_T(BIC_L_SL, VI dst_src, I32 src) {
  auto imm = Read(src);
  auto src_vec = *reinterpret_cast<V *>(&dst_src);
  V res = {};
  _Pragma("unroll") for (int i = 0; i < GetVectorElemsNum(res); i++) {
    res[i] = src_vec[i] & (~imm);
  }
  return *reinterpret_cast<VI *>(&res);
}

}  // namespace

DEF_ISEL(MOVI_ASIMDIMM_D2_D) = MOVI_D2;  // MOVI  <Vd>.2D, #<imm>
DEF_ISEL(MOVI_ASIMDIMM_N_B_8B) = MOVI_N_B<_ecv_u8v8_t, VI64>;  // MOVI  <Vd>.<T>, #<imm8>{, LSL #0}
DEF_ISEL(MOVI_ASIMDIMM_N_B_16B) =
    MOVI_N_B<_ecv_u8v16_t, VI128>;  // MOVI  <Vd>.<T>, #<imm8>{, LSL #0}
DEF_ISEL(MOVI_ASIMDIMM_L_HL_4H) =
    MOVI_L_HL<_ecv_u16v4_t, VI64>;  // MOVI  <Vd>.<T>, #<imm8>{, LSL #<amount>}
DEF_ISEL(MOVI_ASIMDIMM_L_HL_8H) =
    MOVI_L_HL<_ecv_u16v8_t, VI128>;  // MOVI  <Vd>.<T>, #<imm8>{, LSL #<amount>}
DEF_ISEL(MOVI_ASIMDIMM_L_SL_2S) =
    MOVI_L_SL<_ecv_u32v2_t, VI64>;  // MOVI  <Vd>.<T>, #<imm8>{, LSL #<amount>}
DEF_ISEL(MOVI_ASIMDIMM_L_SL_4S) =
    MOVI_L_SL<_ecv_u32v4_t, VI128>;  // MOVI  <Vd>.<T>, #<imm8>{, LSL #<amount>}
DEF_ISEL(MOVI_ASIMDIMM_M_SM_2S) =
    MOVI_L_SL<_ecv_u32v2_t, VI64>;  // MOVI  <Vd>.<T>, #<imm8>, MSL #<amount>
DEF_ISEL(MOVI_ASIMDIMM_M_SM_4S) =
    MOVI_L_SL<_ecv_u32v4_t, VI128>;  // MOVI  <Vd>.<T>, #<imm8>, MSL #<amount>
DEF_ISEL(MOVI_ASIMDIMM_D_DS) = MOVI_DS;  // MOVI  <Dd>, #<imm>

DEF_ISEL(MVNI_ASIMDIMM_L_HL_4H) =
    MOVI_L_HL<_ecv_u16v4_t, VI64>;  // MVNI  <Vd>.<T>, #<imm8>{, LSL #<amount>}
DEF_ISEL(MVNI_ASIMDIMM_L_HL_8H) =
    MOVI_L_HL<_ecv_u16v8_t, VI128>;  // MVNI  <Vd>.<T>, #<imm8>{, LSL #<amount>}
DEF_ISEL(MVNI_ASIMDIMM_L_SL_2S) =
    MOVI_L_SL<_ecv_u32v2_t, VI64>;  // MVNI  <Vd>.<T>, #<imm8>{, LSL #<amount>}
DEF_ISEL(MVNI_ASIMDIMM_L_SL_4S) =
    MOVI_L_SL<_ecv_u32v4_t, VI128>;  // MVNI  <Vd>.<T>, #<imm8>{, LSL #<amount>}
DEF_ISEL(MVNI_ASIMDIMM_M_SM_2S) =
    MOVI_L_SL<_ecv_u32v2_t, VI64>;  // MOVI  <Vd>.<T>, #<imm8>, MSL #<amount>
DEF_ISEL(MVNI_ASIMDIMM_M_SM_4S) =
    MOVI_L_SL<_ecv_u32v4_t, VI128>;  // MOVI  <Vd>.<T>, #<imm8>, MSL #<amount>

DEF_ISEL(BIC_ASIMDIMM_L_HL_4H) =
    BIC_L_HL<_ecv_u16v4_t, VI64>;  // BIC  <Vd>.<T>, #<imm8>{, LSL #<amount>}
DEF_ISEL(BIC_ASIMDIMM_L_HL_8H) =
    BIC_L_HL<_ecv_u16v8_t, VI128>;  // BIC  <Vd>.<T>, #<imm8>{, LSL #<amount>}
DEF_ISEL(BIC_ASIMDIMM_L_SL_2S) =
    BIC_L_SL<_ecv_u32v2_t, VI64>;  // BIC  <Vd>.<T>, #<imm8>{, LSL #<amount>}
DEF_ISEL(BIC_ASIMDIMM_L_SL_4S) =
    BIC_L_SL<_ecv_u32v4_t, VI128>;  // BIC  <Vd>.<T>, #<imm8>{, LSL #<amount>}

/* casa instruction semantics (FIXME: no atomic) */
namespace {

template <typename T, typename D>
DEF_SEM_T_RUN(CAS, T dst_src1, T src2, D dst_mem) {
  T org_val = ReadMem(dst_mem);
  T cmp_val = Read(dst_src1);
  auto cond_eq = UCmpEq(org_val, cmp_val);
  auto new_val = Select<T>(cond_eq, Read(src2), org_val);
  MWriteTrunc(dst_mem, new_val);
  return org_val;
}
}  // namespace

DEF_ISEL(CAS_C32_LDSTEXCL) = CAS<R32, M32W>;  // CAS  <Ws>, <Wt>, [<Xn|SP>{,#0}]
DEF_ISEL(CAS_C64_LDSTEXCL) = CAS<R64, M64W>;  // CAS  <Xs>, <Xt>, [<Xn|SP>{,#0}]

DEF_ISEL(CASA_C32_LDSTEXCL) = CAS<R32, M32W>;  // CAS  <Ws>, <Wt>, [<Xn|SP>{,#0}]
DEF_ISEL(CASA_C64_LDSTEXCL) = CAS<R64, M64W>;  // CAS  <Xs>, <Xt>, [<Xn|SP>{,#0}]

DEF_ISEL(CASAL_C32_LDSTEXCL) = CAS<R32, M32W>;  // CAS  <Ws>, <Wt>, [<Xn|SP>{,#0}]
DEF_ISEL(CASAL_C64_LDSTEXCL) = CAS<R64, M64W>;  // CAS  <Xs>, <Xt>, [<Xn|SP>{,#0}]

DEF_ISEL(CASL_C32_LDSTEXCL) = CAS<R32, M32W>;  // CAS  <Ws>, <Wt>, [<Xn|SP>{,#0}]
DEF_ISEL(CASL_C64_LDSTEXCL) = CAS<R64, M64W>;  // CAS  <Xs>, <Xt>, [<Xn|SP>{,#0}]

namespace {

template <typename D>
DEF_SEM_VOID_STATE_RUN(DC_ZVA, D dst_mem) {
  auto bs = state.sr.dczid_el0.qword & 0b1111; /* get BS field */
  for (size_t i = 0; i < static_cast<size_t>(pow(2.0, static_cast<double>(bs))); i++) {
    Write_Dc_Zva(dst_mem, sizeof(uint32_t) * i, 0);
  }
}

}  // namespace

DEF_ISEL(DC_SYS_CR_SYSTEM) = DC_ZVA<M64W>;  // DC  <dc_op>, <Xt>

namespace {

#define MAKE_CNT(total_size, elem_num) \
  DEF_SEM_T(CNT_SIMD_VI##total_size, VI##total_size src) { \
    auto d0 = UExtractVI##total_size(UReadVI##total_size(src), 0); \
    _ecv_u8v##elem_num##_t res = {}; \
    uint##total_size##_t cnt = d0 - ((d0 >> 1) & 0x5555555555555555); \
    cnt = (cnt & 0x3333333333333333) + ((cnt >> 2) & 0x3333333333333333); \
    cnt = (cnt + (cnt >> 4)) & 0x0f0f0f0f0f0f0f0f; \
    _Pragma("unroll") for (int i = 0; i < elem_num; i++) { \
      res[i] = (uint8_t) ((cnt >> i * 8) & 0xff); \
    } \
    return res; \
  }  // namespace

MAKE_CNT(64, 8)
MAKE_CNT(128, 8)

#undef MAKE_CNT

}  // namespace

DEF_ISEL(CNT_ASIMDMISC_R_8B) = CNT_SIMD_VI64;  // CNT  <Vd>.<T>, <Vn>.<T>
DEF_ISEL(CNT_ASIMDMISC_R_16B) = CNT_SIMD_VI128;  // CNT  <Vd>.<T>, <Vn>.<T>
