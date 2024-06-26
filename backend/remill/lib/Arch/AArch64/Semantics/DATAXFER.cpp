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

DEF_SEM(StorePairUpdateIndex32, R32 src1, R32 src2, MV64W dst_mem, R64W dst_reg, ADDR next_addr) {
  uint32v2_t vec = {};
  vec = UInsertV32(vec, 0, Read(src1));
  vec = UInsertV32(vec, 1, Read(src2));
  UWriteV32(dst_mem, vec);
  Write(dst_reg, Read(next_addr));
}

DEF_SEM(StorePairUpdateIndex64, R64 src1, R64 src2, MV128W dst_mem, R64W dst_reg, ADDR next_addr) {
  uint64v2_t vec = {};
  vec = UInsertV64(vec, 0, Read(src1));
  vec = UInsertV64(vec, 1, Read(src2));
  UWriteV64(dst_mem, vec);
  Write(dst_reg, Read(next_addr));
}

DEF_SEM(StorePairUpdateIndexS, V32 src1, V32 src2, MV64W dst_mem, R64W dst_reg, ADDR next_addr) {
  float32v2_t vec = {};
  auto src1_vec = FReadV32(src1);
  auto src2_vec = FReadV32(src2);
  vec = FInsertV32(vec, 0, FExtractV32(src1_vec, 0));
  vec = FInsertV32(vec, 1, FExtractV32(src2_vec, 0));
  FWriteV32(dst_mem, vec);
  Write(dst_reg, Read(next_addr));
}

DEF_SEM(StorePairUpdateIndexD, V64 src1, V64 src2, MV128W dst_mem, R64W dst_reg, ADDR next_addr) {
  float64v2_t vec = {};
  auto src1_vec = FReadV64(src1);
  auto src2_vec = FReadV64(src2);
  vec = FInsertV64(vec, 0, FExtractV64(src1_vec, 0));
  vec = FInsertV64(vec, 1, FExtractV64(src2_vec, 0));
  FWriteV64(dst_mem, vec);
  Write(dst_reg, Read(next_addr));
}

DEF_SEM(StorePair32, R32 src1, R32 src2, MV64W dst) {
  uint32v2_t vec = {};
  UWriteV32(dst, UInsertV32(UInsertV32(vec, 0, Read(src1)), 1, Read(src2)));
}

DEF_SEM(StorePair64, R64 src1, R64 src2, MV128W dst) {
  uint64v2_t vec = {};
  UWriteV64(dst, UInsertV64(UInsertV64(vec, 0, Read(src1)), 1, Read(src2)));
}

DEF_SEM(STP_S, V32 src1, V32 src2, MV64W dst) {
  auto src1_vec = FReadV32(src1);
  auto src2_vec = FReadV32(src2);
  float32v2_t tmp_vec = {};
  tmp_vec = FInsertV32(tmp_vec, 0, FExtractV32(src1_vec, 0));
  tmp_vec = FInsertV32(tmp_vec, 1, FExtractV32(src2_vec, 0));
  FWriteV32(dst, tmp_vec);
}

DEF_SEM(STP_D, V64 src1, V64 src2, MV128W dst) {
  auto src1_vec = FReadV64(src1);
  auto src2_vec = FReadV64(src2);
  float64v2_t tmp_vec = {};
  tmp_vec = FInsertV64(tmp_vec, 0, FExtractV64(src1_vec, 0));
  tmp_vec = FInsertV64(tmp_vec, 1, FExtractV64(src2_vec, 0));
  FWriteV64(dst, tmp_vec);
}

DEF_SEM(STP_Q, V128 src1, V128 src2, MV256W dst) {
  auto src1_vec = UReadV128(src1);
  auto src2_vec = UReadV128(src2);
  uint128v2_t tmp_vec = {};
  tmp_vec = UInsertV128(tmp_vec, 0, UExtractV128(src1_vec, 0));
  tmp_vec = UInsertV128(tmp_vec, 1, UExtractV128(src2_vec, 0));
  UWriteV128(dst, tmp_vec);
}

DEF_SEM(STP_Q_UPDATE_ADDR, V128 src1, V128 src2, MV256W dst, R64W dst_reg, ADDR next_addr) {
  auto src1_vec = UReadV128(src1);
  auto src2_vec = UReadV128(src2);
  uint128v2_t tmp_vec = {};
  tmp_vec = UInsertV128(tmp_vec, 0, UExtractV128(src1_vec, 0));
  tmp_vec = UInsertV128(tmp_vec, 1, UExtractV128(src2_vec, 0));
  UWriteV128(dst, tmp_vec);
  Write(dst_reg, Read(next_addr));
}

}  // namespace

DEF_ISEL(STP_32_LDSTPAIR_PRE) = StorePairUpdateIndex32;
DEF_ISEL(STP_32_LDSTPAIR_POST) = StorePairUpdateIndex32;

DEF_ISEL(STP_64_LDSTPAIR_PRE) = StorePairUpdateIndex64;
DEF_ISEL(STP_64_LDSTPAIR_POST) = StorePairUpdateIndex64;

DEF_ISEL(STP_S_LDSTPAIR_PRE) = StorePairUpdateIndexS;
DEF_ISEL(STP_S_LDSTPAIR_POST) = StorePairUpdateIndexS;

DEF_ISEL(STP_D_LDSTPAIR_PRE) = StorePairUpdateIndexD;
DEF_ISEL(STP_D_LDSTPAIR_POST) = StorePairUpdateIndexD;

DEF_ISEL(STP_32_LDSTPAIR_OFF) = StorePair32;
DEF_ISEL(STP_64_LDSTPAIR_OFF) = StorePair64;

DEF_ISEL(STP_S_LDSTPAIR_OFF) = STP_S;
DEF_ISEL(STP_D_LDSTPAIR_OFF) = STP_D;

DEF_ISEL(STP_Q_LDSTPAIR_OFF) = STP_Q;
DEF_ISEL(STP_Q_LDSTPAIR_PRE) = STP_Q_UPDATE_ADDR;
DEF_ISEL(STP_Q_LDSTPAIR_POST) = STP_Q_UPDATE_ADDR;

namespace {

template <typename S, typename D>
DEF_SEM(StoreUpdateIndex, S src, D dst_mem, R64W dst_reg, ADDR next_addr) {
  WriteTrunc(dst_mem, Read(src));
  Write(dst_reg, Read(next_addr));
}

DEF_SEM(StoreUpdateIndex_S8, V8 src, MV8W dst_mem, R64W dst_reg, ADDR next_addr) {
  SWriteV8(dst_mem, SReadV8(src));
  Write(dst_reg, Read(next_addr));
}

DEF_SEM(StoreUpdateIndex_S16, V16 src, MV16W dst_mem, R64W dst_reg, ADDR next_addr) {
  SWriteV16(dst_mem, SReadV16(src));
  Write(dst_reg, Read(next_addr));
}

DEF_SEM(StoreUpdateIndex_F32, V32 src, MV32W dst_mem, R64W dst_reg, ADDR next_addr) {
  FWriteV32(dst_mem, FReadV32(src));
  Write(dst_reg, Read(next_addr));
}

DEF_SEM(StoreUpdateIndex_F64, V64 src, MV64W dst_mem, R64W dst_reg, ADDR next_addr) {
  FWriteV64(dst_mem, FReadV64(src));
  Write(dst_reg, Read(next_addr));
}

template <typename S, typename D>
DEF_SEM(Store, S src, D dst) {
  WriteTrunc(dst, Read(src));
}

template <typename S, typename D>
DEF_SEM(StoreToOffset, S src, D base, ADDR offset) {
  WriteTrunc(DisplaceAddress(base, Read(offset)), Read(src));
}

DEF_SEM(StoreWordToOffset, V32 src, MV32W base, ADDR offset) {
  FWriteV32(DisplaceAddress(base, Read(offset)), FReadV32(src));
}

DEF_SEM(StoreDoubleToOffset, V64 src, MV64W base, ADDR offset) {
  FWriteV64(DisplaceAddress(base, Read(offset)), FReadV64(src));
}

template <typename S, typename D>
DEF_SEM(StoreRelease, S src, D dst) {
  WriteTrunc(dst, Read(src));
  __remill_barrier_store_store(runtime_manager);
}

DEF_SEM(STR_Q_UPDATE_ADDR, V128 src, MV128W dst, R64W dst_reg, ADDR next_addr) {
  auto src_vec = UReadV128(src);
  uint128v1_t tmp_vec = {};
  tmp_vec = UInsertV128(tmp_vec, 0, UExtractV128(src_vec, 0));
  UWriteV128(dst, tmp_vec);
  Write(dst_reg, Read(next_addr));
}

/* S1: <W|X>.s, D1: <W|X>.t, S2: Xn, D2: Xn */
template <typename S1, typename D1, typename S2, typename D2>
DEF_SEM(SWP_MEMOP, S1 src1, D1 dst1, S2 src2, D2 dst2) {
  WriteZExt(dst1, Read(src2));
  WriteTrunc(dst2, Read(src1));
}

template <typename S, typename D>
DEF_SEM(LDADD_MEMOP, S src1, S src2, D dst) {
  using T = typename BaseType<S>::BT;
  T dst_val = Read(dst);
  WriteTrunc(dst, UAdd(dst_val, Read(src2)));
  WriteZExt(src1, dst_val);
}

template <typename S, typename D>
DEF_SEM(LDSET_MEMOP, S src1, S src2, D dst) {
  using T = typename BaseType<S>::BT;
  T dst_val = Read(dst);
  WriteTrunc(dst, UOr(dst_val, Read(src2)));
  WriteZExt(src1, dst_val);
}

}  // namespace

DEF_ISEL(STR_32_LDST_IMMPRE) = StoreUpdateIndex<R32, M32W>;
DEF_ISEL(STR_32_LDST_IMMPOST) = StoreUpdateIndex<R32, M32W>;

DEF_ISEL(STR_64_LDST_IMMPRE) = StoreUpdateIndex<R64, M64W>;
DEF_ISEL(STR_64_LDST_IMMPOST) = StoreUpdateIndex<R64, M64W>;

DEF_ISEL(STR_B_LDST_IMMPRE) = StoreUpdateIndex_S8;
DEF_ISEL(STR_B_LDST_IMMPOST) = StoreUpdateIndex_S8;

DEF_ISEL(STR_H_LDST_IMMPRE) = StoreUpdateIndex_S16;
DEF_ISEL(STR_H_LDST_IMMPOST) = StoreUpdateIndex_S16;

DEF_ISEL(STR_S_LDST_IMMPRE) = StoreUpdateIndex_F32;
DEF_ISEL(STR_S_LDST_IMMPOST) = StoreUpdateIndex_F32;

DEF_ISEL(STR_D_LDST_IMMPRE) = StoreUpdateIndex_F64;
DEF_ISEL(STR_D_LDST_IMMPOST) = StoreUpdateIndex_F64;

DEF_ISEL(STR_32_LDST_POS) = Store<R32, M32W>;
DEF_ISEL(STR_64_LDST_POS) = Store<R64, M64W>;

DEF_ISEL(STLR_SL32_LDSTEXCL) = StoreRelease<R32, M32W>;
DEF_ISEL(STLR_SL64_LDSTEXCL) = StoreRelease<R64, M64W>;

DEF_ISEL(STRB_32_LDST_POS) = Store<R32, M8W>;
DEF_ISEL(STRB_32_LDST_IMMPOST) = StoreUpdateIndex<R32, M8W>;
DEF_ISEL(STRB_32_LDST_IMMPRE) = StoreUpdateIndex<R32, M8W>;
DEF_ISEL(STRB_32B_LDST_REGOFF) = StoreToOffset<R32, M8W>;
DEF_ISEL(STRB_32BL_LDST_REGOFF) = StoreToOffset<R32, M8W>;

DEF_ISEL(STRH_32_LDST_REGOFF) = StoreToOffset<R32, M16W>;
DEF_ISEL(STRH_32_LDST_IMMPRE) = StoreUpdateIndex<R32, M16W>;
DEF_ISEL(STRH_32_LDST_IMMPOST) = StoreUpdateIndex<R32, M16W>;
DEF_ISEL(STRH_32_LDST_POS) = Store<R32, M16W>;

DEF_ISEL(STR_32_LDST_REGOFF) = StoreToOffset<R32, M32W>;
DEF_ISEL(STR_64_LDST_REGOFF) = StoreToOffset<R64, M64W>;
DEF_ISEL(STR_S_LDST_REGOFF) = StoreWordToOffset;
DEF_ISEL(STR_D_LDST_REGOFF) = StoreDoubleToOffset;

DEF_ISEL(SWP_32_MEMOP) = SWP_MEMOP<R32, R32W, M32, M32W>;
DEF_ISEL(SWP_64_MEMOP) = SWP_MEMOP<R64, R64W, M64, M64W>;

DEF_ISEL(SWPA_32_MEMOP) = SWP_MEMOP<R32, R32W, M32, M32W>;
DEF_ISEL(SWPA_64_MEMOP) = SWP_MEMOP<R64, R64W, M64, M64W>;

DEF_ISEL(SWPL_32_MEMOP) = SWP_MEMOP<R32, R32W, M32, M32W>;
DEF_ISEL(SWPL_64_MEMOP) = SWP_MEMOP<R64, R64W, M64, M64W>;

DEF_ISEL(LDADD_32_MEMOP) = LDADD_MEMOP<R32W, M32W>;
DEF_ISEL(LDADD_64_MEMOP) = LDADD_MEMOP<R64W, M64W>;

DEF_ISEL(LDADDA_32_MEMOP) = LDADD_MEMOP<R32W, M32W>;
DEF_ISEL(LDADDA_64_MEMOP) = LDADD_MEMOP<R64W, M64W>;

DEF_ISEL(LDADDL_32_MEMOP) = LDADD_MEMOP<R32W, M32W>;
DEF_ISEL(LDADDL_64_MEMOP) = LDADD_MEMOP<R64W, M64W>;

DEF_ISEL(LDADDAL_32_MEMOP) = LDADD_MEMOP<R32W, M32W>;
DEF_ISEL(LDADDAL_64_MEMOP) = LDADD_MEMOP<R64W, M64W>;

DEF_ISEL(LDSET_32_MEMOP) = LDSET_MEMOP<R32W, M32W>;
DEF_ISEL(LDSET_64_MEMOP) = LDSET_MEMOP<R64W, M64W>;

DEF_ISEL(LDSETA_32_MEMOP) = LDSET_MEMOP<R32W, M32W>;
DEF_ISEL(LDSETA_64_MEMOP) = LDSET_MEMOP<R64W, M64W>;

DEF_ISEL(LDSETL_32_MEMOP) = LDSET_MEMOP<R32W, M32W>;
DEF_ISEL(LDSETL_64_MEMOP) = LDSET_MEMOP<R64W, M64W>;

DEF_ISEL(LDSETAL_32_MEMOP) = LDSET_MEMOP<R32W, M32W>;
DEF_ISEL(LDSETAL_64_MEMOP) = LDSET_MEMOP<R64W, M64W>;

namespace {

DEF_SEM(LoadPairUpdateIndex32, R32W dst1, R32W dst2, MV64 src_mem, R64W dst_reg, ADDR next_addr) {
  auto vec = UReadV32(src_mem);
  WriteZExt(dst1, UExtractV32(vec, 0));
  WriteZExt(dst2, UExtractV32(vec, 1));
  Write(dst_reg, Read(next_addr));
}

DEF_SEM(LoadPairUpdateIndex64, R64W dst1, R64W dst2, MV128 src_mem, R64W dst_reg, ADDR next_addr) {
  auto vec = UReadV64(src_mem);
  Write(dst1, UExtractV64(vec, 0));
  Write(dst2, UExtractV64(vec, 1));
  Write(dst_reg, Read(next_addr));
}

}  // namespace

DEF_ISEL(LDP_32_LDSTPAIR_PRE) = LoadPairUpdateIndex32;
DEF_ISEL(LDP_32_LDSTPAIR_POST) = LoadPairUpdateIndex32;

DEF_ISEL(LDP_64_LDSTPAIR_PRE) = LoadPairUpdateIndex64;
DEF_ISEL(LDP_64_LDSTPAIR_POST) = LoadPairUpdateIndex64;

namespace {

DEF_SEM(LoadPair32, R32W dst1, R32W dst2, MV64 src_mem) {
  auto vec = UReadV32(src_mem);
  WriteZExt(dst1, UExtractV32(vec, 0));
  WriteZExt(dst2, UExtractV32(vec, 1));
}

DEF_SEM(LoadPair64, R64W dst1, R64W dst2, MV128 src_mem) {
  auto vec = UReadV64(src_mem);
  Write(dst1, UExtractV64(vec, 0));
  Write(dst2, UExtractV64(vec, 1));
}

}  // namespace

DEF_ISEL(LDP_32_LDSTPAIR_OFF) = LoadPair32;
DEF_ISEL(LDP_64_LDSTPAIR_OFF) = LoadPair64;

namespace {

DEF_SEM(LoadSignedPair64, R64W dst1, R64W dst2, MV64 src_mem) {
  auto vec = SReadV32(src_mem);
  WriteZExt(dst1, SExtTo<int64_t>(SExtractV32(vec, 0)));
  WriteZExt(dst2, SExtTo<int64_t>(SExtractV32(vec, 1)));
}

DEF_SEM(LoadSignedPairUpdateIndex64, R64W dst1, R64W dst2, MV64 src_mem, R64W dst_reg,
        ADDR next_addr) {
  auto vec = SReadV32(src_mem);
  WriteZExt(dst1, SExtTo<int64_t>(SExtractV32(vec, 0)));
  WriteZExt(dst2, SExtTo<int64_t>(SExtractV32(vec, 1)));
  Write(dst_reg, Read(next_addr));
}

}  // namespace

DEF_ISEL(LDPSW_64_LDSTPAIR_OFF) = LoadSignedPair64;
DEF_ISEL(LDPSW_64_LDSTPAIR_PRE) = LoadSignedPairUpdateIndex64;
DEF_ISEL(LDPSW_64_LDSTPAIR_POST) = LoadSignedPairUpdateIndex64;

namespace {

template <typename D, typename S>
DEF_SEM(Load, D dst, S src) {
  WriteZExt(dst, Read(src));
}

template <typename D, typename S>
DEF_SEM(LoadUpdateIndex, D dst, S src, R64W dst_reg, ADDR next_addr) {
  WriteZExt(dst, Read(src));
  Write(dst_reg, Read(next_addr));
}

template <typename D, typename M>
DEF_SEM(LoadFromOffset, D dst, M base, ADDR offset) {
  WriteZExt(dst, Read(DisplaceAddress(base, Read(offset))));
}
}  // namespace

DEF_ISEL(LDRB_32_LDST_POS) = Load<R32W, M8>;
DEF_ISEL(LDRB_32_LDST_IMMPOST) = LoadUpdateIndex<R32W, M8>;
DEF_ISEL(LDRB_32_LDST_IMMPRE) = LoadUpdateIndex<R32W, M8>;
DEF_ISEL(LDRB_32B_LDST_REGOFF) = LoadFromOffset<R32W, M8>;
DEF_ISEL(LDRB_32BL_LDST_REGOFF) = LoadFromOffset<R32W, M8>;

DEF_ISEL(LDRH_32_LDST_POS) = Load<R32W, M16>;
DEF_ISEL(LDRH_32_LDST_IMMPOST) = LoadUpdateIndex<R32W, M16>;
DEF_ISEL(LDRH_32_LDST_IMMPRE) = LoadUpdateIndex<R32W, M16>;
DEF_ISEL(LDRH_32_LDST_REGOFF) = LoadFromOffset<R32W, M16>;

DEF_ISEL(LDR_32_LDST_POS) = Load<R32W, M32>;
DEF_ISEL(LDR_32_LDST_IMMPOST) = LoadUpdateIndex<R32W, M32>;
DEF_ISEL(LDR_32_LDST_IMMPRE) = LoadUpdateIndex<R32W, M32>;
DEF_ISEL(LDR_32_LDST_REGOFF) = LoadFromOffset<R32W, M32>;
DEF_ISEL(LDR_32_LOADLIT) = Load<R32W, M32>;

DEF_ISEL(LDR_64_LDST_POS) = Load<R64W, M64>;
DEF_ISEL(LDR_64_LDST_IMMPOST) = LoadUpdateIndex<R64W, M64>;
DEF_ISEL(LDR_64_LDST_IMMPRE) = LoadUpdateIndex<R64W, M64>;
DEF_ISEL(LDR_64_LDST_REGOFF) = LoadFromOffset<R64W, M64>;
DEF_ISEL(LDR_64_LOADLIT) = Load<R64W, M64>;

DEF_ISEL(LDURB_32_LDST_UNSCALED) = Load<R32W, M8>;
DEF_ISEL(LDURH_32_LDST_UNSCALED) = Load<R32W, M16>;
DEF_ISEL(LDUR_32_LDST_UNSCALED) = Load<R32W, M32>;
DEF_ISEL(LDUR_64_LDST_UNSCALED) = Load<R64W, M64>;

DEF_ISEL(STURB_32_LDST_UNSCALED) = Store<R32, M8W>;
DEF_ISEL(STURH_32_LDST_UNSCALED) = Store<R32, M16W>;
DEF_ISEL(STUR_32_LDST_UNSCALED) = Store<R32, M32W>;
DEF_ISEL(STUR_64_LDST_UNSCALED) = Store<R64, M64W>;

DEF_ISEL(MOVZ_32_MOVEWIDE) = Load<R32W, I32>;
DEF_ISEL(MOVZ_64_MOVEWIDE) = Load<R64W, I64>;


namespace {

template <typename D, typename S>
DEF_SEM(LDXR, D dst, S src, R64W monitor) {
  WriteZExt(dst, Read(src));
  Write(monitor, AddressOf(src));
}

template <typename D, typename S>
DEF_SEM(LDAXR, D dst, S src, R64W monitor) {
  __remill_barrier_load_store(runtime_manager);
  WriteZExt(dst, Read(src));
  Write(monitor, AddressOf(src));
}

template <typename S, typename D>
DEF_SEM(STLXR, R32W dst1, S src1, D dst2, R64W monitor) {
  auto old_addr = Read(monitor);
  if (old_addr == AddressOf(dst2)) {
    WriteZExt(dst2, Read(src1));
    WriteZExt(dst1, 0_u32);  // Store succeeded.
  } else {
    WriteZExt(dst1, 1_u32);  // Store failed.
  }
  Write(monitor, 0_u64);
  __remill_barrier_store_store(runtime_manager);
}

template <typename S, typename D>
DEF_SEM(STXR, R32W dst1, S src1, D dst2, R64W monitor) {
  auto old_addr = Read(monitor);
  if (old_addr == AddressOf(dst2)) {
    WriteZExt(dst2, Read(src1));
    WriteZExt(dst1, 0_u32);  // Store succeeded.
  } else {
    WriteZExt(dst1, 1_u32);  // Store failed.
  }
  Write(monitor, 0_u64);
  __remill_barrier_store_store(runtime_manager);
}

}  // namespace

DEF_ISEL(LDXR_LR32_LDSTEXCL) = LDXR<R32W, M32>;
DEF_ISEL(LDXR_LR64_LDSTEXCL) = LDXR<R64W, M64>;
DEF_ISEL(LDAXR_LR32_LDSTEXCL) = LDAXR<R32W, M32>;
DEF_ISEL(LDAXR_LR64_LDSTEXCL) = LDAXR<R64W, M64>;
DEF_ISEL(STLXR_SR32_LDSTEXCL) = STLXR<R32, M32W>;
DEF_ISEL(STLXR_SR64_LDSTEXCL) = STLXR<R64, M64W>;
DEF_ISEL(STXR_SR32_LDSTEXCL) = STXR<R32, M32W>;
DEF_ISEL(STXR_SR64_LDSTEXCL) = STXR<R64, M64W>;

namespace {

template <typename D, typename S, typename InterType>
DEF_SEM(LoadSExt, D dst, S src) {
  WriteZExt(dst, SExtTo<InterType>(Read(src)));
}

template <typename D, typename S, typename InterType>
DEF_SEM(LoadSExtUpdateIndex, D dst, S src, R64W dst_reg, ADDR next_addr) {
  WriteZExt(dst, SExtTo<InterType>(Read(src)));
  Write(dst_reg, Read(next_addr));
}

template <typename D, typename M, typename InterType>
DEF_SEM(LoadSExtFromOffset, D dst, M base, ADDR offset) {
  WriteZExt(dst, SExtTo<InterType>(Read(DisplaceAddress(base, Read(offset)))));
}

}  // namespace

DEF_ISEL(LDURSB_32_LDST_UNSCALED) = LoadSExt<R32W, M8, int32_t>;
DEF_ISEL(LDURSH_32_LDST_UNSCALED) = LoadSExt<R32W, M16, int32_t>;
DEF_ISEL(LDURSH_64_LDST_UNSCALED) = LoadSExt<R64W, M16, int64_t>;
DEF_ISEL(LDURSW_64_LDST_UNSCALED) = LoadSExt<R64W, M32, int64_t>;

DEF_ISEL(LDRSB_32_LDST_POS) = LoadSExt<R32W, M8, int32_t>;
DEF_ISEL(LDRSB_64_LDST_POS) = LoadSExt<R64W, M8, int64_t>;
DEF_ISEL(LDRSB_32_LDST_IMMPOST) = LoadSExtUpdateIndex<R32W, M8, int32_t>;
DEF_ISEL(LDRSB_64_LDST_IMMPOST) = LoadSExtUpdateIndex<R64W, M8, int64_t>;
DEF_ISEL(LDRSB_32_LDST_IMMPRE) = LoadSExtUpdateIndex<R32W, M8, int32_t>;
DEF_ISEL(LDRSB_64_LDST_IMMPRE) = LoadSExtUpdateIndex<R64W, M8, int64_t>;
DEF_ISEL(LDRSB_32B_LDST_REGOFF) = LoadSExtFromOffset<R32W, M8, int32_t>;
DEF_ISEL(LDRSB_32BL_LDST_REGOFF) = LoadSExtFromOffset<R32W, M8, int32_t>;
DEF_ISEL(LDRSB_64B_LDST_REGOFF) = LoadSExtFromOffset<R64W, M8, int64_t>;
DEF_ISEL(LDRSB_64BL_LDST_REGOFF) = LoadSExtFromOffset<R64W, M8, int64_t>;

DEF_ISEL(LDRSH_32_LDST_POS) = LoadSExt<R32W, M16, int32_t>;
DEF_ISEL(LDRSH_64_LDST_POS) = LoadSExt<R64W, M16, int64_t>;
DEF_ISEL(LDRSH_32_LDST_IMMPOST) = LoadSExtUpdateIndex<R32W, M16, int32_t>;
DEF_ISEL(LDRSH_64_LDST_IMMPOST) = LoadSExtUpdateIndex<R64W, M16, int64_t>;
DEF_ISEL(LDRSH_32_LDST_IMMPRE) = LoadSExtUpdateIndex<R32W, M16, int32_t>;
DEF_ISEL(LDRSH_64_LDST_IMMPRE) = LoadSExtUpdateIndex<R64W, M16, int64_t>;
DEF_ISEL(LDRSH_32_LDST_REGOFF) = LoadSExtFromOffset<R32W, M16, int32_t>;
DEF_ISEL(LDRSH_64_LDST_REGOFF) = LoadSExtFromOffset<R64W, M16, int64_t>;

DEF_ISEL(LDRSW_64_LDST_POS) = LoadSExt<R64W, M32, int64_t>;
DEF_ISEL(LDRSW_64_LDST_IMMPOST) = LoadSExtUpdateIndex<R64W, M32, int64_t>;
DEF_ISEL(LDRSW_64_LDST_IMMPRE) = LoadSExtUpdateIndex<R64W, M32, int64_t>;
DEF_ISEL(LDRSW_64_LDST_REGOFF) = LoadSExtFromOffset<R64W, M32, int64_t>;
DEF_ISEL(LDRSW_64_LOADLIT) = LoadSExt<R64W, M32, int64_t>;

namespace {

template <typename D, typename S>
DEF_SEM(MoveWithKeep, D dst, S src, I64 imm, I8 shift_) {
  auto shift = ZExtTo<uint64_t>(Read(shift_));
  auto val = UShl(Read(imm), shift);
  auto mask = UNot(UShl((0xFFFFULL), shift));
  auto reg = ZExtTo<uint64_t>(Read(src));
  WriteZExt(dst, UOr(UAnd(reg, mask), val));
}

DEF_SEM(FMOV_Imm32, V128W dst, F32 imm) {
  auto val = Read(imm);
  FWriteV32(dst, val);
}

DEF_SEM(FMOV_Imm64, V128W dst, F64 imm) {
  auto val = Read(imm);
  FWriteV64(dst, val);
}

DEF_SEM(FMOV_I32ToF32, V128W dst, R32 src) {
  auto val = Read(src);
  UWriteV32(dst, val);
}

DEF_SEM(FMOV_F32ToI32, R32W dst, V32 src) {
  auto float_val = FExtractV32(FReadV32(src), 0);
  WriteZExt(dst, reinterpret_cast<uint32_t &>(float_val));
}

DEF_SEM(FMOV_I64ToF64, V128W dst, R64 src) {
  auto val = Read(src);
  UWriteV64(dst, val);
}

DEF_SEM(FMOV_F64ToI64, R64W dst, V64 src) {
  auto float_val = FExtractV64(FReadV64(src), 0);
  WriteZExt(dst, reinterpret_cast<uint64_t &>(float_val));
}

DEF_SEM(FMOV_S, V128W dst, V32 src) {
  auto reg = FReadV32(src);
  FWriteV32(dst, reg);
}

DEF_SEM(FMOV_D, V128W dst, V64 src) {
  auto reg = FReadV64(src);
  FWriteV64(dst, reg);
}
}  // namespace

DEF_ISEL(MOVK_32_MOVEWIDE) = MoveWithKeep<R32W, R32>;
DEF_ISEL(MOVK_64_MOVEWIDE) = MoveWithKeep<R64W, R64>;

// Shifting and negating of the immediate happens in the post-decoder.
DEF_ISEL(MOVN_32_MOVEWIDE) = Load<R32W, I32>;
DEF_ISEL(MOVN_64_MOVEWIDE) = Load<R64W, I64>;

DEF_ISEL(FMOV_H_FLOATIMM) = FMOV_Imm32;
DEF_ISEL(FMOV_S_FLOATIMM) = FMOV_Imm32;
DEF_ISEL(FMOV_D_FLOATIMM) = FMOV_Imm64;

DEF_ISEL(FMOV_32S_FLOAT2INT) = FMOV_F32ToI32;
DEF_ISEL(FMOV_S32_FLOAT2INT) = FMOV_I32ToF32;

DEF_ISEL(FMOV_64D_FLOAT2INT) = FMOV_F64ToI64;
DEF_ISEL(FMOV_D64_FLOAT2INT) = FMOV_I64ToF64;

DEF_ISEL(FMOV_S_FLOATDP1) = FMOV_S;
DEF_ISEL(FMOV_D_FLOATDP1) = FMOV_D;

namespace {

DEF_SEM(ADRP, R64W dst, PC label) {
  addr_t label_addr = Read(label);

  // clear the bottom 12 bits of label_addr
  // to make this page aligned
  // the Post decoding already made the label page aligned
  // and added the label to PC
  // the semantics just needs to fix up for PC not being page aligned
  auto label_page = UAnd(UNot(static_cast<uint64_t>(4095)), label_addr);
  Write(dst, label_page);
}

}  // namespace

DEF_ISEL(ADRP_ONLY_PCRELADDR) = ADRP;

DEF_ISEL(ADR_ONLY_PCRELADDR) = Load<R64W, I64>;

namespace {

DEF_SEM(LDR_B, V128W dst, MV8 src) {
  UWriteV8(dst, UReadV8(src));
}

DEF_SEM(LDR_H, V128W dst, MV16 src) {
  UWriteV16(dst, UReadV16(src));
}

DEF_SEM(LDR_S, V128W dst, MV32 src) {
  FWriteV32(dst, FReadV32(src));
}

DEF_SEM(LDR_D, V128W dst, MV64 src) {
  FWriteV64(dst, FReadV64(src));
}

DEF_SEM(LDR_Q, V128W dst, MV128 src) {
  UWriteV128(dst, UReadV128(src));
}

DEF_SEM(LDR_B_UpdateIndex, V128W dst, MV8 src, R64W dst_reg, ADDR next_addr) {
  UWriteV8(dst, UReadV8(src));
  Write(dst_reg, Read(next_addr));
}

DEF_SEM(LDR_H_UpdateIndex, V128W dst, MV16 src, R64W dst_reg, ADDR next_addr) {
  UWriteV16(dst, UReadV16(src));
  Write(dst_reg, Read(next_addr));
}

DEF_SEM(LDR_S_UpdateIndex, V128W dst, MV32W src, R64W dst_reg, ADDR next_addr) {
  FWriteV32(dst, FReadV32(src));
  Write(dst_reg, Read(next_addr));
}

DEF_SEM(LDR_D_UpdateIndex, V128W dst, MV64 src, R64W dst_reg, ADDR next_addr) {
  FWriteV64(dst, FReadV64(src));
  Write(dst_reg, Read(next_addr));
}

DEF_SEM(LDR_Q_UpdateIndex, V128W dst, MV128 src, R64W dst_reg, ADDR next_addr) {
  UWriteV128(dst, UReadV128(src));
  Write(dst_reg, Read(next_addr));
}

DEF_SEM(LDR_B_FromOffset, V128W dst, MV8 src, ADDR offset) {
  UWriteV8(dst, UReadV8(DisplaceAddress(src, Read(offset))));
}

DEF_SEM(LDR_H_FromOffset, V128W dst, MV16 src, ADDR offset) {
  UWriteV16(dst, UReadV16(DisplaceAddress(src, Read(offset))));
}

DEF_SEM(LDR_S_FromOffset, V128W dst, MV32 src, ADDR offset) {
  FWriteV32(dst, FReadV32(DisplaceAddress(src, Read(offset))));
}

DEF_SEM(LDR_D_FromOffset, V128W dst, MV64 src, ADDR offset) {
  FWriteV64(dst, FReadV64(DisplaceAddress(src, Read(offset))));
}

DEF_SEM(LDR_Q_FromOffset, V128W dst, MV128 src, ADDR offset) {
  UWriteV128(dst, UReadV128(DisplaceAddress(src, Read(offset))));
}

}  // namespace

DEF_ISEL(LDR_B_LDST_POS) = LDR_B;
DEF_ISEL(LDR_H_LDST_POS) = LDR_H;
DEF_ISEL(LDR_S_LDST_POS) = LDR_S;
DEF_ISEL(LDR_D_LDST_POS) = LDR_D;
DEF_ISEL(LDR_Q_LDST_POS) = LDR_Q;

DEF_ISEL(LDUR_B_LDST_UNSCALED) = LDR_B;
DEF_ISEL(LDUR_H_LDST_UNSCALED) = LDR_H;
DEF_ISEL(LDUR_S_LDST_UNSCALED) = LDR_S;
DEF_ISEL(LDUR_D_LDST_UNSCALED) = LDR_D;
DEF_ISEL(LDUR_Q_LDST_UNSCALED) = LDR_Q;

DEF_ISEL(LDR_S_LOADLIT) = LDR_S;
DEF_ISEL(LDR_D_LOADLIT) = LDR_D;
DEF_ISEL(LDR_Q_LOADLIT) = LDR_Q;

DEF_ISEL(LDR_B_LDST_IMMPRE) = LDR_B_UpdateIndex;
DEF_ISEL(LDR_H_LDST_IMMPRE) = LDR_H_UpdateIndex;
DEF_ISEL(LDR_S_LDST_IMMPRE) = LDR_S_UpdateIndex;
DEF_ISEL(LDR_D_LDST_IMMPRE) = LDR_D_UpdateIndex;
DEF_ISEL(LDR_Q_LDST_IMMPRE) = LDR_Q_UpdateIndex;

DEF_ISEL(LDR_B_LDST_IMMPOST) = LDR_B_UpdateIndex;
DEF_ISEL(LDR_H_LDST_IMMPOST) = LDR_H_UpdateIndex;
DEF_ISEL(LDR_S_LDST_IMMPOST) = LDR_S_UpdateIndex;
DEF_ISEL(LDR_D_LDST_IMMPOST) = LDR_D_UpdateIndex;
DEF_ISEL(LDR_Q_LDST_IMMPOST) = LDR_Q_UpdateIndex;

DEF_ISEL(LDR_B_LDST_REGOFF) = LDR_B_FromOffset;
DEF_ISEL(LDR_BL_LDST_REGOFF) = LDR_B_FromOffset;
DEF_ISEL(LDR_H_LDST_REGOFF) = LDR_H_FromOffset;
DEF_ISEL(LDR_S_LDST_REGOFF) = LDR_S_FromOffset;
DEF_ISEL(LDR_D_LDST_REGOFF) = LDR_D_FromOffset;
DEF_ISEL(LDR_Q_LDST_REGOFF) = LDR_Q_FromOffset;

namespace {

DEF_SEM(LDP_S, V128W dst1, V128W dst2, MV64 src) {
  auto src_vec = FReadV32(src);
  FWriteV32(dst1, FExtractV32(src_vec, 0));
  FWriteV32(dst2, FExtractV32(src_vec, 1));
}

DEF_SEM(LDP_D, V128W dst1, V128W dst2, MV128 src) {
  auto src_vec = FReadV64(src);
  FWriteV64(dst1, FExtractV64(src_vec, 0));
  FWriteV64(dst2, FExtractV64(src_vec, 1));
}

DEF_SEM(LDP_Q, V128W dst1, V128W dst2, MV256 src) {
  auto src_vec = UReadV128(src);
  UWriteV128(dst1, UExtractV128(src_vec, 0));
  UWriteV128(dst2, UExtractV128(src_vec, 1));
}

DEF_SEM(LDP_S_UpdateIndex, V128W dst1, V128W dst2, MV64 src, R64W dst_reg, ADDR next_addr) {
  auto src_vec = FReadV32(src);
  FWriteV32(dst1, FExtractV32(src_vec, 0));
  FWriteV32(dst2, FExtractV32(src_vec, 1));
  Write(dst_reg, Read(next_addr));
}

DEF_SEM(LDP_D_UpdateIndex, V128W dst1, V128W dst2, MV128 src, R64W dst_reg, ADDR next_addr) {
  auto src_vec = FReadV64(src);
  FWriteV64(dst1, FExtractV64(src_vec, 0));
  FWriteV64(dst2, FExtractV64(src_vec, 1));
  Write(dst_reg, Read(next_addr));
}

DEF_SEM(LDP_Q_UpdateIndex, V128W dst1, V128W dst2, MV256 src, R64W dst_reg, ADDR next_addr) {
  auto src_vec = UReadV128(src);
  UWriteV128(dst1, UExtractV128(src_vec, 0));
  UWriteV128(dst2, UExtractV128(src_vec, 1));
  Write(dst_reg, Read(next_addr));
}

}  // namespace

DEF_ISEL(LDP_S_LDSTPAIR_OFF) = LDP_S;
DEF_ISEL(LDP_D_LDSTPAIR_OFF) = LDP_D;
DEF_ISEL(LDP_Q_LDSTPAIR_OFF) = LDP_Q;

DEF_ISEL(LDP_S_LDSTPAIR_POST) = LDP_S_UpdateIndex;
DEF_ISEL(LDP_D_LDSTPAIR_POST) = LDP_D_UpdateIndex;
DEF_ISEL(LDP_Q_LDSTPAIR_POST) = LDP_Q_UpdateIndex;

DEF_ISEL(LDP_S_LDSTPAIR_PRE) = LDP_S_UpdateIndex;
DEF_ISEL(LDP_D_LDSTPAIR_PRE) = LDP_D_UpdateIndex;
DEF_ISEL(LDP_Q_LDSTPAIR_PRE) = LDP_Q_UpdateIndex;

namespace {

DEF_SEM(STR_B, V8 src, MV8W dst) {
  UWriteV8(dst, UReadV8(src));
}

DEF_SEM(STR_H, V16 src, MV16W dst) {
  UWriteV16(dst, UReadV16(src));
}

DEF_SEM(STR_S, V32 src, MV32W dst) {
  FWriteV32(dst, FReadV32(src));
}

DEF_SEM(STR_D, V64 src, MV64W dst) {
  FWriteV64(dst, FReadV64(src));
}

DEF_SEM(STR_Q, V128 src, MV128W dst) {
  UWriteV128(dst, UReadV128(src));
}

DEF_SEM(STR_Q_UpdateIndex, V128 src, MV128W dst, R64W dst_reg, ADDR next_addr) {
  UWriteV128(dst, UReadV128(src));
  Write(dst_reg, Read(next_addr));
}

DEF_SEM(STR_Q_FromOffset, V128 src, MV128W dst, ADDR offset) {
  UWriteV128(DisplaceAddress(dst, Read(offset)), UReadV128(src));
}
}  // namespace

DEF_ISEL(STR_B_LDST_POS) = STR_B;
DEF_ISEL(STR_H_LDST_POS) = STR_H;
DEF_ISEL(STR_S_LDST_POS) = STR_S;
DEF_ISEL(STR_D_LDST_POS) = STR_D;
DEF_ISEL(STR_Q_LDST_POS) = STR_Q;

DEF_ISEL(STUR_B_LDST_UNSCALED) = STR_B;
DEF_ISEL(STUR_H_LDST_UNSCALED) = STR_H;
DEF_ISEL(STUR_S_LDST_UNSCALED) = STR_S;
DEF_ISEL(STUR_D_LDST_UNSCALED) = STR_D;
DEF_ISEL(STUR_Q_LDST_UNSCALED) = STR_Q;

DEF_ISEL(STR_Q_LDST_REGOFF) = STR_Q_FromOffset;

DEF_ISEL(STR_Q_LDST_IMMPRE) = STR_Q_UpdateIndex;
DEF_ISEL(STR_Q_LDST_IMMPOST) = STR_Q_UpdateIndex;

namespace {

template <typename D, typename S>
DEF_SEM(LoadAcquire, D dst, S src) {
  __remill_barrier_load_store(runtime_manager);
  WriteZExt(dst, Read(src));
}

}  // namespace

DEF_ISEL(LDARB_LR32_LDSTEXCL) = LoadAcquire<R32W, M8>;
DEF_ISEL(LDARH_LR32_LDSTEXCL) = LoadAcquire<R32W, M16>;
DEF_ISEL(LDAR_LR32_LDSTEXCL) = LoadAcquire<R32W, M32>;
DEF_ISEL(LDAR_LR64_LDSTEXCL) = LoadAcquire<R64W, M64>;

namespace {

#define MAKE_ST1(esize) \
  template <typename D> \
  DEF_SEM(ST1_SINGLE_##esize, V##esize src1, D dst) { \
    auto elems1 = UReadV##esize(src1); \
    UWriteV##esize(dst, elems1); \
  }

MAKE_ST1(64)
MAKE_ST1(128)

#undef MAKE_ST1

}  // namespace

DEF_ISEL(ST1_ASISDLSE_R1_1V_8B) = ST1_SINGLE_64<MV64W>;
DEF_ISEL(ST1_ASISDLSE_R1_1V_16B) = ST1_SINGLE_128<MV128W>;

DEF_ISEL(ST1_ASISDLSE_R1_1V_4H) = ST1_SINGLE_64<MV64W>;
DEF_ISEL(ST1_ASISDLSE_R1_1V_8H) = ST1_SINGLE_128<MV128W>;

DEF_ISEL(ST1_ASISDLSE_R1_1V_2S) = ST1_SINGLE_64<MV64W>;
DEF_ISEL(ST1_ASISDLSE_R1_1V_4S) = ST1_SINGLE_128<MV128W>;

DEF_ISEL(ST1_ASISDLSE_R1_1V_1D) = ST1_SINGLE_64<MV64W>;
DEF_ISEL(ST1_ASISDLSE_R1_1V_2D) = ST1_SINGLE_128<MV128W>;

namespace {

#define MAKE_LD1(esize) \
  template <typename S> \
  DEF_SEM(LD1_SINGLE_##esize, V128W dst1, S src) { \
    auto elems1 = UReadV##esize(src); \
    UWriteV##esize(dst1, elems1); \
  }

MAKE_LD1(8)
MAKE_LD1(16)
MAKE_LD1(32)
MAKE_LD1(64)

#undef MAKE_LD1

}  // namespace

DEF_ISEL(LD1_ASISDLSE_R1_1V_8B) = LD1_SINGLE_8<MV64>;
DEF_ISEL(LD1_ASISDLSE_R1_1V_16B) = LD1_SINGLE_8<MV128>;

DEF_ISEL(LD1_ASISDLSE_R1_1V_4H) = LD1_SINGLE_16<MV64>;
DEF_ISEL(LD1_ASISDLSE_R1_1V_8H) = LD1_SINGLE_16<MV128>;

DEF_ISEL(LD1_ASISDLSE_R1_1V_2S) = LD1_SINGLE_32<MV64>;
DEF_ISEL(LD1_ASISDLSE_R1_1V_4S) = LD1_SINGLE_32<MV128>;

DEF_ISEL(LD1_ASISDLSE_R1_1V_1D) = LD1_SINGLE_64<MV64>;
DEF_ISEL(LD1_ASISDLSE_R1_1V_2D) = LD1_SINGLE_64<MV128>;

namespace {

#define MAKE_LD1(esize) \
  template <typename S> \
  DEF_SEM(LD1_PAIR_##esize, V128W dst1, V128W dst2, S src) { \
    auto elems1 = UReadV##esize(src); \
    auto elems2 = UReadV##esize(GetElementPtr(src, 1U)); \
    UWriteV##esize(dst1, elems1); \
    UWriteV##esize(dst2, elems2); \
  }

MAKE_LD1(8)
MAKE_LD1(16)
MAKE_LD1(32)
MAKE_LD1(64)

#undef MAKE_LD1

}  // namespace

DEF_ISEL(LD1_ASISDLSE_R2_2V_8B) = LD1_PAIR_8<MV64>;
DEF_ISEL(LD1_ASISDLSE_R2_2V_16B) = LD1_PAIR_8<MV128>;

DEF_ISEL(LD1_ASISDLSE_R2_2V_4H) = LD1_PAIR_16<MV64>;
DEF_ISEL(LD1_ASISDLSE_R2_2V_8H) = LD1_PAIR_16<MV128>;

DEF_ISEL(LD1_ASISDLSE_R2_2V_2S) = LD1_PAIR_32<MV64>;
DEF_ISEL(LD1_ASISDLSE_R2_2V_4S) = LD1_PAIR_32<MV128>;

DEF_ISEL(LD1_ASISDLSE_R2_2V_1D) = LD1_PAIR_64<MV64>;
DEF_ISEL(LD1_ASISDLSE_R2_2V_2D) = LD1_PAIR_64<MV128>;

namespace {

#define MAKE_ST1(esize) \
  template <typename D> \
  DEF_SEM(ST1_PAIR_##esize, V##esize src1, V##esize src2, D dst) { \
    auto elems1 = UReadV##esize(src1); \
    auto elems2 = UReadV##esize(src2); \
    UWriteV##esize(dst, elems1); \
    UWriteV##esize(GetElementPtr(dst, 1U), elems2); \
  }

MAKE_ST1(64)
MAKE_ST1(128)

#undef MAKE_ST1

}  //namespace

DEF_ISEL(ST1_ASISDLSE_R2_2V_8B) = ST1_PAIR_64<MV64W>;
DEF_ISEL(ST1_ASISDLSE_R2_2V_16B) = ST1_PAIR_128<MV128W>;

DEF_ISEL(ST1_ASISDLSE_R2_2V_4H) = ST1_PAIR_64<MV64W>;
DEF_ISEL(ST1_ASISDLSE_R2_2V_8H) = ST1_PAIR_128<MV128W>;

DEF_ISEL(ST1_ASISDLSE_R2_2V_2S) = ST1_PAIR_64<MV64W>;
DEF_ISEL(ST1_ASISDLSE_R2_2V_4S) = ST1_PAIR_128<MV128W>;

DEF_ISEL(ST1_ASISDLSE_R2_2V_1D) = ST1_PAIR_64<MV64W>;
DEF_ISEL(ST1_ASISDLSE_R2_2V_2D) = ST1_PAIR_128<MV128W>;

namespace {

#define MAKE_ST1_POSTINDEX(esize) \
  template <typename D> \
  DEF_SEM(ST1_PAIR_POSTINDEX_##esize, V##esize src1, V##esize src2, D dst, R64W addr_reg, \
          ADDR next_addr) { \
    ST1_PAIR_##esize(runtime_manager, state, src1, src2, dst); \
    Write(addr_reg, Read(next_addr)); \
  }

MAKE_ST1_POSTINDEX(64)
MAKE_ST1_POSTINDEX(128)

#undef MAKE_ST1_POSTINDEX

}  // namespace

DEF_ISEL(ST1_ASISDLSEP_I2_I2_8B) = ST1_PAIR_POSTINDEX_64<MV64W>;
DEF_ISEL(ST1_ASISDLSEP_I2_I2_16B) = ST1_PAIR_POSTINDEX_128<MV128W>;

DEF_ISEL(ST1_ASISDLSEP_I2_I2_4H) = ST1_PAIR_POSTINDEX_64<MV64W>;
DEF_ISEL(ST1_ASISDLSEP_I2_I2_8H) = ST1_PAIR_POSTINDEX_128<MV128W>;

DEF_ISEL(ST1_ASISDLSEP_I2_I2_2S) = ST1_PAIR_POSTINDEX_64<MV64W>;
DEF_ISEL(ST1_ASISDLSEP_I2_I2_4S) = ST1_PAIR_POSTINDEX_128<MV128W>;

DEF_ISEL(ST1_ASISDLSEP_I2_I2_1D) = ST1_PAIR_POSTINDEX_64<MV64W>;
DEF_ISEL(ST1_ASISDLSEP_I2_I2_2D) = ST1_PAIR_POSTINDEX_128<MV128W>;

namespace {
#define MAKE_ST1_UNIT(esize) \
  DEF_SEM(ST1_UNIT_V##esize, V128 src, I32 index, M##esize##W dst_mem) { \
    auto src_v = UReadV##esize(src); \
    uint##esize##_t elem = UExtractV##esize(src_v, Read(index)); \
    WriteTrunc(dst_mem, elem); \
\
  }  // namespace

MAKE_ST1_UNIT(8)
MAKE_ST1_UNIT(16)
MAKE_ST1_UNIT(32)
MAKE_ST1_UNIT(64)

#undef MAKE_ST1_UNIT

}  // namespace

// ST1  { <Vt>.B }[<index>], [<Xn|SP>]
DEF_ISEL(ST1_ASISDLSO_B1_1B) = ST1_UNIT_V8;
// ST1  { <Vt>.H }[<index>], [<Xn|SP>]
DEF_ISEL(ST1_ASISDLSO_H1_1H) = ST1_UNIT_V16;
// ST1  { <Vt>.S }[<index>], [<Xn|SP>]
DEF_ISEL(ST1_ASISDLSO_S1_1S) = ST1_UNIT_V32;
// ST1  { <Vt>.D }[<index>], [<Xn|SP>]
DEF_ISEL(ST1_ASISDLSO_D1_1D) = ST1_UNIT_V64;

namespace {
#define MAKE_ST1_UNIT_POSTINDEX(esize) \
  DEF_SEM(ST1_UNIT_POSTINDEX_V##esize, V128 src, I32 index, M##esize##W dst_mem, R64W dst_reg, \
          ADDR next_addr) { \
    auto src_v = UReadV##esize(src); \
    uint##esize##_t elem = UExtractV##esize(src_v, Read(index)); \
    WriteTrunc(dst_mem, elem); \
    Write(dst_reg, Read(next_addr)); \
\
  }  // namespace

MAKE_ST1_UNIT_POSTINDEX(8)
MAKE_ST1_UNIT_POSTINDEX(16)
MAKE_ST1_UNIT_POSTINDEX(32)
MAKE_ST1_UNIT_POSTINDEX(64)

#undef MAKE_ST1_UNIT_POSTINDEX

}  // namespace

// ST1  { <Vt>.B }[<index>], [<Xn|SP>], #1
DEF_ISEL(ST1_ASISDLSOP_B1_I1B) = ST1_UNIT_POSTINDEX_V8;
// ST1  { <Vt>.B }[<index>], [<Xn|SP>], <Xm>
DEF_ISEL(ST1_ASISDLSOP_BX1_R1B) = ST1_UNIT_POSTINDEX_V8;
// ST1  { <Vt>.H }[<index>], [<Xn|SP>], #2
DEF_ISEL(ST1_ASISDLSOP_H1_I1H) = ST1_UNIT_POSTINDEX_V16;
// ST1  { <Vt>.H }[<index>], [<Xn|SP>], <Xm>
DEF_ISEL(ST1_ASISDLSOP_HX1_R1H) = ST1_UNIT_POSTINDEX_V16;
// ST1  { <Vt>.S }[<index>], [<Xn|SP>], #4
DEF_ISEL(ST1_ASISDLSOP_S1_I1S) = ST1_UNIT_POSTINDEX_V32;
// ST1  { <Vt>.S }[<index>], [<Xn|SP>], <Xm>
DEF_ISEL(ST1_ASISDLSOP_SX1_R1S) = ST1_UNIT_POSTINDEX_V32;
// ST1  { <Vt>.D }[<index>], [<Xn|SP>], #8
DEF_ISEL(ST1_ASISDLSOP_D1_I1D) = ST1_UNIT_POSTINDEX_V64;
// ST1  { <Vt>.D }[<index>], [<Xn|SP>], <Xm>
DEF_ISEL(ST1_ASISDLSOP_DX1_R1D) = ST1_UNIT_POSTINDEX_V64;

namespace {

#define MAKE_LD1(esize) \
  template <typename S> \
  DEF_SEM(LD1_TRIPLE_##esize, V128W dst1, V128W dst2, V128W dst3, S src) { \
    auto elems1 = UReadV##esize(src); \
    auto elems2 = UReadV##esize(GetElementPtr(src, 1U)); \
    auto elems3 = UReadV##esize(GetElementPtr(src, 2U)); \
    UWriteV##esize(dst1, elems1); \
    UWriteV##esize(dst2, elems2); \
    UWriteV##esize(dst3, elems3); \
  }

MAKE_LD1(8)
MAKE_LD1(16)
MAKE_LD1(32)
MAKE_LD1(64)

#undef MAKE_LD1

}  // namespace

DEF_ISEL(LD1_ASISDLSE_R3_3V_8B) = LD1_TRIPLE_8<MV64>;
DEF_ISEL(LD1_ASISDLSE_R3_3V_16B) = LD1_TRIPLE_8<MV128>;

DEF_ISEL(LD1_ASISDLSE_R3_3V_4H) = LD1_TRIPLE_16<MV64>;
DEF_ISEL(LD1_ASISDLSE_R3_3V_8H) = LD1_TRIPLE_16<MV128>;

DEF_ISEL(LD1_ASISDLSE_R3_3V_2S) = LD1_TRIPLE_32<MV64>;
DEF_ISEL(LD1_ASISDLSE_R3_3V_4S) = LD1_TRIPLE_32<MV128>;

DEF_ISEL(LD1_ASISDLSE_R3_3V_1D) = LD1_TRIPLE_64<MV64>;
DEF_ISEL(LD1_ASISDLSE_R3_3V_2D) = LD1_TRIPLE_64<MV128>;

namespace {

#define MAKE_LD1(esize) \
  template <typename S> \
  DEF_SEM(LD1_QUAD_##esize, V128W dst1, V128W dst2, V128W dst3, V128W dst4, S src) { \
    auto elems1 = UReadV##esize(src); \
    auto elems2 = UReadV##esize(GetElementPtr(src, 1U)); \
    auto elems3 = UReadV##esize(GetElementPtr(src, 2U)); \
    auto elems4 = UReadV##esize(GetElementPtr(src, 3U)); \
    UWriteV##esize(dst1, elems1); \
    UWriteV##esize(dst2, elems2); \
    UWriteV##esize(dst3, elems3); \
    UWriteV##esize(dst4, elems4); \
  }

MAKE_LD1(8)
MAKE_LD1(16)
MAKE_LD1(32)
MAKE_LD1(64)

#undef MAKE_LD1

}  // namespace

DEF_ISEL(LD1_ASISDLSE_R4_4V_8B) = LD1_QUAD_8<MV64>;
DEF_ISEL(LD1_ASISDLSE_R4_4V_16B) = LD1_QUAD_8<MV128>;

DEF_ISEL(LD1_ASISDLSE_R4_4V_4H) = LD1_QUAD_16<MV64>;
DEF_ISEL(LD1_ASISDLSE_R4_4V_8H) = LD1_QUAD_16<MV128>;

DEF_ISEL(LD1_ASISDLSE_R4_4V_2S) = LD1_QUAD_32<MV64>;
DEF_ISEL(LD1_ASISDLSE_R4_4V_4S) = LD1_QUAD_32<MV128>;

DEF_ISEL(LD1_ASISDLSE_R4_4V_1D) = LD1_QUAD_64<MV64>;
DEF_ISEL(LD1_ASISDLSE_R4_4V_2D) = LD1_QUAD_64<MV128>;

namespace {

#define MAKE_LD1_POSTINDEX(esize) \
  template <typename S> \
  DEF_SEM(LD1_SINGLE_POSTINDEX_##esize, V128W dst1, S src, R64W addr_reg, ADDR next_addr) { \
    LD1_SINGLE_##esize(runtime_manager, state, dst1, src); \
    Write(addr_reg, Read(next_addr)); \
  }

MAKE_LD1_POSTINDEX(8)
MAKE_LD1_POSTINDEX(16)
MAKE_LD1_POSTINDEX(32)
MAKE_LD1_POSTINDEX(64)

#undef MAKE_LD1_POSTINDEX

}  // namespace

DEF_ISEL(LD1_ASISDLSEP_I1_I1_8B) = LD1_SINGLE_POSTINDEX_8<MV64>;
DEF_ISEL(LD1_ASISDLSEP_I1_I1_16B) = LD1_SINGLE_POSTINDEX_8<MV128>;

DEF_ISEL(LD1_ASISDLSEP_I1_I1_4H) = LD1_SINGLE_POSTINDEX_16<MV64>;
DEF_ISEL(LD1_ASISDLSEP_I1_I1_8H) = LD1_SINGLE_POSTINDEX_16<MV128>;

DEF_ISEL(LD1_ASISDLSEP_I1_I1_2S) = LD1_SINGLE_POSTINDEX_32<MV64>;
DEF_ISEL(LD1_ASISDLSEP_I1_I1_4S) = LD1_SINGLE_POSTINDEX_32<MV128>;

DEF_ISEL(LD1_ASISDLSEP_I1_I1_1D) = LD1_SINGLE_POSTINDEX_64<MV64>;
DEF_ISEL(LD1_ASISDLSEP_I1_I1_2D) = LD1_SINGLE_POSTINDEX_64<MV128>;

namespace {

#define MAKE_LD1_POSTINDEX(esize) \
  template <typename S> \
  DEF_SEM(LD1_PAIR_POSTINDEX_##esize, V128W dst1, V128W dst2, S src, R64W addr_reg, \
          ADDR next_addr) { \
    LD1_PAIR_##esize(runtime_manager, state, dst1, dst2, src); \
    Write(addr_reg, Read(next_addr)); \
  }

MAKE_LD1_POSTINDEX(8)
MAKE_LD1_POSTINDEX(16)
MAKE_LD1_POSTINDEX(32)
MAKE_LD1_POSTINDEX(64)

#undef MAKE_LD1_POSTINDEX

}  // namespace

DEF_ISEL(LD1_ASISDLSEP_I2_I2_8B) = LD1_PAIR_POSTINDEX_8<MV64>;
DEF_ISEL(LD1_ASISDLSEP_I2_I2_16B) = LD1_PAIR_POSTINDEX_8<MV128>;

DEF_ISEL(LD1_ASISDLSEP_I2_I2_4H) = LD1_PAIR_POSTINDEX_16<MV64>;
DEF_ISEL(LD1_ASISDLSEP_I2_I2_8H) = LD1_PAIR_POSTINDEX_16<MV128>;

DEF_ISEL(LD1_ASISDLSEP_I2_I2_2S) = LD1_PAIR_POSTINDEX_32<MV64>;
DEF_ISEL(LD1_ASISDLSEP_I2_I2_4S) = LD1_PAIR_POSTINDEX_32<MV128>;

DEF_ISEL(LD1_ASISDLSEP_I2_I2_1D) = LD1_PAIR_POSTINDEX_64<MV64>;
DEF_ISEL(LD1_ASISDLSEP_I2_I2_2D) = LD1_PAIR_POSTINDEX_64<MV128>;

namespace {

#define MAKE_LD1_POSTINDEX(esize) \
  template <typename S> \
  DEF_SEM(LD1_TRIPLE_POSTINDEX_##esize, V128W dst1, V128W dst2, V128W dst3, S src, R64W addr_reg, \
          ADDR next_addr) { \
    LD1_TRIPLE_##esize(runtime_manager, state, dst1, dst2, dst3, src); \
    Write(addr_reg, Read(next_addr)); \
  }

MAKE_LD1_POSTINDEX(8)
MAKE_LD1_POSTINDEX(16)
MAKE_LD1_POSTINDEX(32)
MAKE_LD1_POSTINDEX(64)

#undef MAKE_LD1_POSTINDEX

}  // namespace

DEF_ISEL(LD1_ASISDLSEP_I3_I3_8B) = LD1_TRIPLE_POSTINDEX_8<MV64>;
DEF_ISEL(LD1_ASISDLSEP_I3_I3_16B) = LD1_TRIPLE_POSTINDEX_8<MV128>;

DEF_ISEL(LD1_ASISDLSEP_I3_I3_4H) = LD1_TRIPLE_POSTINDEX_16<MV64>;
DEF_ISEL(LD1_ASISDLSEP_I3_I3_8H) = LD1_TRIPLE_POSTINDEX_16<MV128>;

DEF_ISEL(LD1_ASISDLSEP_I3_I3_2S) = LD1_TRIPLE_POSTINDEX_32<MV64>;
DEF_ISEL(LD1_ASISDLSEP_I3_I3_4S) = LD1_TRIPLE_POSTINDEX_32<MV128>;

DEF_ISEL(LD1_ASISDLSEP_I3_I3_1D) = LD1_TRIPLE_POSTINDEX_64<MV64>;
DEF_ISEL(LD1_ASISDLSEP_I3_I3_2D) = LD1_TRIPLE_POSTINDEX_64<MV128>;

namespace {

#define MAKE_LD1_POSTINDEX(esize) \
  template <typename S> \
  DEF_SEM(LD1_QUAD_POSTINDEX_##esize, V128W dst1, V128W dst2, V128W dst3, V128W dst4, S src, \
          R64W addr_reg, ADDR next_addr) { \
    LD1_QUAD_##esize(runtime_manager, state, dst1, dst2, dst3, dst4, src); \
    Write(addr_reg, Read(next_addr)); \
  }

MAKE_LD1_POSTINDEX(8)
MAKE_LD1_POSTINDEX(16)
MAKE_LD1_POSTINDEX(32)
MAKE_LD1_POSTINDEX(64)

#undef MAKE_LD1_POSTINDEX

}  // namespace

DEF_ISEL(LD1_ASISDLSEP_I4_I4_8B) = LD1_QUAD_POSTINDEX_8<MV64>;
DEF_ISEL(LD1_ASISDLSEP_I4_I4_16B) = LD1_QUAD_POSTINDEX_8<MV128>;

DEF_ISEL(LD1_ASISDLSEP_I4_I4_4H) = LD1_QUAD_POSTINDEX_16<MV64>;
DEF_ISEL(LD1_ASISDLSEP_I4_I4_8H) = LD1_QUAD_POSTINDEX_16<MV128>;

DEF_ISEL(LD1_ASISDLSEP_I4_I4_2S) = LD1_QUAD_POSTINDEX_32<MV64>;
DEF_ISEL(LD1_ASISDLSEP_I4_I4_4S) = LD1_QUAD_POSTINDEX_32<MV128>;

DEF_ISEL(LD1_ASISDLSEP_I4_I4_1D) = LD1_QUAD_POSTINDEX_64<MV64>;
DEF_ISEL(LD1_ASISDLSEP_I4_I4_2D) = LD1_QUAD_POSTINDEX_64<MV128>;

namespace {

#define MAKE_LD2(size) \
  template <typename S> \
  DEF_SEM(LD2_##size, V128W dst1, V128W dst2, S src) { \
    auto vec = UReadV##size(src); \
    auto dst1_vec = UClearV##size(UReadV##size(dst1)); \
    auto dst2_vec = UClearV##size(UReadV##size(dst2)); \
    _Pragma("unroll") for (size_t i = 0, j = 0; i < NumVectorElems(vec); j++) { \
      dst1_vec = UInsertV##size(dst1_vec, j, UExtractV##size(vec, i++)); \
      dst2_vec = UInsertV##size(dst2_vec, j, UExtractV##size(vec, i++)); \
    } \
    UWriteV##size(dst1, dst1_vec); \
    UWriteV##size(dst2, dst2_vec); \
  }

MAKE_LD2(8)
MAKE_LD2(16)
MAKE_LD2(32)
MAKE_LD2(64)

#undef MAKE_LD2

#define MAKE_LD2(size) \
  template <typename S> \
  DEF_SEM(LD2_##size##_POSTINDEX, V128W dst1, V128W dst2, S src, R64W addr_reg, ADDR next_addr) { \
    LD2_##size(runtime_manager, state, dst1, dst2, src); \
    Write(addr_reg, Read(next_addr)); \
  }

MAKE_LD2(8)
MAKE_LD2(16)
MAKE_LD2(32)
MAKE_LD2(64)

#undef MAKE_LD2

}  // namespace

DEF_ISEL(LD2_ASISDLSE_R2_8B) = LD2_8<MV128>;
DEF_ISEL(LD2_ASISDLSE_R2_16B) = LD2_8<MV256>;
DEF_ISEL(LD2_ASISDLSE_R2_4H) = LD2_16<MV128>;
DEF_ISEL(LD2_ASISDLSE_R2_8H) = LD2_16<MV256>;
DEF_ISEL(LD2_ASISDLSE_R2_2S) = LD2_32<MV128>;
DEF_ISEL(LD2_ASISDLSE_R2_4S) = LD2_32<MV256>;
DEF_ISEL(LD2_ASISDLSE_R2_2D) = LD2_64<MV256>;

DEF_ISEL(LD2_ASISDLSEP_I2_I_8B) = LD2_8_POSTINDEX<MV128>;
DEF_ISEL(LD2_ASISDLSEP_I2_I_16B) = LD2_8_POSTINDEX<MV256>;
DEF_ISEL(LD2_ASISDLSEP_I2_I_4H) = LD2_16_POSTINDEX<MV128>;
DEF_ISEL(LD2_ASISDLSEP_I2_I_8H) = LD2_16_POSTINDEX<MV256>;
DEF_ISEL(LD2_ASISDLSEP_I2_I_2S) = LD2_32_POSTINDEX<MV128>;
DEF_ISEL(LD2_ASISDLSEP_I2_I_4S) = LD2_32_POSTINDEX<MV256>;
DEF_ISEL(LD2_ASISDLSEP_I2_I_2D) = LD2_64_POSTINDEX<MV256>;

DEF_ISEL(LD2_ASISDLSEP_R2_R_8B) = LD2_8_POSTINDEX<MV128>;
DEF_ISEL(LD2_ASISDLSEP_R2_R_16B) = LD2_8_POSTINDEX<MV256>;
DEF_ISEL(LD2_ASISDLSEP_R2_R_4H) = LD2_16_POSTINDEX<MV128>;
DEF_ISEL(LD2_ASISDLSEP_R2_R_8H) = LD2_16_POSTINDEX<MV256>;
DEF_ISEL(LD2_ASISDLSEP_R2_R_2S) = LD2_32_POSTINDEX<MV128>;
DEF_ISEL(LD2_ASISDLSEP_R2_R_4S) = LD2_32_POSTINDEX<MV256>;
DEF_ISEL(LD2_ASISDLSEP_R2_R_2D) = LD2_64_POSTINDEX<MV256>;

namespace {

#define MAKE_LD3(size) \
  template <typename S, size_t count> \
  DEF_SEM(LD3_##size, V128W dst1, V128W dst2, V128W dst3, S src) { \
    auto dst1_vec = UClearV##size(UReadV##size(dst1)); \
    auto dst2_vec = UClearV##size(UReadV##size(dst2)); \
    auto dst3_vec = UClearV##size(UReadV##size(dst3)); \
    _Pragma("unroll") for (size_t i = 0; i < count; ++i) { \
      auto val = Read(src); \
      src = GetElementPtr(src, 1); \
      dst1_vec = UInsertV##size(dst1_vec, i, val); \
      val = Read(src); \
      src = GetElementPtr(src, 1); \
      dst2_vec = UInsertV##size(dst2_vec, i, val); \
      val = Read(src); \
      src = GetElementPtr(src, 1); \
      dst3_vec = UInsertV##size(dst3_vec, i, val); \
    } \
    UWriteV##size(dst1, dst1_vec); \
    UWriteV##size(dst2, dst2_vec); \
    UWriteV##size(dst3, dst3_vec); \
  }

MAKE_LD3(8)
MAKE_LD3(16)
MAKE_LD3(32)
MAKE_LD3(64)

#undef MAKE_LD3

}  // namespace

DEF_ISEL(LD3_ASISDLSE_R3_8B) = LD3_8<M8, 8>;
DEF_ISEL(LD3_ASISDLSE_R3_16B) = LD3_8<M8, 16>;
DEF_ISEL(LD3_ASISDLSE_R3_4H) = LD3_16<M16, 4>;
DEF_ISEL(LD3_ASISDLSE_R3_8H) = LD3_16<M16, 8>;
DEF_ISEL(LD3_ASISDLSE_R3_2S) = LD3_32<M32, 2>;
DEF_ISEL(LD3_ASISDLSE_R3_4S) = LD3_32<M32, 4>;
DEF_ISEL(LD3_ASISDLSE_R3_2D) = LD3_64<M64, 2>;

namespace {

#define MAKE_LD4(size) \
  template <typename S, size_t count> \
  DEF_SEM(LD4_##size, V128W dst1, V128W dst2, V128W dst3, V128W dst4, S src) { \
    auto dst1_vec = UClearV##size(UReadV##size(dst1)); \
    auto dst2_vec = UClearV##size(UReadV##size(dst2)); \
    auto dst3_vec = UClearV##size(UReadV##size(dst3)); \
    auto dst4_vec = UClearV##size(UReadV##size(dst4)); \
    _Pragma("unroll") for (size_t i = 0; i < count; ++i) { \
      auto val = Read(src); \
      src = GetElementPtr(src, 1); \
      dst1_vec = UInsertV##size(dst1_vec, i, val); \
      val = Read(src); \
      src = GetElementPtr(src, 1); \
      dst2_vec = UInsertV##size(dst2_vec, i, val); \
      val = Read(src); \
      src = GetElementPtr(src, 1); \
      dst3_vec = UInsertV##size(dst3_vec, i, val); \
      val = Read(src); \
      src = GetElementPtr(src, 1); \
      dst4_vec = UInsertV##size(dst4_vec, i, val); \
    } \
    UWriteV##size(dst1, dst1_vec); \
    UWriteV##size(dst2, dst2_vec); \
    UWriteV##size(dst3, dst3_vec); \
    UWriteV##size(dst4, dst4_vec); \
  }

MAKE_LD4(8)
MAKE_LD4(16)
MAKE_LD4(32)
MAKE_LD4(64)

#undef MAKE_LD4

}  // namespace

DEF_ISEL(LD4_ASISDLSE_R4_8B) = LD4_8<M8, 8>;
DEF_ISEL(LD4_ASISDLSE_R4_16B) = LD4_8<M8, 16>;
DEF_ISEL(LD4_ASISDLSE_R4_4H) = LD4_16<M16, 4>;
DEF_ISEL(LD4_ASISDLSE_R4_8H) = LD4_16<M16, 8>;
DEF_ISEL(LD4_ASISDLSE_R4_2S) = LD4_32<M32, 2>;
DEF_ISEL(LD4_ASISDLSE_R4_4S) = LD4_32<M32, 4>;
DEF_ISEL(LD4_ASISDLSE_R4_2D) = LD4_64<M64, 2>;

namespace {

#define INS_VEC(size) \
  template <typename T> \
  DEF_SEM(INS_##size, V128W dst, I64 idx, T src) { \
    auto vec = UReadV##size(dst); \
    auto index = Read(idx); \
    auto val = Read(src); \
    vec = UInsertV##size(vec, index, TruncTo<uint##size##_t>(val)); \
    UWriteV##size(dst, vec); \
  }

INS_VEC(8)
INS_VEC(16)
INS_VEC(32)
INS_VEC(64)

#undef INS_VEC

}  // namespace

DEF_ISEL(INS_ASIMDINS_IR_R_B) = INS_8<R32>;
DEF_ISEL(INS_ASIMDINS_IR_R_H) = INS_16<R32>;
DEF_ISEL(INS_ASIMDINS_IR_R_S) = INS_32<R32>;
DEF_ISEL(INS_ASIMDINS_IR_R_D) = INS_64<R64>;

namespace {

// LD1R  { <Vt>.<T> }, [<Xn|SP>]
#define MAKE_LD1R(elem_size) \
  template <typename D, typename T> \
  DEF_SEM(LD1R_##elem_size, D dst, T mem) { \
    auto mem_val = Read(mem); \
    auto tmp_v = UReadV##elem_size(dst); \
    _Pragma("unroll") for (auto &elem : tmp_v.elems) { \
      elem = mem_val; \
    } \
    UWriteV##elem_size(dst, tmp_v); \
\
  }  // namespace

MAKE_LD1R(8)
MAKE_LD1R(16)
MAKE_LD1R(32)
MAKE_LD1R(64)

}  // namespace

DEF_ISEL(LD1R_ASISDLSO_R1_8B) = LD1R_8<V64W, M8>;
DEF_ISEL(LD1R_ASISDLSO_R1_16B) = LD1R_8<V128W, M8>;
DEF_ISEL(LD1R_ASISDLSO_R1_4H) = LD1R_16<V64W, M16>;
DEF_ISEL(LD1R_ASISDLSO_R1_8H) = LD1R_16<V128W, M16>;
DEF_ISEL(LD1R_ASISDLSO_R1_2S) = LD1R_32<V64W, M32>;
DEF_ISEL(LD1R_ASISDLSO_R1_4S) = LD1R_32<V128W, M32>;
DEF_ISEL(LD1R_ASISDLSO_R1_1D) = LD1R_64<V64W, M64>;
DEF_ISEL(LD1R_ASISDLSO_R1_2D) = LD1R_64<V128W, M64>;

// MOV  <Vd>.<Ts>[<index1>], <Vn>.<Ts>[<index2>]
namespace {

#define INS_MOV_VEC(size) \
  DEF_SEM(INS_MOV_##size, V128W dst, I64 idx1, V128 src, I64 idx2) { \
    auto vec = UReadV##size(dst); \
    auto index_1 = Read(idx1); \
    auto index_2 = Read(idx2); \
    auto src_vec = UReadV##size(src); \
    vec = UInsertV##size(vec, index_1, TruncTo<uint##size##_t>(src_vec.elems[index_2])); \
    UWriteV##size(dst, vec); \
  }

INS_MOV_VEC(8)
INS_MOV_VEC(16)
INS_MOV_VEC(32)
INS_MOV_VEC(64)

#undef INS_MOV_VEC

}  // namespace

DEF_ISEL(MOV_INS_ASIMDINS_IV_V_B) = INS_MOV_8;
DEF_ISEL(MOV_INS_ASIMDINS_IV_V_H) = INS_MOV_16;
DEF_ISEL(MOV_INS_ASIMDINS_IV_V_S) = INS_MOV_32;
DEF_ISEL(MOV_INS_ASIMDINS_IV_V_D) = INS_MOV_64;

namespace {

#define EXTRACT_VEC(prefix, size, ext_op) \
  template <typename D, typename T> \
  DEF_SEM(prefix##MovFromVec##size, D dst, V128 src, I64 index) { \
    WriteZExt(dst, ext_op<T>(prefix##ExtractV##size(prefix##ReadV##size(src), Read(index)))); \
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

DEF_ISEL(UMOV_ASIMDINS_W_W_B) = UMovFromVec8<R32W, uint32_t>;
DEF_ISEL(UMOV_ASIMDINS_W_W_H) = UMovFromVec16<R32W, uint32_t>;
DEF_ISEL(UMOV_ASIMDINS_W_W_S) = UMovFromVec32<R32W, uint32_t>;
DEF_ISEL(UMOV_ASIMDINS_X_X_D) = UMovFromVec64<R64W, uint64_t>;

DEF_ISEL(SMOV_ASIMDINS_W_W_B) = SMovFromVec8<R32W, int32_t>;
DEF_ISEL(SMOV_ASIMDINS_W_W_H) = SMovFromVec16<R32W, int32_t>;

DEF_ISEL(SMOV_ASIMDINS_X_X_B) = SMovFromVec8<R64W, int64_t>;
DEF_ISEL(SMOV_ASIMDINS_X_X_H) = SMovFromVec16<R64W, int64_t>;
DEF_ISEL(SMOV_ASIMDINS_X_X_S) = SMovFromVec32<R64W, int64_t>;

namespace {

DEF_SEM(MOVI_D2, V128W dst, I64 src) {
  auto imm = Read(src);
  auto res = UClearV64(UReadV64(dst));
  res = UInsertV64(res, 0, imm);
  res = UInsertV64(res, 1, imm);
  UWriteV64(dst, res);
}

template <typename V, typename VNW>
DEF_SEM(MOVI_N_B, VNW dst, I8 src) {
  auto imm = Read(src);
  V res = {};
  _Pragma("unroll") for (auto &elem : res.elems) {
    elem = imm;
  }
  UWriteV8(dst, res);
}

template <typename V, typename VNW>
DEF_SEM(MOVI_L_HL, VNW dst, I16 src) {
  auto imm = Read(src);
  V res = {};
  _Pragma("unroll") for (auto &elem : res.elems) {
    elem = imm;
  }
  UWriteV16(dst, res);
}

template <typename V, typename VNW>
DEF_SEM(MOVI_L_SL, VNW dst, I32 src) {
  auto imm = Read(src);
  V res = {};
  _Pragma("unroll") for (auto &elem : res.elems) {
    elem = imm;
  }
  UWriteV32(dst, res);
}

DEF_SEM(MOVI_DS, V128W dst, I64 src) {
  auto imm = Read(src);
  auto res = UClearV64(UReadV64(dst));
  res = UInsertV64(res, 0, imm);
  UWriteV64(dst, res);
}

template <typename V, typename VNW>
DEF_SEM(BIC_L_HL, VNW dst, I16 src) {
  auto imm = Read(src);
  auto src_vec = UReadV16(dst);
  V res = {};
  _Pragma("unroll") for (int i = 0; i < NumVectorElems(src_vec); i++) {
    res.elems[i] = src_vec.elems[i] & (~imm);
  }
  UWriteV16(dst, res);
}

template <typename V, typename VNW>
DEF_SEM(BIC_L_SL, VNW dst, I32 src) {
  auto imm = Read(src);
  auto src_vec = UReadV32(dst);
  V res = {};
  _Pragma("unroll") for (int i = 0; i < NumVectorElems(src_vec); i++) {
    res.elems[i] = src_vec.elems[i] & (~imm);
  }
  UWriteV32(dst, res);
}

}  // namespace

DEF_ISEL(MOVI_ASIMDIMM_D2_D) = MOVI_D2;
DEF_ISEL(MOVI_ASIMDIMM_N_B_8B) = MOVI_N_B<uint8v8_t, V64W>;
DEF_ISEL(MOVI_ASIMDIMM_N_B_16B) = MOVI_N_B<uint8v16_t, V128W>;
DEF_ISEL(MOVI_ASIMDIMM_L_HL_4H) = MOVI_L_HL<uint16v4_t, V64W>;
DEF_ISEL(MOVI_ASIMDIMM_L_HL_8H) = MOVI_L_HL<uint16v8_t, V128W>;
DEF_ISEL(MOVI_ASIMDIMM_L_SL_2S) = MOVI_L_SL<uint32v2_t, V64W>;
DEF_ISEL(MOVI_ASIMDIMM_L_SL_4S) = MOVI_L_SL<uint32v4_t, V128W>;
DEF_ISEL(MOVI_ASIMDIMM_M_SM_2S) = MOVI_L_SL<uint32v2_t, V64W>;
DEF_ISEL(MOVI_ASIMDIMM_M_SM_4S) = MOVI_L_SL<uint32v4_t, V128W>;
DEF_ISEL(MOVI_ASIMDIMM_D_DS) = MOVI_DS;

DEF_ISEL(MVNI_ASIMDIMM_L_HL_4H) = MOVI_L_HL<uint16v4_t, V64W>;
DEF_ISEL(MVNI_ASIMDIMM_L_HL_8H) = MOVI_L_HL<uint16v8_t, V128W>;
DEF_ISEL(MVNI_ASIMDIMM_L_SL_2S) = MOVI_L_SL<uint32v2_t, V64W>;
DEF_ISEL(MVNI_ASIMDIMM_L_SL_4S) = MOVI_L_SL<uint32v4_t, V128W>;
DEF_ISEL(MVNI_ASIMDIMM_M_SM_2S) = MOVI_L_SL<uint32v2_t, V64W>;
DEF_ISEL(MVNI_ASIMDIMM_M_SM_4S) = MOVI_L_SL<uint32v4_t, V128W>;

DEF_ISEL(BIC_ASIMDIMM_L_HL_4H) = BIC_L_HL<uint16v4_t, V64W>;
DEF_ISEL(BIC_ASIMDIMM_L_HL_8H) = BIC_L_HL<uint16v8_t, V128W>;
DEF_ISEL(BIC_ASIMDIMM_L_SL_2S) = BIC_L_SL<uint32v2_t, V64W>;
DEF_ISEL(BIC_ASIMDIMM_L_SL_4S) = BIC_L_SL<uint32v4_t, V128W>;

/* casa instruction semantics (FIXME: no atomic) */
namespace {
template <typename S, typename D>
DEF_SEM(CAS, S src1, S src2, D dst) {
  using T = typename BaseType<S>::BT;
  T org_val = Read(dst);
  T cmp_val = Read(src1);
  auto cond_eq = UCmpEq(org_val, cmp_val);
  WriteTrunc(src1, org_val);
  auto new_val = Select<T>(cond_eq, Read(src2), org_val);
  WriteTrunc(dst, new_val);
}
}  // namespace

DEF_ISEL(CAS_C32_LDSTEXCL) = CAS<R32W, M32W>;
DEF_ISEL(CAS_C64_LDSTEXCL) = CAS<R64W, M64W>;

DEF_ISEL(CASA_C32_LDSTEXCL) = CAS<R32W, M32W>;
DEF_ISEL(CASA_C64_LDSTEXCL) = CAS<R64W, M64W>;

DEF_ISEL(CASAL_C32_LDSTEXCL) = CAS<R32W, M32W>;
DEF_ISEL(CASAL_C64_LDSTEXCL) = CAS<R64W, M64W>;

DEF_ISEL(CASL_C32_LDSTEXCL) = CAS<R32W, M32W>;
DEF_ISEL(CASL_C64_LDSTEXCL) = CAS<R64W, M64W>;

namespace {

template <typename D>
DEF_SEM(DC_ZVA, D dst_mem) {
  auto bs = state.sr.dczid_el0.qword & 0b1111; /* get BS field */
  for (size_t i = 0; i < static_cast<size_t>(pow(2.0, static_cast<double>(bs))); i++) {
    Write_Dc_Zva(dst_mem, sizeof(uint32_t) * i, 0);
  }
}

}  // namespace

DEF_ISEL(DC_SYS_CR_SYSTEM) = DC_ZVA<M64W>; /* DC  <dc_op>, <Xt> */

namespace {

#define MAKE_CNT(total_size, elem_num) \
  DEF_SEM(CNT_SIMD_V##total_size, V##total_size##W dst, V##total_size src) { \
    auto d0 = UExtractV##total_size(UReadV##total_size(src), 0); \
    uint8v##elem_num##_t tmp_v = {}; \
    uint##total_size##_t cnt = d0 - ((d0 >> 1) & 0x5555555555555555); \
    cnt = (cnt & 0x3333333333333333) + ((cnt >> 2) & 0x3333333333333333); \
    cnt = (cnt + (cnt >> 4)) & 0x0f0f0f0f0f0f0f0f; \
    _Pragma("unroll") for (int i = 0; i < elem_num; i++) { \
      tmp_v.elems[i] = (uint8_t) ((cnt >> i * 8) & 0xff); \
    } \
    UWriteV8(dst, tmp_v); \
  }

MAKE_CNT(64, 8)
MAKE_CNT(128, 8)

#undef MAKE_CNT

}  // namespace

DEF_ISEL(CNT_ASIMDMISC_R_8B) = CNT_SIMD_V64;
DEF_ISEL(CNT_ASIMDMISC_R_16B) = CNT_SIMD_V128;
