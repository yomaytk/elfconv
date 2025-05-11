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

#pragma once

#include "remill/Arch/Runtime/Types.h"
typedef Rn<uint8_t> R8;
typedef Rn<uint16_t> R16;
typedef Rn<uint32_t> R32;
typedef Rn<uint64_t> R64;
typedef Rn<uint128_t> R128;

typedef Rn<float32_t> RF32;
typedef Rn<float64_t> RF64;

typedef Vn<vec8_t> V8;
typedef Vn<vec16_t> V16;
typedef Vn<vec32_t> V32;
typedef Vn<vec64_t> V64;
typedef VnW<vec64_t> V64W;
typedef Vn<vec128_t> V128;
typedef VnW<vec128_t> V128W;

// 64bit vector
// unsigned
typedef VI<_ecv_u8v8_t> VIu8v8;
typedef VI<_ecv_u16v4_t> VIu16v4;
typedef VI<_ecv_u32v2_t> VIu32v2;
typedef VI<_ecv_u64v1_t> VIu64v1;
// signed
typedef VI<_ecv_i8v8_t> VIi8v8;
typedef VI<_ecv_i16v4_t> VIi16v4;
typedef VI<_ecv_i32v2_t> VIi32v2;
typedef VI<_ecv_i64v1_t> VIi64v1;
// float
typedef VI<_ecv_f32v2_t> VIf32v2;
typedef VI<_ecv_f64v1_t> VIf64v1;

// 128bit vector
// unsigned
typedef VI<_ecv_u8v16_t> VIu8v16;
typedef VI<_ecv_u16v8_t> VIu16v8;
typedef VI<_ecv_u32v4_t> VIu32v4;
typedef VI<_ecv_u64v2_t> VIu64v2;
typedef VI<_ecv_u128v1_t> VIu128v1;
// signed
typedef VI<_ecv_i8v16_t> VIi8v16;
typedef VI<_ecv_i16v8_t> VIi16v8;
typedef VI<_ecv_i32v4_t> VIi32v4;
typedef VI<_ecv_i64v2_t> VIi64v2;
typedef VI<_ecv_i128v1_t> VIi128v1;
// float
typedef VI<_ecv_f32v4_t> VIf32v4;
typedef VI<_ecv_f64v2_t> VIf64v2;

// 256bit vector
// unsigned
typedef VI<_ecv_u8v32_t> VIu8v32;
// signed
typedef VI<_ecv_i8v32_t> VIi8v32;

typedef MVI<_ecv_u8v1_t> MVI8;
typedef MVI<_ecv_u16v1_t> MVI16;
typedef MVI<_ecv_u32v1_t> MVI32;
typedef MVI<_ecv_u64v1_t> MVI64;
typedef MVI<_ecv_u128v1_t> MVI128;
typedef MVI<_ecv_u128v2_t> MVI256;

typedef MnW<uint8_t> M8W;
typedef MnW<uint16_t> M16W;
typedef MnW<uint32_t> M32W;
typedef MnW<uint64_t> M64W;

typedef MVnW<vec8_t> MV8W;
typedef MVnW<vec16_t> MV16W;
typedef MVnW<vec32_t> MV32W;
typedef MVnW<vec64_t> MV64W;
typedef MVnW<vec128_t> MV128W;
typedef MVnW<vec256_t> MV256W;

typedef Mn<uint8_t> M8;
typedef Mn<uint16_t> M16;
typedef Mn<uint32_t> M32;
typedef Mn<uint64_t> M64;
typedef Mn<uint128_t> M128;

typedef Mn<float32_t> MF32;
typedef Mn<float64_t> MF64;

typedef MVn<vec8_t> MV8;
typedef MVn<vec16_t> MV16;
typedef MVn<vec32_t> MV32;
typedef MVn<vec64_t> MV64;
typedef MVn<vec128_t> MV128;
typedef MVn<vec256_t> MV256;

typedef In<uint8_t> I8;
typedef In<uint16_t> I16;
typedef In<uint32_t> I32;
typedef In<uint64_t> I64;

typedef In<float32_t> F32;
typedef In<float64_t> F64;

typedef In<addr_t> PC;
typedef In<addr_t> ADDR;
