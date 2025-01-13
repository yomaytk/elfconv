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

#include "remill/Arch/AArch64/Runtime/Types.h"
#include "remill/Arch/Runtime/Definitions.h"

template <typename T>
struct TPair {
  T r1;
  T r2;
} __attribute__((packed));

typedef struct {
  uint64_t r1;
  uint64_t r2;
} U64U64 __attribute__((packed));

typedef struct {
  uint32_t r1;
  uint64_t r2;
} U32U64 __attribute__((packed));

typedef struct {
  uint32_t r1;
  uint32_t r2;
} U32U32 __attribute__((packed));

typedef struct {
  float64_t r1;
  uint64_t r2;
} F64U64 __attribute__((packed));

typedef struct {
  float32_t r1;
  float32_t r2;
} F32F32 __attribute__((packed));

typedef struct {
  float64_t r1;
  float64_t r2;
} F64F64 __attribute__((packed));

#if defined(__x86_64__)
typedef _ecv_u128v2_t V128V128;
#else
typedef struct {
  _ecv_u128v1_t r1;
  _ecv_u128v1_t r2;
} V128V128 __attribute__((packed));
#endif

// Define a semantics implementing function for aarch64 target.
/*
  void
*/
#define DEF_SEM_VOID(name, ...) ALWAYS_INLINE __attribute__((flatten)) static void name(__VA_ARGS__)

#define DEF_SEM_VOID_STATE(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static void name(State &state, ##__VA_ARGS__)

#define DEF_SEM_VOID_RUN(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static void name(RuntimeManager *runtime_manager, \
                                                          ##__VA_ARGS__)

#define DEF_SEM_VOID_STATE_RUN(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static void name( \
      State &state, RuntimeManager *runtime_manager, ##__VA_ARGS__)
// ALIAS
#define DEF_SEM_VOID_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static void name(__VA_ARGS__) asm(#symbol); \
  void name(__VA_ARGS__)

#define DEF_SEM_VOID_STATE_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static void name(State &state, \
                                                          ##__VA_ARGS__) asm(#symbol); \
  void name(State &state, ##__VA_ARGS__)

#define DEF_SEM_VOID_RUN_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static void name(RuntimeManager *runtime_manager, \
                                                          ##__VA_ARGS__) asm(#symbol); \
  void name(RuntimeManager *runtime_manager, ##__VA_ARGS__)

#define DEF_SEM_VOID_STATE_RUN_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static void name( \
      State &state, RuntimeManager *runtime_manager, ##__VA_ARGS__) asm(#symbol); \
  void name(State &state, RuntimeManager *runtime_manager, ##__VA_ARGS__)

/*
  auto
*/
#define DEF_SEM_T(name, ...) ALWAYS_INLINE __attribute__((flatten)) static auto name(__VA_ARGS__)

#define DEF_SEM_T_STATE(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static auto name(State &state, ##__VA_ARGS__)

#define DEF_SEM_T_RUN(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static auto name(RuntimeManager *runtime_manager, \
                                                          ##__VA_ARGS__)

#define DEF_SEM_T_STATE_RUN(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static auto name( \
      State &state, RuntimeManager *runtime_manager, ##__VA_ARGS__)
// ALIAS
#define DEF_SEM_T_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static auto name(__VA_ARGS__) asm(#symbol); \
  auto name(__VA_ARGS__)

#define DEF_SEM_T_STATE_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static auto name(State &state, \
                                                          ##__VA_ARGS__) asm(#symbol); \
  auto name(State &state, ##__VA_ARGS__)

#define DEF_SEM_T_RUN_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static auto name(RuntimeManager *runtime_manager, \
                                                          ##__VA_ARGS__) asm(#symbol); \
  auto name(RuntimeManager *runtime_manager, ##__VA_ARGS__)

#define DEF_SEM_T_STATE_RUN_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static auto name( \
      State &state, RuntimeManager *runtime_manager, ##__VA_ARGS__) asm(#symbol); \
  auto name(State &state, RuntimeManager *runtime_manager, ##__VA_ARGS__)

/*
  uint8_t
*/
#define DEF_SEM_U8(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static uint8_t name(__VA_ARGS__)

#define DEF_SEM_U8_STATE(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static uint8_t name(State &state, ##__VA_ARGS__)

#define DEF_SEM_U8_RUN(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static uint8_t name(RuntimeManager *runtime_manager, \
                                                             ##__VA_ARGS__)

#define DEF_SEM_U8_STATE_RUN(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static uint8_t name( \
      State &state, RuntimeManager *runtime_manager, ##__VA_ARGS__)
// ALIAS
#define DEF_SEM_U8_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static uint8_t name(__VA_ARGS__) asm(#symbol); \
  uint8_t name(__VA_ARGS__)

#define DEF_SEM_U8_STATE_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static uint8_t name(State &state, \
                                                             ##__VA_ARGS__) asm(#symbol); \
  uint8_t name(State &state, ##__VA_ARGS__)

#define DEF_SEM_U8_RUN_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static uint8_t name(RuntimeManager *runtime_manager, \
                                                             ##__VA_ARGS__) asm(#symbol); \
  uint8_t name(RuntimeManager *runtime_manager, ##__VA_ARGS__)

#define DEF_SEM_U8_STATE_RUN_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static uint8_t name( \
      State &state, RuntimeManager *runtime_manager, ##__VA_ARGS__) asm(#symbol); \
  uint8_t name(State &state, RuntimeManager *runtime_manager, ##__VA_ARGS__)


/*
  uint16_t
*/
#define DEF_SEM_U16(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static uint16_t name(__VA_ARGS__)

#define DEF_SEM_U16_STATE(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static uint16_t name(State &state, ##__VA_ARGS__)

#define DEF_SEM_U16_RUN(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static uint16_t name(RuntimeManager *runtime_manager, \
                                                              ##__VA_ARGS__)

#define DEF_SEM_U16_STATE_RUN(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static uint16_t name( \
      State &state, RuntimeManager *runtime_manager, ##__VA_ARGS__)
// ALIAS
#define DEF_SEM_U16_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static uint16_t name(__VA_ARGS__) asm(#symbol); \
  uint16_t name(__VA_ARGS__)

#define DEF_SEM_U16_STATE_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static uint16_t name(State &state, \
                                                              ##__VA_ARGS__) asm(#symbol); \
  uint16_t name(State &state, ##__VA_ARGS__)

#define DEF_SEM_U16_RUN_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static uint16_t name(RuntimeManager *runtime_manager, \
                                                              ##__VA_ARGS__) asm(#symbol); \
  uint16_t name(RuntimeManager *runtime_manager, ##__VA_ARGS__)

#define DEF_SEM_U16_STATE_RUN_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static uint16_t name( \
      State &state, RuntimeManager *runtime_manager, ##__VA_ARGS__) asm(#symbol); \
  uint16_t name(State &state, RuntimeManager *runtime_manager, ##__VA_ARGS__)

/*
  uint32_t
*/
#define DEF_SEM_U32(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static uint32_t name(__VA_ARGS__)

#define DEF_SEM_U32_STATE(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static uint32_t name(State &state, ##__VA_ARGS__)

#define DEF_SEM_U32_RUN(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static uint32_t name(RuntimeManager *runtime_manager, \
                                                              ##__VA_ARGS__)

#define DEF_SEM_U32_STATE_RUN(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static uint32_t name( \
      State &state, RuntimeManager *runtime_manager, ##__VA_ARGS__)
// ALIAS
#define DEF_SEM_U32_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static uint32_t name(__VA_ARGS__) asm(#symbol); \
  uint32_t name(__VA_ARGS__)

#define DEF_SEM_U32_STATE_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static uint32_t name(State &state, \
                                                              ##__VA_ARGS__) asm(#symbol); \
  uint32_t name(State &state, ##__VA_ARGS__)

#define DEF_SEM_U32_RUN_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static uint32_t name(RuntimeManager *runtime_manager, \
                                                              ##__VA_ARGS__) asm(#symbol); \
  uint32_t name(RuntimeManager *runtime_manager, ##__VA_ARGS__)

#define DEF_SEM_U32_STATE_RUN_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static uint32_t name( \
      State &state, RuntimeManager *runtime_manager, ##__VA_ARGS__) asm(#symbol); \
  uint32_t name(State &state, RuntimeManager *runtime_manager, ##__VA_ARGS__)

/*
  uint64_t
*/
#define DEF_SEM_U64(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static uint64_t name(__VA_ARGS__)

#define DEF_SEM_U64_STATE(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static uint64_t name(State &state, ##__VA_ARGS__)

#define DEF_SEM_U64_RUN(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static uint64_t name(RuntimeManager *runtime_manager, \
                                                              ##__VA_ARGS__)

#define DEF_SEM_U64_STATE_RUN(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static uint64_t name( \
      State &state, RuntimeManager *runtime_manager, ##__VA_ARGS__)
// ALIAS
#define DEF_SEM_U64_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static uint64_t name(__VA_ARGS__) asm(#symbol); \
  uint64_t name(__VA_ARGS__)

#define DEF_SEM_U64_STATE_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static uint64_t name(State &state, \
                                                              ##__VA_ARGS__) asm(#symbol); \
  uint64_t name(State &state, ##__VA_ARGS__)

#define DEF_SEM_U64_RUN_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static uint64_t name(RuntimeManager *runtime_manager, \
                                                              ##__VA_ARGS__) asm(#symbol); \
  uint64_t name(RuntimeManager *runtime_manager, ##__VA_ARGS__)

#define DEF_SEM_U64_STATE_RUN_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static uint64_t name( \
      State &state, RuntimeManager *runtime_manager, ##__VA_ARGS__) asm(#symbol); \
  uint64_t name(State &state, RuntimeManager *runtime_manager, ##__VA_ARGS__)

/*
  float32_t
*/
#define DEF_SEM_F32(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static float32_t name(__VA_ARGS__)

#define DEF_SEM_F32_STATE(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static float32_t name(State &state, ##__VA_ARGS__)

#define DEF_SEM_F32_RUN(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static float32_t name(RuntimeManager *runtime_manager, \
                                                               ##__VA_ARGS__)

#define DEF_SEM_F32_STATE_RUN(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static float32_t name( \
      State &state, RuntimeManager *runtime_manager, ##__VA_ARGS__)
// ALIAS
#define DEF_SEM_F32_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static float32_t name(__VA_ARGS__) asm(#symbol); \
  float32_t name(__VA_ARGS__)

#define DEF_SEM_F32_STATE_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static float32_t name(State &state, \
                                                               ##__VA_ARGS__) asm(#symbol); \
  float32_t name(State &state, ##__VA_ARGS__)

#define DEF_SEM_F32_RUN_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static float32_t name(RuntimeManager *runtime_manager, \
                                                               ##__VA_ARGS__) asm(#symbol); \
  float32_t name(RuntimeManager *runtime_manager, ##__VA_ARGS__)

#define DEF_SEM_F32_STATE_RUN_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static float32_t name( \
      State &state, RuntimeManager *runtime_manager, ##__VA_ARGS__) asm(#symbol); \
  float32_t name(State &state, RuntimeManager *runtime_manager, ##__VA_ARGS__)

/*
  float64_t
*/
#define DEF_SEM_F64(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static float64_t name(__VA_ARGS__)

#define DEF_SEM_F64_STATE(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static float64_t name(State &state, ##__VA_ARGS__)

#define DEF_SEM_F64_RUN(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static float64_t name(RuntimeManager *runtime_manager, \
                                                               ##__VA_ARGS__)

#define DEF_SEM_F64_STATE_RUN(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static float64_t name( \
      State &state, RuntimeManager *runtime_manager, ##__VA_ARGS__)
// ALIAS
#define DEF_SEM_F64_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static float64_t name(__VA_ARGS__) asm(#symbol); \
  float64_t name(__VA_ARGS__)

#define DEF_SEM_F64_STATE_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static float64_t name(State &state, \
                                                               ##__VA_ARGS__) asm(#symbol); \
  float64_t name(State &state, ##__VA_ARGS__)

#define DEF_SEM_F64_RUN_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static float64_t name(RuntimeManager *runtime_manager, \
                                                               ##__VA_ARGS__) asm(#symbol); \
  float64_t name(RuntimeManager *runtime_manager, ##__VA_ARGS__)

#define DEF_SEM_F64_STATE_RUN_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static float64_t name( \
      State &state, RuntimeManager *runtime_manager, ##__VA_ARGS__) asm(#symbol); \
  float64_t name(State &state, RuntimeManager *runtime_manager, ##__VA_ARGS__)

/*
  { uint64_t, uint64_t }
*/
#define DEF_SEM_U64U64(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static U64U64 name(__VA_ARGS__)

#define DEF_SEM_U64U64_STATE(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static U64U64 name(State &state, ##__VA_ARGS__)

#define DEF_SEM_U64U64_RUN(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static U64U64 name(RuntimeManager *runtime_manager, \
                                                            ##__VA_ARGS__)
// ALIAS
#define DEF_SEM_U64U64_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static U64U64 name(__VA_ARGS__) asm(#symbol); \
  U64U64 name(__VA_ARGS__)

#define DEF_SEM_U64U64_STATE_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static U64U64 name(State &state, \
                                                            ##__VA_ARGS__) asm(#symbol); \
  U64U64 name(State &state, ##__VA_ARGS__)

#define DEF_SEM_U64U64_RUN_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static U64U64 name(RuntimeManager *runtime_manager, \
                                                            ##__VA_ARGS__) asm(#symbol); \
  U64U64 name(RuntimeManager *runtime_manager, ##__VA_ARGS__)

/*
  { uint32_t, uint64_t }
*/
#define DEF_SEM_U32U64(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static U32U64 name(__VA_ARGS__)

#define DEF_SEM_U32U64_STATE(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static U32U64 name(State &state, ##__VA_ARGS__)

#define DEF_SEM_U32U64_RUN(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static U32U64 name(RuntimeManager *runtime_manager, \
                                                            ##__VA_ARGS__)
// ALIAS
#define DEF_SEM_U32U64_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static U32U64 name(__VA_ARGS__) asm(#symbol); \
  U32U64 name(__VA_ARGS__)

#define DEF_SEM_U32U64_STATE_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static U32U64 name(State &state, ##__VA_ARGS__)

#define DEF_SEM_U32U64_RUN_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static U32U64 name(RuntimeManager *runtime_manager, \
                                                            ##__VA_ARGS__)

/*
  { float64_t, float64_t }
*/
#define DEF_SEM_F64F64(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static F64F64 name(__VA_ARGS__)

#define DEF_SEM_F64F64_STATE(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static F64F64 name(State &state, ##__VA_ARGS__)

#define DEF_SEM_F64F64_RUN(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static F64F64 name(RuntimeManager *runtime_manager, \
                                                            ##__VA_ARGS__)
// ALIAS
#define DEF_SEM_F64F64_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static F64F64 name(__VA_ARGS__) asm(#symbol); \
  F64F64 name(__VA_ARGS__)

#define DEF_SEM_F64F64_STATE_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static F64F64 name(State &state, \
                                                            ##__VA_ARGS__) asm(#symbol); \
  F64F64 name(State &state, __VA_ARGS__)

#define DEF_SEM_F64F64_RUN_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static F64F64 name(RuntimeManager *runtime_manager, \
                                                            ##__VA_ARGS__) asm(#symbol); \
  F64F64 name(RuntimeManager *runtime_manager, ##__VA_ARGS__)

/*
  { float32_t, float32_t }
*/
#define DEF_SEM_F32F32(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static F32F32 name(__VA_ARGS__)

#define DEF_SEM_F32F32_STATE(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static F32F32 name(State &state, ##__VA_ARGS__)

#define DEF_SEM_F32F32_RUN(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static F32F32 name(RuntimeManager *runtime_manager, \
                                                            ##__VA_ARGS__)
// ALIAS
#define DEF_SEM_F32F32_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static F32F32 name(__VA_ARGS__) asm(#symbol); \
  F32F32 name(__VA_ARGS__)

#define DEF_SEM_F32F32_STATE_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static F32F32 name(State &state, \
                                                            ##__VA_ARGS__) asm(#symbol); \
  F32F32 name(State &state, ##__VA_ARGS__)

#define DEF_SEM_F32F32_RUN_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static F32F32 name(RuntimeManager *runtime_manager, \
                                                            ##__VA_ARGS__) asm(#symbol); \
  F32F32 name(RuntimeManager *runtime_manager, ##__VA_ARGS__)

/*
  __uint128_t
*/
#define DEF_SEM_U128(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static __uint128_t name(__VA_ARGS__)

#define DEF_SEM_U128_STATE(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static __uint128_t name(State &state, ##__VA_ARGS__)

#define DEF_SEM_U128_RUN(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static __uint128_t name(RuntimeManager *runtime_manager, \
                                                                 ##__VA_ARGS__)
// ALIAS
#define DEF_SEM_U128_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static __uint128_t name(__VA_ARGS__) asm(#symbol); \
  __uint128_t name(__VA_ARGS__)

#define DEF_SEM_U128_STATE_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static __uint128_t name(State &state, \
                                                                 ##__VA_ARGS__) asm(#symbol); \
  __uint128_t name(State &state, ##__VA_ARGS__)

#define DEF_SEM_U128_RUN_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static __uint128_t name(RuntimeManager *runtime_manager, \
                                                                 ##__VA_ARGS__) asm(#symbol); \
  __uint128_t name(RuntimeManager *runtime_manager, ##__VA_ARGS__)

/*
  _ecv_u128v1_t
*/
#define DEF_SEM_U128V1(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static _ecv_u128v1_t name(__VA_ARGS__)

#define DEF_SEM_U128V1_STATE(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static _ecv_u128v1_t name(State &state, ##__VA_ARGS__)

#define DEF_SEM_U128V1_RUN(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static _ecv_u128v1_t name( \
      RuntimeManager *runtime_manager, ##__VA_ARGS__)
// ALIAS
#define DEF_SEM_U128V1_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static _ecv_u128v1_t name(__VA_ARGS__) asm(#symbol); \
  _ecv_u128v1_t name(__VA_ARGS__)

#define DEF_SEM_U128V1_STATE_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static _ecv_u128v1_t name(State &state, \
                                                                   ##__VA_ARGS__) asm(#symbol); \
  _ecv_u128v1_t name(State &state, ##__VA_ARGS__)

#define DEF_SEM_U128V1_RUN_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static _ecv_u128v1_t name( \
      RuntimeManager *runtime_manager, ##__VA_ARGS__) asm(#symbol); \
  _ecv_u128v1_t name(RuntimeManager *runtime_manager, ##__VA_ARGS__)

/*
  { _ecv_u128v1_t, _ecv_u128v1_t }
*/
#define DEF_SEM_U128V2(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static V128V128 name(__VA_ARGS__)

#define DEF_SEM_U128V2_STATE(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static V128V128 name(State &state, ##__VA_ARGS__)

#define DEF_SEM_U128V2_RUN(name, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static V128V128 name(RuntimeManager *runtime_manager, \
                                                              ##__VA_ARGS__)
// ALIAS
#define DEF_SEM_U128V2_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static V128V128 name(__VA_ARGS__) asm(#symbol); \
  V128V128 name(__VA_ARGS__)

#define DEF_SEM_U128V2_STATE_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static V128V128 name(State &state, \
                                                              ##__VA_ARGS__) asm(#symbol); \
  V128V128 name(State &state, ##__VA_ARGS__)

#define DEF_SEM_U128V2_RUN_ALIAS(name, symbol, ...) \
  ALWAYS_INLINE __attribute__((flatten)) static V128V128 name(RuntimeManager *runtime_manager, \
                                                              ##__VA_ARGS__) asm(#symbol); \
  V128V128 name(RuntimeManager *runtime_manager, ##__VA_ARGS__)