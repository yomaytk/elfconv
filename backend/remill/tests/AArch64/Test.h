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

struct State;

namespace test {

typedef unsigned long addr_t;
typedef unsigned long size_t;
typedef unsigned long uintptr_t;
typedef unsigned long uint64_t;

enum : unsigned long { kPageSize = 4096, kMaxInstrLen = 4 };

struct alignas(128) TestInfo {
  const uintptr_t test_begin;
  const uintptr_t test_end;
  const char *test_name;
  const uint64_t *const args_begin;
  const uint64_t *const args_end;
  const uint64_t num_args;
  const char *isel_name;
} __attribute__((packed));

extern "C" {
extern const TestInfo __aarch64_test_table_begin[];
extern const TestInfo __aarch64_test_table_end[];
}  // extern C

}  // namespace test
