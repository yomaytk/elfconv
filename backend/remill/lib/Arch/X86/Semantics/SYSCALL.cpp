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

extern "C" void emulate_system_call(State &state, RuntimeManager *runtime_manager) {
  __remill_syscall_tranpoline_call(state, runtime_manager);
}

// DEF_SEM(DoSYSENTER, IF_32BIT_ELSE(R32W, R64W)) {
//   memory = __remill_sync_hyper_call(state, memory, SyncHyperCall::kX86SysEnter);
//   HYPER_CALL = AsyncHyperCall::kX86SysEnter;
//   return memory;
// }

// DEF_SEM(DoSYSEXIT, IF_32BIT_ELSE(R32W, R64W)) {
//   memory = __remill_sync_hyper_call(state, memory, SyncHyperCall::kX86SysExit);
//   HYPER_CALL = AsyncHyperCall::kX86SysExit;
//   return memory;
// }
}  // namespace

DEF_ISEL(SYSCALL) = emulate_system_call;

DEF_ISEL(SYSCALL_AMD) = emulate_system_call;

// DEF_ISEL(SYSENTER) = DoSYSENTER;

// DEF_ISEL(SYSEXIT) = DoSYSEXIT;
