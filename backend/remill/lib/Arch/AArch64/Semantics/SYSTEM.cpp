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

DEF_SEM_VOID_STATE_RUN(CallSupervisor, I32) {
  HYPER_CALL = AsyncHyperCall::kAArch64SupervisorCall;
  __remill_syscall_tranpoline_call(state, runtime_manager);
}

DEF_SEM_VOID_STATE_RUN(Breakpoint, I32 imm) {
  HYPER_CALL_VECTOR = Read(imm);
  __remill_sync_hyper_call(state, runtime_manager, SyncHyperCall::kAArch64Breakpoint);
}

DEF_SEM_U64_STATE(DoMRS_RS_SYSTEM_FPSR) {
  auto fpsr = state.fpsr;
  fpsr.ixc = state.sr.ixc;
  fpsr.ofc = state.sr.ofc;
  fpsr.ufc = state.sr.ufc;

  //fpsr.idc = state.sr.idc;  // TODO(garret): fix the saving of the idc bit before reenabling (issue #188)
  fpsr.ioc = state.sr.ioc;
  return fpsr.flat;
}

DEF_SEM_VOID_STATE(DoMSR_SR_SYSTEM_FPSR, R64 src) {
  FPSR fpsr;
  WriteZExt(fpsr.flat, Read(src));
  fpsr._res0 = 0;
  fpsr._res1 = 0;
  state.fpsr = fpsr;
  state.sr.ioc = fpsr.ioc;
  state.sr.ofc = fpsr.ofc;
  state.sr.ixc = fpsr.ixc;
  state.sr.ufc = fpsr.ufc;

  //state.sr.idc = fpsr.idc;  // TODO(garret): fix the saving of the idc bit before reenabling (issue #188)
}

DEF_SEM_U64_STATE(DoMRS_RS_SYSTEM_FPCR) {
  auto fpcr = state.fpcr;
  return fpcr.flat;
}

DEF_SEM_VOID_STATE_RUN(DoMSR_SR_SYSTEM_FPCR, R64 src) {
  FPCR fpcr;
  WriteZExt(fpcr.flat, Read(src));
  fpcr._res0 = 0;
  fpcr._res1 = 0;
  state.fpcr = fpcr;
}

DEF_SEM_U64_STATE(DoMRS_RS_SYSTEM_TPIDR_EL0) {
  return Read(state.sr.tpidr_el0.qword);
}

DEF_SEM_VOID_STATE(DoMSR_SR_SYSTEM_TPIDR_EL0, R64 src) {
  WriteZExt(state.sr.tpidr_el0.qword, Read(src));
}

DEF_SEM_U64_STATE(DoMRS_RS_SYSTEM_CTR_EL0) {
  return Read(state.sr.ctr_el0.qword);
}

DEF_SEM_VOID_STATE(DoMSR_SR_SYSTEM_CTR_EL0, R64 src) {
  WriteZExt(state.sr.ctr_el0.qword, Read(src));
}

DEF_SEM_U64_STATE(DoMRS_RS_SYSTEM_DCZID_EL0) {
  return Read(state.sr.dczid_el0.qword);
}

DEF_SEM_VOID_STATE(DoMSR_SR_SYSTEM_DCZID_EL0, R64 src) {
  WriteZExt(state.sr.dczid_el0.qword, Read(src));
}

DEF_SEM_U64_STATE(DoMRS_RS_SYSTEM_MIDR_EL1) {
  return Read(state.sr.midr_el1.qword);
}

DEF_SEM_VOID_STATE(DoMSR_SR_SYSTEM_MIDR_EL1, R64 src) {
  WriteZExt(state.sr.midr_el1.qword, Read(src));
}

DEF_SEM_VOID_RUN(DataMemoryBarrier) {

  // TODO(pag): Full-system data memory barrier probably requires a synchronous
  //            hypercall if it behaves kind of like Linux's `sys_membarrier`.
  __remill_barrier_store_store(runtime_manager);
}

}  // namespace

DEF_ISEL(SVC_EX_EXCEPTION) = CallSupervisor;  // SVC  #<imm>
DEF_ISEL(BRK_EX_EXCEPTION) = Breakpoint;  // BRK  #<imm>

DEF_ISEL(MRS_RS_SYSTEM_FPSR) =
    DoMRS_RS_SYSTEM_FPSR;  // MRS  <Xt>, (<systemreg>|S<op0>_<op1>_<Cn>_<Cm>_<op2>)
DEF_ISEL(MSR_SR_SYSTEM_FPSR) =
    DoMSR_SR_SYSTEM_FPSR;  // MSR  (<systemreg>|S<op0>_<op1>_<Cn>_<Cm>_<op2>), <Xt>

DEF_ISEL(MRS_RS_SYSTEM_FPCR) =
    DoMRS_RS_SYSTEM_FPCR;  // MRS  <Xt>, (<systemreg>|S<op0>_<op1>_<Cn>_<Cm>_<op2>)
DEF_ISEL(MSR_SR_SYSTEM_FPCR) =
    DoMSR_SR_SYSTEM_FPCR;  // MSR  (<systemreg>|S<op0>_<op1>_<Cn>_<Cm>_<op2>), <Xt>

DEF_ISEL(MRS_RS_SYSTEM_TPIDR_EL0) =
    DoMRS_RS_SYSTEM_TPIDR_EL0;  // MRS  <Xt>, (<systemreg>|S<op0>_<op1>_<Cn>_<Cm>_<op2>)
DEF_ISEL(MSR_SR_SYSTEM_TPIDR_EL0) =
    DoMSR_SR_SYSTEM_TPIDR_EL0;  // MSR  (<systemreg>|S<op0>_<op1>_<Cn>_<Cm>_<op2>), <Xt>

DEF_ISEL(MRS_RS_SYSTEM_CTR_EL0) =
    DoMRS_RS_SYSTEM_CTR_EL0;  // MRS  <Xt>, (<systemreg>|S<op0>_<op1>_<Cn>_<Cm>_<op2>)
DEF_ISEL(MSR_SR_SYSTEM_CTR_EL0) =
    DoMSR_SR_SYSTEM_CTR_EL0;  // MSR  (<systemreg>|S<op0>_<op1>_<Cn>_<Cm>_<op2>), <Xt>

DEF_ISEL(MRS_RS_SYSTEM_DCZID_EL0) =
    DoMRS_RS_SYSTEM_DCZID_EL0;  // MRS  <Xt>, (<systemreg>|S<op0>_<op1>_<Cn>_<Cm>_<op2>)
DEF_ISEL(MSR_SR_SYSTEM_DCZID_EL0) =
    DoMSR_SR_SYSTEM_DCZID_EL0;  // MSR  (<systemreg>|S<op0>_<op1>_<Cn>_<Cm>_<op2>), <Xt>

DEF_ISEL(MRS_RS_SYSTEM_MIDR_EL1) =
    DoMRS_RS_SYSTEM_MIDR_EL1;  // MRS  <Xt>, (<systemreg>|S<op0>_<op1>_<Cn>_<Cm>_<op2>)
DEF_ISEL(MSR_SR_SYSTEM_MIDR_EL1) =
    DoMSR_SR_SYSTEM_MIDR_EL1;  // MSR  (<systemreg>|S<op0>_<op1>_<Cn>_<Cm>_<op2>), <Xt>

DEF_ISEL(DMB_BO_SYSTEM) = DataMemoryBarrier;  // DMB  <option>|#<imm>
