#include "TestLift.h"

#include "TestMainLifter.h"
#include "front/Util.h"
#include "remill/BC/Util.h"

DEFINE_string(bc_out, "", "Name of the file in which to place the generated bitcode.");

DEFINE_string(os, REMILL_OS,
              "Operating system name of the code being "
              "translated. Valid OSes: linux, macos, windows, solaris.");
DEFINE_string(arch, REMILL_ARCH,
              "Architecture of the code being translated. "
              "Valid architectures: aarch64");

extern std::map<uint64_t, TestInstructionState> g_disasm_funcs;

/* DisassembleCmd class */
/*
  e.g.
  'mov x0, #42' -> 0x400580d2
  rasm2_exe_buf[0] = '4', [1] = '0', ... [8] = '2'
  --> insn_bytes[0] = d2, [1] = 80, [2] = 05, [3] = 40
*/
void DisassembleCmd::ExecRasm2(const std::string &mnemonic, uint8_t insn_bytes[4]) {
  uint8_t rasm2_exe_buf[128];
  memset(rasm2_exe_buf, 0, sizeof(rasm2_exe_buf));
  std::string cmd = "rasm2 -a arm -b 64 '" + mnemonic + "'";
  FILE *pipe = popen(cmd.c_str(), "r");
  if (!pipe)
    elfconv_runtime_error("[TEST_ERROR] rasm2 disassemble pipe is invalid. mnemonic: %s\n",
                          mnemonic.c_str());
  fgets(reinterpret_cast<char *>(rasm2_exe_buf), sizeof(rasm2_exe_buf), pipe);
  char dum_buf[128];
  CHECK(NULL == fgets(dum_buf, sizeof(dum_buf), pipe));
  /* decode rasm2_exe_buf */
  auto char2hex = [&rasm2_exe_buf](int id) -> int {
    if ('0' <= rasm2_exe_buf[id] && rasm2_exe_buf[id] <= '9')
      return rasm2_exe_buf[id] - '0';
    else if ('a' <= rasm2_exe_buf[id] && rasm2_exe_buf[id] <= 'f')
      return rasm2_exe_buf[id] - 'a' + 10;
    else
      elfconv_runtime_error("ExecRasm2 Error: rasm2_exe_buf has invalid num.\n");
    return 0;
  };
  insn_bytes[0] = char2hex(0) * 16 + char2hex(1);
  insn_bytes[1] = char2hex(2) * 16 + char2hex(3);
  insn_bytes[2] = char2hex(4) * 16 + char2hex(5);
  insn_bytes[3] = char2hex(6) * 16 + char2hex(7);
}

int main(int argc, char *argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);

  uintptr_t test_disasm_func_vma = g_test_disasm_func_vma;
  uint64_t test_disasm_func_size = AARCH64_OP_SIZE * g_disasm_funcs.size();

  TestAArch64TraceManager manager("DummyELF");

  /* set insn data to manager.memory */
  for (auto &[_vma, _test_aarch64_insn] : g_disasm_funcs) {
    manager.test_inst_state_map[_vma] = &_test_aarch64_insn;
    uint8_t insn_data[4];
    DisassembleCmd::ExecRasm2(_test_aarch64_insn.mnemonic, insn_data);
    manager.memory[_vma] = insn_data[0];
    manager.memory[_vma + 1] = insn_data[1];
    manager.memory[_vma + 2] = insn_data[2];
    manager.memory[_vma + 3] = insn_data[3];
  }

  /* set test_main_function using g_disasm_funcs */
  manager.disasm_funcs = {
      {test_disasm_func_vma,
       DisasmFunc("aarch64_insn_test_main_func", test_disasm_func_vma, test_disasm_func_size)}};
  manager.entry_func_lifted_name = "aarch64_insn_test_main_func";

  llvm::LLVMContext context;
  auto os_name = remill::GetOSName(REMILL_OS);
  auto arch_name = remill::GetArchName(FLAGS_arch);
  auto arch = remill::Arch::Build(&context, os_name, arch_name);
  auto module = remill::LoadArchSemantics(arch.get());

  remill::IntrinsicTable intrinsics(module.get());
  TestLifter test_lifter(arch.get(), &manager);

  std::unordered_map<uint64_t, const char *> addr_fn_map;

  /* declare helper function for lifted LLVM bitcode */
  test_lifter.DeclareHelperFunction();
  test_lifter.DeclareDebugFunction();
  /* lift every disassembled function */
  for (const auto &[addr, dasm_func] : manager.disasm_funcs) {
    if (!test_lifter.Lift(dasm_func.vma, dasm_func.func_name.c_str())) {
      elfconv_runtime_error("[ERROR] Failed to Lift \"%s\"\n", dasm_func.func_name.c_str());
    }
    addr_fn_map[addr] = dasm_func.func_name.c_str();
    /* set function name */
    auto lifted_fn = manager.GetLiftedTraceDefinition(dasm_func.vma);
    lifted_fn->setName(dasm_func.func_name.c_str());
  }
  /* set lifted entry function */
  test_lifter.SetEntryPoint(manager.entry_func_lifted_name);
  /* set lifted function pointer table (necessary for indirect call) */
  test_lifter.SetLiftedFunPtrTable(addr_fn_map);

  /* generate LLVM bitcode file */
  auto host_arch = remill::Arch::Build(&context, os_name, remill::GetArchName(REMILL_ARCH));
  host_arch->PrepareModule(module.get());
  remill::StoreModuleToFile(module.get(), FLAGS_bc_out);

  printf("[INFO] Lift Done.\n");
  return 0;
}
