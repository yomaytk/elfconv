#include "TestLift.h"

#include "front/MainLifter.h"
#include "remill/include/remill/BC/Util.h"

DEFINE_string(bc_out, "", "Name of the file in which to place the generated bitcode.");

DEFINE_string(os, REMILL_OS,
              "Operating system name of the code being "
              "translated. Valid OSes: linux, macos, windows, solaris.");
DEFINE_string(arch, REMILL_ARCH,
              "Architecture of the code being translated. "
              "Valid architectures: aarch64");

#include "Instructions.cpp"

/* DisassembleCmd class */
uint8_t *DisassembleCmd::ExecRasm2(const std::string &mnemonic) {
  static uint8_t rasm2_dis_buf[128];
  memset(rasm2_dis_buf, 0, sizeof(rasm2_dis_buf));
  std::string cmd = "rasm2 -a arm -b 64 '" + mnemonic + "'";
  FILE *pipe = popen(cmd.c_str(), "r");
  if (!pipe) {
    printf("[TEST_ERROR] rasm2 disassemble pipe is invalid. mnemonic: %s\n", mnemonic.c_str());
    abort();
  }
  fgets(reinterpret_cast<char *>(rasm2_dis_buf), sizeof(rasm2_dis_buf), pipe);
  char dum_buf[128];
  CHECK(NULL == fgets(dum_buf, sizeof(dum_buf), pipe));
  return rasm2_dis_buf;
}

/* TestLifter class */
llvm::BasicBlock *
TestLifter::TestWrapImpl::PreVirtualMachineForInsnTest(uint64_t inst_addr,
                                                       TraceManager &trace_manager) {
  llvm::BasicBlock *pre_test_vm_bb;

  auto test_manager = static_cast<TestAArch64TraceManager *>(&trace_manager);
  if (1 == test_manager->test_inst_state_map.count(inst_addr)) {
    auto insn_state = test_manager->test_inst_state_map[inst_addr];
    pre_test_vm_bb = llvm::BasicBlock::Create(context, pre_vm_bb_name.c_str(), func);
    llvm::IRBuilder<> ir(pre_test_vm_bb);
    CHECK(inst.IsValid());
    auto state_ptr = NthArgument(func, kStatePointerArgNum);
    /* set every initial state of virtual machine */
    for (auto &[_reg_name, ini_num] : insn_state->ini_state) {
      auto [reg_ptr, _reg_ty] =
          inst.GetLifter()->LoadRegAddress(pre_test_vm_bb, state_ptr, _reg_name);
      ir.CreateStore(llvm::ConstantInt::get(_reg_ty, ini_num), reg_ptr);
    }
  } else {
    printf("[ERROR] %lld is invalid address at Preparation of instruction test state.\n",
           inst_addr);
    abort();
  }

  return pre_test_vm_bb;
}

llvm::BasicBlock *TestLifter::TestWrapImpl::CheckVirtualMahcineForInsnTest(
    uint64_t inst_addr, TraceManager &trace_manager, llvm::BasicBlock *next_insn_block) {
  llvm::BasicBlock *check_test_vm_bb;

  auto test_manager = static_cast<TestAArch64TraceManager *>(&trace_manager);
  if (1 == test_manager->test_inst_state_map.count(inst_addr)) {
    auto insn_state = test_manager->test_inst_state_map[inst_addr];
    check_test_vm_bb = llvm::BasicBlock::Create(context, check_vm_bb_name.c_str(), func);
    llvm::IRBuilder<> ir_1(check_test_vm_bb);
    CHECK(inst.IsValid());
    auto state_ptr = NthArgument(func, kStatePointerArgNum);
    /* check every state of virtual machine */
    llvm::Value *cond_val = llvm::ConstantInt::get(llvm::Type::getInt1Ty(context), 1);
    for (auto &[_reg_name, required_num] : insn_state->required_state) {
      auto reg_val = inst.GetLifter()->LoadRegValue(check_test_vm_bb, state_ptr, _reg_name);
      auto is_eq =
          ir_1.CreateICmpEQ(reg_val, llvm::ConstantInt::get(reg_val->getType(), required_num));
      cond_val = ir_1.CreateAnd(cond_val, is_eq);
    }
    ir_1.CreateCondBr(cond_val, next_insn_block, test_failed_block);
  } else {
    printf("[ERROR] %lld is invalid address at Check of instruction test state.\n", inst_addr);
    abort();
  }
  /* put the next_insn_block back on */
  block = next_insn_block;
  return check_test_vm_bb;
}

void TestLifter::TestWrapImpl::AddTestFailedBlock() {
  CHECK(!test_failed_block);
  test_failed_block = llvm::BasicBlock::Create(context, test_failed_bb_name.c_str(), func);
  llvm::IRBuilder<> ir(test_failed_block);
  auto failed_fun = module->getFunction(test_failed_result_fn_name.c_str());
  if (!failed_fun) {
    printf("[ERROR] %s is not defined in LLVM module.\n", test_failed_result_fn_name.c_str());
    abort();
  }
  ir.CreateCall(failed_fun);
  /* actually unreachable */
  ir.CreateRet(llvm::ConstantInt::get(llvm::Type::getInt64PtrTy(context), 0));
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
    uint8_t *insn_data = DisassembleCmd::ExecRasm2(_test_aarch64_insn.mnemonic);
    manager.memory[_vma] = insn_data[0];
    manager.memory[_vma + 1] = insn_data[1];
    manager.memory[_vma + 2] = insn_data[2];
    manager.memory[_vma + 3] = insn_data[3];
  }

  /* set test_main_function using g_disasm_funcs */
  manager.disasm_funcs = {
      {test_disasm_func_vma,
       DisasmFunc("aarch64_insn_test_main_func", test_disasm_func_vma, test_disasm_func_size)}};

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
  /* lift every disassembled function */
  for (const auto &[addr, dasm_func] : manager.disasm_funcs) {
    if (!test_lifter.Lift(dasm_func.vma, dasm_func.func_name.c_str())) {
      printf("[ERROR] Failed to Lift \"%s\"\n", dasm_func.func_name.c_str());
      exit(EXIT_FAILURE);
    }
    addr_fn_map[addr] = dasm_func.func_name.c_str();
    /* set function name */
    auto lifted_fn = manager.GetLiftedTraceDefinition(dasm_func.vma);
    lifted_fn->setName(dasm_func.func_name.c_str());
  }
  /* set lifted function pointer table (necessary for indirect call) */
  test_lifter.SetLiftedFunPtrTable(addr_fn_map);
  /* set block address data */
  test_lifter.SetBlockAddressData(
      manager.g_block_address_ptrs_array, manager.g_block_address_vmas_array,
      manager.g_block_address_size_array, manager.g_block_address_fn_vma_array);

  /* generate LLVM bitcode file */
  auto host_arch = remill::Arch::Build(&context, os_name, remill::GetArchName(REMILL_ARCH));
  host_arch->PrepareModule(module.get());
  remill::StoreModuleToFile(module.get(), FLAGS_bc_out);

  printf("[INFO] Lift Done.\n");
  return 0;
}