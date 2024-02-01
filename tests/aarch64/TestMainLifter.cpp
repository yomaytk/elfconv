#include "TestMainLifter.h"

#include "TestLift.h"
#include "utils/Util.h"

/* TestLifter class */
void TestLifter::DeclareHelperFunction() {
  static_cast<TestWrapImpl *>(impl.get())->DeclareHelperFunction();
}

llvm::BasicBlock *TestLifter::TestWrapImpl::PreVirtualMachineForInsnTest(
    uint64_t inst_addr, TraceManager &trace_manager, llvm::BranchInst *pre_check_branch_inst) {
  llvm::BasicBlock *pre_test_vm_bb;

  auto test_manager = static_cast<TestAArch64TraceManager *>(&trace_manager);
  if (1 == test_manager->test_inst_state_map.count(inst_addr)) {
    auto insn_state = test_manager->test_inst_state_map[inst_addr];
    pre_test_vm_bb = llvm::BasicBlock::Create(context, GetUniquePreVMBBName().c_str(), func);
    llvm::IRBuilder<> ir(pre_test_vm_bb);
    auto state_ptr = NthArgument(func, kStatePointerArgNum);
    /* Set next pc */
    auto [pc_ref, pc_ref_type] =
        arch->DefaultLifter(*intrinsics)->LoadRegAddress(block, state_ptr, kPCVariableName);
    auto [next_pc_ref, next_pc_ref_type] =
        arch->DefaultLifter(*intrinsics)->LoadRegAddress(block, state_ptr, kNextPCVariableName);
    ir.CreateStore(ir.CreateLoad(word_type, next_pc_ref), pc_ref);
    /* show target inst */
    auto show_test_func = module->getFunction(show_test_target_inst_name);
    if (!show_test_func)
      elfconv_runtime_error("[ERROR] %s doesn't exist in LLVM module.\n",
                            show_test_target_inst_name.c_str());
    ir.CreateCall(show_test_func);
    /* set every initial state of virtual machine */
    for (auto &[_reg_name, ini_num] : insn_state->ini_state) {
      auto [reg_ptr, _reg_ty] =
          arch->DefaultLifter(*intrinsics)->LoadRegAddress(pre_test_vm_bb, state_ptr, _reg_name);
      ir.CreateStore(llvm::ConstantInt::get(_reg_ty, ini_num), reg_ptr);
    }
  } else {
    elfconv_runtime_error(
        "[ERROR] %lld is invalid address at Preparation of instruction test state.\n", inst_addr);
  }

  /* change the succesor of pre_check_branch_inst to `L_pre_vmX`*/
  if (nullptr != pre_check_branch_inst) {
    if (pre_check_branch_inst->getSuccessor(0) != block)
      elfconv_runtime_error(
          "pre_check_branch_inst->getSuccessor(0) must be equaul to current block.\n");
    pre_check_branch_inst->setSuccessor(0, pre_test_vm_bb);
  }

  return pre_test_vm_bb;
}

llvm::BranchInst *
TestLifter::TestWrapImpl::CheckVirtualMahcineForInsnTest(uint64_t inst_addr,
                                                         TraceManager &trace_manager) {
  llvm::BasicBlock *check_test_vm_bb;
  llvm::BranchInst *block_branch_inst;
  llvm::BasicBlock *next_insn_block;
  llvm::BranchInst *check_branch_inst;

  for (llvm::Instruction &ir_instr : *block)
    if (block_branch_inst = llvm::dyn_cast<llvm::BranchInst>(&ir_instr);
        nullptr != block_branch_inst) {
      next_insn_block = block_branch_inst->getSuccessor(0);
      /* why? */  // CHECK(nullptr == block_branch_inst->getSuccessor(1));
      break;
    }
  if (nullptr == block_branch_inst || nullptr == next_insn_block)
    elfconv_runtime_error(
        "[TESTERROR] cannot find the llvm::BranchInst* from the already lifted basic block.\n");

  auto test_manager = static_cast<TestAArch64TraceManager *>(&trace_manager);
  if (1 == test_manager->test_inst_state_map.count(inst_addr)) {
    auto insn_state = test_manager->test_inst_state_map[inst_addr];
    check_test_vm_bb = llvm::BasicBlock::Create(context, GetUniqueCheckVMBBName().c_str(), func);
    /* change the branch block to `L_check` */
    block_branch_inst->setSuccessor(0, check_test_vm_bb);
    llvm::IRBuilder<> ir_1(check_test_vm_bb);
    CHECK(inst.IsValid());
    auto state_ptr = NthArgument(func, kStatePointerArgNum);
    /* check every state of virtual machine */
    llvm::Value *cond_val = llvm::ConstantInt::get(llvm::Type::getInt1Ty(context), 1);
    for (auto &[_reg_name, required_num] : insn_state->required_state) {
      auto reg_val = inst.GetLifter()->LoadRegValue(check_test_vm_bb, state_ptr, _reg_name);
      auto is_eq =
          ir_1.CreateICmpEQ(reg_val, llvm::ConstantInt::get(reg_val->getType(), required_num));
      cond_val = ir_1.CreateAnd(cond_val, is_eq); /* cond_val = cond_1 && cond_2 && ... cond_n */
    }
    CHECK(test_failed_block);
    check_branch_inst = ir_1.CreateCondBr(cond_val, next_insn_block, test_failed_block);
  } else {
    elfconv_runtime_error("[ERROR] %lld is invalid address at Check of instruction test state.\n",
                          inst_addr);
  }

  return check_branch_inst;
}

void TestLifter::TestWrapImpl::AddTestFailedBlock() {
  if (test_failed_block)
    return;
  CHECK(!test_failed_block);
  test_failed_block = llvm::BasicBlock::Create(context, test_failed_bb_name.c_str(), func);
  llvm::IRBuilder<> ir(test_failed_block);
  auto failed_fun = module->getFunction(test_failed_result_fn_name.c_str());
  if (!failed_fun)
    elfconv_runtime_error("[ERROR] %s is not defined in LLVM module.\n",
                          test_failed_result_fn_name.c_str());
  ir.CreateCall(failed_fun);
  /* actually unreachable */
  auto mem_ptr_val = inst.GetLifter()->LoadRegValue(
      test_failed_block, NthArgument(func, kStatePointerArgNum), kMemoryVariableName);
  ir.CreateRet(mem_ptr_val);
}

void TestLifter::TestWrapImpl::DeclareHelperFunction() {
  /* void get_failed_lifting_detail() */
  llvm::Function::Create(llvm::FunctionType::get(llvm::Type::getVoidTy(context), {}, false),
                         llvm::Function::ExternalLinkage, test_failed_result_fn_name, *module);
  /* void show_test_target_inst() */
  llvm::Function::Create(llvm::FunctionType::get(llvm::Type::getVoidTy(context), {}, false),
                         llvm::Function::ExternalLinkage, show_test_target_inst_name, *module);
}

std::string TestLifter::TestWrapImpl::GetUniquePreVMBBName() {
  return pre_vm_bb_name + to_string(unique_num_of_bb++);
}

std::string TestLifter::TestWrapImpl::GetUniqueCheckVMBBName() {
  return check_vm_bb_name + to_string(unique_num_of_bb++);
}
