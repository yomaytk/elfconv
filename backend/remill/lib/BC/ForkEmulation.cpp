/*
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

#include "remill/Arch/Arch.h"
#include "remill/BC/ABI.h"
#include "remill/BC/InstructionLifter.h"

#include <glog/logging.h>
#include <iostream>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constant.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Type.h>
#include <map>
#include <remill/Arch/Instruction.h>
#include <remill/Arch/Name.h>
#include <remill/BC/HelperMacro.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/TraceLifter.h>
#include <remill/BC/Util.h>
#include <set>
#include <sstream>

namespace remill {

void TraceLifter::Impl::JoinBasicBlocksForFork() {

  llvm::BasicBlock *t_bb, *entry_bb;
  std::set<llvm::BasicBlock *> visited;
  std::queue<llvm::BasicBlock *> bb_queue;

  entry_bb = &func->getEntryBlock();
  auto entry_terminator_br = llvm::dyn_cast<llvm::BranchInst>(entry_bb->getTerminator());
  t_bb = entry_terminator_br->getSuccessor(0);
  bb_queue.push(t_bb);

  auto push_successor_bb_queue = [&bb_queue, &visited](llvm::BasicBlock *successor_bb) {
    if (!visited.contains(successor_bb)) {
      bb_queue.push(successor_bb);
    }
  };

  auto &bb_parents = virtual_regs_opt->bb_parents;
  auto &bb_reg_info_node_map = virtual_regs_opt->bb_reg_info_node_map;

  // remill individually convert each machine instruction into a basic block of LLVM IR.
  // However, VRP yields the some phi instructions for the every basic block, so having many basic blocks may incur performance overheads.
  // According that, VRP combine the basic block to the basic block if the former has only child basic block and the latter has only parent basic block.
  // Therefore VRP decrease the total number of basic blocks.
  while (!bb_queue.empty()) {

    t_bb = bb_queue.front();
    bb_queue.pop();
    visited.insert(t_bb);

    llvm::Instruction *t_endbr = t_bb->getTerminator();

    // if `t_endbr` is not branched to the specified basic block, t_bb must not be the joining bb.
    // This is necessary because JoinBasicBlocksForFork will be called before calling AddTerminatingCall against all basic blocks.
    if (!t_endbr) {
      continue;
    }

    uint64_t child_num = t_endbr->getNumSuccessors();

    if (2 < child_num) {
      LOG(FATAL)
          << "Every block of the lifted function by elfconv must not have the child blocks more than two."
          << ECV_DEBUG_STREAM.str();
    } else if (2 == child_num) {
      push_successor_bb_queue(t_endbr->getSuccessor(0));
      push_successor_bb_queue(t_endbr->getSuccessor(1));
    } else if (1 == child_num) {

      llvm::BasicBlock *candidate_bb, *joined_bb;

      candidate_bb = t_endbr->getSuccessor(0);
      auto &candidate_bb_parents = bb_parents.at(candidate_bb);
      if (1 == candidate_bb_parents.size()) {

        // The next instruction of `lifted function` or `system call` calling may be jumped by context switching, so cannot join those.
        if (lift_or_system_calling_bbs.contains(candidate_bb)) {
          if (t_endbr->getNumSuccessors() > 0) {
            push_successor_bb_queue(t_endbr->getSuccessor(0));
          }
          continue;
        }

        // join candidate_bb to the t_bb
        joined_bb = candidate_bb;
        CHECK(llvm::dyn_cast<llvm::BranchInst>(t_endbr))
            << "The parent basic block of the lifted function must terminate by the branch instruction.";
        // delete the branch instruction of the t_bb and joined_bb
        t_endbr->eraseFromParent();
        // transfer the all instructions (t_bb = t_bb & joined_bb)
        t_bb->splice(t_bb->end(), joined_bb);
        // join BBRegInfoNode
        auto joined_bb_reg_info_node =
            virtual_regs_opt->bb_reg_info_node_map.extract(joined_bb).mapped();
        bb_reg_info_node_map.at(t_bb)->join_reg_info_node(joined_bb_reg_info_node);

        // update bb_parents
        bb_parents.erase(joined_bb);
        t_endbr = t_bb->getTerminator();
        if (llvm::dyn_cast<llvm::BranchInst>(t_endbr)) {
          // joined_bb has children
          for (uint32_t i = 0; i < t_endbr->getNumSuccessors(); i++) {
            bb_parents.at(t_endbr->getSuccessor(i)).erase(joined_bb);
            bb_parents.at(t_endbr->getSuccessor(i)).insert(t_bb);
          }
          // should push t_bb again for searching the children of original joined_bb.
          bb_queue.push(t_bb);
        } else {
          // When JoinBasicBlocksForFork is called, switch instruction should not exist.
          CHECK(llvm::dyn_cast<llvm::ReturnInst>(t_endbr));
        }

        // update inst_nums_in_bb
        CHECK(inst_nums_in_bb[t_bb] > 0 && inst_nums_in_bb[joined_bb] > 0);
        inst_nums_in_bb[t_bb] += inst_nums_in_bb[joined_bb];
        inst_nums_in_bb.erase(joined_bb);

        // delete the joined block
        joined_bb->eraseFromParent();
      } else {
        push_successor_bb_queue(candidate_bb);
      }
    } else if (0 == child_num) {
      CHECK(llvm::dyn_cast<llvm::ReturnInst>(t_endbr))
          << "The basic block which doesn't have the successors must be ReturnInst.";
    }
  }
}

// requires: `_near_jump_bb (BB*)`, `br_bb (BB*)`
void TraceLifter::Impl::AddBrBBIR() {
  //  Define IR for `br_bb`.
  llvm::IRBuilder<> br_bb_ir(br_bb);
  //  function to calculate the target basic block address
  auto br_vma_phi = br_bb_ir.CreatePHI(llvm::Type::getInt64Ty(context), br_blocks.size());
  for (auto &br_pair : br_blocks) {
    auto br_block = br_pair.first;
    auto dest_addr = br_pair.second;
    br_vma_phi->addIncoming(dest_addr, br_block);
    virtual_regs_opt->bb_parents[br_block].insert(br_bb);
  }
  br_bb_ir.CreateBr(_near_jump_bb);
}

// requires `br_bb (BB*)`
void TraceLifter::Impl::AddFarJumpBB() {

  // `L_far_jump`: BB to call `remill_jump`.
  far_jump_bb = llvm::BasicBlock::Create(context, "L_far_jump", func);
  llvm::IRBuilder<> far_jump_ir(far_jump_bb);

  auto t_pc = far_jump_ir.CreatePHI(llvm::Type::getInt64Ty(context), 1);
  AddTerminatingTailCall(far_jump_bb, intrinsics->jump, *intrinsics, -1, t_pc);
  // Update cache for `L_far_jump` block.
  virtual_regs_opt->bb_parents.insert({far_jump_bb, {br_bb}});
  virtual_regs_opt->bb_reg_info_node_map.insert(
      {far_jump_bb, new BBRegInfoNode(func, state_ptr, runtime_ptr)});
}

/// fork emulation helper function
void TraceLifter::Impl::GenForkNearJump(uint64_t trace_addr) {

  auto u64ty = llvm::Type::getInt64Ty(context);

  auto root_bb = &(func->front());
  auto root_trmi = root_bb->getTerminator();
  auto org_first_bb = root_trmi->getSuccessor(0);

  _near_jump_bb = llvm::BasicBlock::Create(context, "L_near_jump", func);
  root_trmi->setSuccessor(0, _near_jump_bb);
  llvm::IRBuilder<> _near_jump_ir(_near_jump_bb);

  if (br_bb) {
    // generate the indirect jump IR code to `br_bb`.
    GenIndirectJumpCode(trace_addr);
    // delegates the indirect jump process to the `br_bb`.
    _near_jump_ir.CreateBr(br_bb);
    if (auto br_bb_phi = llvm::dyn_cast<llvm::PHINode>(&br_bb->front()); br_bb_phi) {
      br_bb_phi->addIncoming(NthArgument(func, kPCArgNum), _near_jump_bb);
    } else {
      LOG(FATAL) << "br_bb is not defined correctly.";
    }
  }
  // Add switch jump IR code to `_near_jump_bb`.
  else {

    auto t_pc = NthArgument(func, kPCArgNum);

    // IR to get actual basic block address using `t_vma_phi`.
    // i.e. t_bb_ptr = call _ecv_get_indirectbr_block_address (t_vma_phi);
    //      indirectbr ptr <t_bb_ptr>, [ %L1, %L2, ..., %Ln ]
    auto unreached_bb = llvm::BasicBlock::Create(context, "L_unreached_1", func);
    llvm::IRBuilder<> unreached_ir(unreached_bb);
    unreached_ir.CreateCall(module->getFunction("_ecv_unreached"), {t_pc});
    unreached_ir.CreateRetVoid();
    auto near_switch_jump = _near_jump_ir.CreateSwitch(t_pc, unreached_bb);

    // Add all next bbs of function or system calling.
    for (auto t_bb : lift_or_system_calling_bbs) {
      near_switch_jump->addCase(llvm::ConstantInt::get(u64ty, rev_lifted_block_map.at(t_bb)), t_bb);
    }
    // Add entry pc.
    near_switch_jump->addCase(llvm::ConstantInt::get(u64ty, trace_addr), org_first_bb);
  }

  // Update cache.
  // Parent-child relationship.
  virtual_regs_opt->bb_parents.insert({_near_jump_bb, {root_bb}});
  virtual_regs_opt->bb_parents.at(org_first_bb).erase(root_bb);
  virtual_regs_opt->bb_parents.at(org_first_bb).insert(_near_jump_bb);
  // Add _near_jump_bb to the bb_reg_info_node_map.
  virtual_regs_opt->bb_reg_info_node_map.insert(
      {_near_jump_bb, new BBRegInfoNode(func, state_ptr, runtime_ptr)});
}

}  // namespace remill