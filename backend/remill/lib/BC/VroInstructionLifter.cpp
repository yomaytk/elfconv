/*
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

#include "InstructionLifter.h"
#include "remill/Arch/Instruction.h"
#include "remill/Arch/Name.h"
#include "remill/BC/HelperMacro.h"
#include "remill/BC/InstructionLifter.h"

#include <cstdint>
#include <glog/logging.h>
#include <type_traits>

namespace remill {

/*
  AArch64 register methods.
*/
std::unordered_map<llvm::Value *, uint64_t> Sema_func_vma_map = {};

// get ERC from the register name.
std::pair<EcvReg, ERC> EcvReg::GetRegInfo(const std::string &_reg_name) {
  if (kArchAArch64LittleEndian == target_elf_arch) {
    auto c0 = _reg_name[0];
    auto c1 = _reg_name[1];
    // vector type register (e.g. 16B8, 4S20, 2DF30)
    if (std::isdigit(c0)) {
      ERC res_ecv_reg_class;
      uint32_t reg_kind_str_off = std::isdigit(c1) ? 2 : 1;
      auto corr_val = c0 - '0';
      uint32_t reg_num;
      if ('F' == _reg_name[reg_kind_str_off + 1]) /* e.g. 4SF, 2DF */ {
        // float vector
        res_ecv_reg_class =
            static_cast<ERC>('V' + _reg_name[reg_kind_str_off] + 'F' - 'A' + corr_val);
        reg_num = static_cast<uint32_t>(std::stoi(_reg_name.substr(reg_kind_str_off + 2)));
      }
      // integer vector
      else {
        res_ecv_reg_class = static_cast<ERC>('V' + _reg_name[reg_kind_str_off] - 'A' + corr_val);
        reg_num = static_cast<uint32_t>(std::stoi(_reg_name.substr(reg_kind_str_off + 1)));
      }
      return std::make_pair(EcvReg(RegKind::Vector, reg_num), res_ecv_reg_class);
    }
    // general register
    else if (std::isdigit(c1)) {
      auto res_ecv_reg_class = static_cast<ERC>(c0 - 'A');
      return std::make_pair(
          EcvReg((ERC::RegW == res_ecv_reg_class || ERC::RegX == res_ecv_reg_class)
                     ? RegKind::General
                     : RegKind::Vector,
                 static_cast<uint32_t>(std::stoi(_reg_name.substr(1)))),
          res_ecv_reg_class);
    }
    // system register
    else {
      if ("SP" == _reg_name) {
        return std::make_pair(EcvReg(RegKind::Special, SP_ORDER), ERC::RegX);
      } else if ("PC" == _reg_name) {
        return std::make_pair(EcvReg(RegKind::Special, PC_ORDER), ERC::RegX);
      } else if ("STATE" == _reg_name) {
        return std::make_pair(EcvReg(RegKind::Special, STATE_ORDER), ERC::RegP);
      } else if ("RUNTIME" == _reg_name) {
        return std::make_pair(EcvReg(RegKind::Special, RUNTIME_ORDER), ERC::RegP);
      } else if ("BRANCH_TAKEN" == _reg_name) {
        return std::make_pair(EcvReg(RegKind::Special, BRANCH_TAKEN_ORDER), ERC::RegX);
      } else if ("ECV_NZCV" == _reg_name) {
        return std::make_pair(EcvReg(RegKind::Special, ECV_NZCV_ORDER), ERC::RegX);
      } else if ("IGNORE_WRITE_TO_WZR" == _reg_name) {
        return std::make_pair(EcvReg(RegKind::Special, IGNORE_WRITE_TO_WZR_ORDER), ERC::RegW);
      } else if ("IGNORE_WRITE_TO_XZR" == _reg_name) {
        return std::make_pair(EcvReg(RegKind::Special, IGNORE_WRITE_TO_XZR_ORDER), ERC::RegX);
      } else if ("MONITOR" == _reg_name) {
        return std::make_pair(EcvReg(RegKind::Special, MONITOR_ORDER), ERC::RegX);
      } else if ("WZR" == _reg_name) {
        return std::make_pair(EcvReg(RegKind::Special, WZR_ORDER), ERC::RegW);
      } else if ("XZR" == _reg_name) {
        return std::make_pair(EcvReg(RegKind::Special, XZR_ORDER), ERC::RegX);
      } else if ("WSP" == _reg_name) {
        return std::make_pair(EcvReg(RegKind::Special, WSP_ORDER), ERC::RegW);
      }
    }

    LOG(FATAL) << "Unexpected register name at GetRegInfo. reg_name: " << _reg_name;
  } else if (kArchAMD64 == target_elf_arch) {
    if ("RAX" == _reg_name) {
      return {EcvReg(RegKind::General, 0), ERC::RegX};
    } else if ("EAX" == _reg_name) {
      return {EcvReg(RegKind::General, 0), ERC::RegW};
    } else if ("AX" == _reg_name) {
      return {EcvReg(RegKind::General, 0), ERC::RegH};
    } else if ("AL" == _reg_name) {
      return {EcvReg(RegKind::General, 0), ERC::RegB};
    } else if ("RCX" == _reg_name) {
      return {EcvReg(RegKind::General, 1), ERC::RegX};
    } else if ("ECX" == _reg_name) {
      return {EcvReg(RegKind::General, 1), ERC::RegW};
    } else if ("CL" == _reg_name) {
      return {EcvReg(RegKind::General, 1), ERC::RegB};
    } else if ("RDX" == _reg_name) {
      return {EcvReg(RegKind::General, 2), ERC::RegX};
    } else if ("DL" == _reg_name) {
      return {EcvReg(RegKind::General, 2), ERC::RegB};
    } else if ("EDX" == _reg_name) {
      return {EcvReg(RegKind::General, 2), ERC::RegW};
    } else if ("RBX" == _reg_name) {
      return {EcvReg(RegKind::General, 3), ERC::RegX};
    } else if ("EBX" == _reg_name) {
      return {EcvReg(RegKind::General, 3), ERC::RegW};
    } else if ("BL" == _reg_name) {
      return {EcvReg(RegKind::General, 3), ERC::RegB};
    } else if ("RSP" == _reg_name) {
      return {EcvReg(RegKind::General, 4), ERC::RegX};
    } else if ("RBP" == _reg_name) {
      return {EcvReg(RegKind::General, 5), ERC::RegX};
    } else if ("RSI" == _reg_name) {
      return {EcvReg(RegKind::General, 6), ERC::RegX};
    } else if ("ESI" == _reg_name) {
      return {EcvReg(RegKind::General, 6), ERC::RegW};
    } else if ("RDI" == _reg_name) {
      return {EcvReg(RegKind::General, 7), ERC::RegX};
    } else if ("EDI" == _reg_name) {
      return {EcvReg(RegKind::General, 7), ERC::RegW};
    } else if ("R8" == _reg_name) {
      return {EcvReg(RegKind::General, 8), ERC::RegX};
    } else if ("RIP" == _reg_name) {
      return {EcvReg(RegKind::Special, RIP_ORDER), ERC::RegX};
    } else if ("BRANCH_TAKEN" == _reg_name) {
      return {EcvReg(RegKind::Special, BRANCH_TAKEN_ORDER), ERC::RegX};
    } else if ("STATE" == _reg_name) {
      return {EcvReg(RegKind::Special, STATE_ORDER), ERC::RegP};
    } else if ("RUNTIME" == _reg_name) {
      return {EcvReg(RegKind::Special, RUNTIME_ORDER), ERC::RegP};
    } else if ("CSBASE" == _reg_name) {
      return {EcvReg(RegKind::Special, CSBASE_ORDER), ERC::RegX};
    } else if ("SSBASE" == _reg_name) {
      return {EcvReg(RegKind::Special, SSBASE_ORDER), ERC::RegX};
    } else if ("ESBASE" == _reg_name) {
      return {EcvReg(RegKind::Special, ESBASE_ORDER), ERC::RegX};
    } else if ("DSBASE" == _reg_name) {
      return {EcvReg(RegKind::Special, DSBASE_ORDER), ERC::RegX};
    } else if ("RETURN_PC" == _reg_name) {
      return {EcvReg(RegKind::Special, RETURN_PC_ORDER), ERC::RegX};
    } else if ("NEXT_PC" == _reg_name) {
      return {EcvReg(RegKind::Special, NEXT_PC_ORDER), ERC::RegX};
    } else {
      LOG(FATAL) << "Unsupported x86-64 register: " << _reg_name;
    }
  }
  std::terminate();
}

/*
  static map between `ERC` and `register name`
*/
class amd64_er_hash1 {
 public:
  std::size_t operator()(const std::pair<uint32_t, ERC> &key) const {
    return std::hash<uint32_t>()(key.first) ^
           std::hash<uint32_t>()(std::underlying_type<ERC>::type(key.second) + 10000);
  }
};

static std::unordered_map<ERC, std::string> AArch64EcvRegClassRegNameMap = {
    {ERC::RegW, "W"},   {ERC::RegX, "X"},     {ERC::RegB, "B"},   {ERC::RegH, "H"},
    {ERC::RegS, "S"},   {ERC::RegD, "D"},     {ERC::Reg8B, "8B"}, {ERC::Reg16B, "16B"},
    {ERC::Reg4H, "4H"}, {ERC::Reg8H, "8H"},   {ERC::Reg2S, "2S"}, {ERC::Reg2SF, "2SF"},
    {ERC::Reg4S, "4S"}, {ERC::Reg4SF, "4SF"}, {ERC::Reg1D, "1D"}, {ERC::Reg1DF, "1DF"},
    {ERC::Reg2D, "2D"}, {ERC::Reg2DF, "2DF"}, {ERC::RegQ, "Q"},   {ERC::RegV, "V"}};

static std::unordered_map<std::pair<uint32_t, ERC>, std::string, amd64_er_hash1>
    AMD64EcvRegClassRegNameMap = {
        {{0, ERC::RegX}, "RAX"},  {{1, ERC::RegX}, "RCX"},  {{2, ERC::RegX}, "RDX"},
        {{3, ERC::RegX}, "RBX"},  {{4, ERC::RegX}, "RSP"},  {{5, ERC::RegX}, "RBP"},
        {{6, ERC::RegX}, "RSI"},  {{7, ERC::RegX}, "RDI"},  {{8, ERC::RegX}, "R8"},
        {{9, ERC::RegX}, "R9"},   {{10, ERC::RegX}, "R10"}, {{11, ERC::RegX}, "R11"},
        {{12, ERC::RegX}, "R12"}, {{13, ERC::RegX}, "R13"}, {{14, ERC::RegX}, "R14"},
        {{15, ERC::RegX}, "R15"}};

std::string EcvReg::GetWideRegName() const {
  if (kArchAArch64LittleEndian == target_elf_arch) {
    if (number <= 31) {
      std::string reg_name;
      switch (reg_kind) {
        case RegKind::General: reg_name = "X"; break;
        case RegKind::Vector: reg_name = "V"; break;
        case RegKind::Special:
        default: LOG(FATAL) << "[Bug]: number must be 31 or less at GetWideRegName."; break;
      }
      reg_name += std::to_string(number);
      return reg_name;
    } else if (SP_ORDER == number) {
      return "SP";
    } else if (PC_ORDER == number) {
      return "PC";
    } else if (STATE_ORDER == number) {
      return "STATE";
    } else if (RUNTIME_ORDER == number) {
      return "RUNTIME";
    } else if (BRANCH_TAKEN_ORDER == number) {
      return "BRANCH_TAKEN";
    } else if (ECV_NZCV_ORDER == number) {
      return "ECV_NZCV";
    } else if (IGNORE_WRITE_TO_WZR_ORDER == number) {
      return "IGNORE_WRITE_TO_WZR";
    } else if (IGNORE_WRITE_TO_XZR_ORDER == number) {
      return "IGNORE_WRITE_TO_XZR";
    } else if (MONITOR_ORDER == number) {
      return "MONITOR";
    } else if (WZR_ORDER == number) {
      return "WZR";
    } else if (XZR_ORDER == number) {
      return "XZR";
    } else {
      LOG(FATAL) << "[Bug]: Reach the unreachable code at EcvReg::GetWideRegName.";
    }
  } else if (kArchAMD64 == target_elf_arch) {
    if (0 == number) {
      return "RAX";
    } else if (1 == number) {
      return "RCX";
    } else if (2 == number) {
      return "RDX";
    } else if (3 == number) {
      return "RBX";
    } else if (4 == number) {
      return "RSP";
    } else if (5 == number) {
      return "RBP";
    } else if (6 == number) {
      return "RSI";
    } else if (7 == number) {
      return "RDI";
    } else if (8 == number) {
      return "R8";
    } else if (SP_ORDER == number) {
      return "RSP";
    } else if (RIP_ORDER == number) {
      return "RIP";
    } else if (CSBASE_ORDER == number) {
      return "CSBASE";
    } else if (SSBASE_ORDER == number) {
      return "SSBASE";
    } else if (ESBASE_ORDER == number) {
      return "ESBASE";
    } else if (DSBASE_ORDER == number) {
      return "DSBASE";
    } else if (BRANCH_TAKEN_ORDER == number) {
      return "BRANCH_TAKEN";
    } else if (RETURN_PC_ORDER == number) {
      return "RETURN_PC";
    } else if (NEXT_PC_ORDER == number) {
      return "NEXT_PC";
    } else {
      LOG(FATAL) << "Unsupported x86-64 register. number: " << number;
    }
  }
  std::terminate();
}

std::string EcvReg::GetRegName(ERC ecv_reg_class) const {
  if (kArchAArch64LittleEndian == target_elf_arch) {
    // General or Vector register.
    if (number <= 31) {
      auto reg_name = AArch64EcvRegClassRegNameMap[ecv_reg_class];
      reg_name += std::to_string(number);
      return reg_name;
    }
    // RegKind::Special register.
    else if (SP_ORDER == number) {
      return "SP";
    } else if (PC_ORDER == number) {
      return "PC";
    } else if (STATE_ORDER == number) {
      return "STATE";
    } else if (RUNTIME_ORDER == number) {
      return "RUNTIME";
    } else if (BRANCH_TAKEN_ORDER == number) {
      return "BRANCH_TAKEN";
    } else if (ECV_NZCV_ORDER == number) {
      return "ECV_NZCV";
    } else if (IGNORE_WRITE_TO_WZR_ORDER == number) {
      return "IGNORE_WRITE_TO_WZR";
    } else if (IGNORE_WRITE_TO_XZR_ORDER == number) {
      return "IGNORE_WRITE_TO_XZR";
    } else if (MONITOR_ORDER == number) {
      return "MONITOR";
    } else if (WZR_ORDER == number) {
      return "WZR";
    } else if (XZR_ORDER == number) {
      return "XZR";
    }

    LOG(FATAL) << "[Bug]: Reach the unreachable code at EcvReg::GetRegName.";
  } else if (kArchAMD64 == target_elf_arch) {
    if (0 == number) {
      switch (ecv_reg_class) {
        case ERC::RegW: return "EAX"; break;
        case ERC::RegX: return "RAX"; break;
        case ERC::RegB: return "AL"; break;
        case ERC::RegH: return "AX"; break;
        default: LOG(FATAL) << "Unsupported x86-64 register. number: " << number;
      }
    } else if (1 == number) {
      switch (ecv_reg_class) {
        case ERC::RegW: return "ECX"; break;
        case ERC::RegX: return "RCX"; break;
        case ERC::RegB: return "CL"; break;
        case ERC::RegH: return "CX"; break;
        default: LOG(FATAL) << "Unsupported x86-64 register. number: " << number;
      }
    } else if (2 == number) {
      switch (ecv_reg_class) {
        case ERC::RegW: return "EDX"; break;
        case ERC::RegX: return "RDX"; break;
        case ERC::RegB: return "DL"; break;
        case ERC::RegH: return "DX"; break;
        default: LOG(FATAL) << "Unsupported x86-64 register. number: " << number;
      }
    } else if (3 == number) {
      switch (ecv_reg_class) {
        case ERC::RegX: return "RBX"; break;
        case ERC::RegW: return "EBX"; break;
        case ERC::RegB: return "BL"; break;
        default: LOG(FATAL) << "Unsupported x86-64 register. number: " << number;
      }
    } else if (4 == number) {
      return "RSP";
    } else if (5 == number) {
      return "RBP";
    } else if (6 == number) {
      switch (ecv_reg_class) {
        case ERC::RegX: return "RSI"; break;
        case ERC::RegW: return "ESI"; break;
        default: LOG(FATAL) << "Unsupported x86-64 register. number: " << number;
      }
    } else if (7 == number) {
      return "RDI";
    } else if (8 == number) {
      return "R8";
    } else if (SP_ORDER == number) {
      return "RSP";
    } else if (RIP_ORDER == number) {
      return "RIP";
    } else if (CSBASE_ORDER == number) {
      return "CSBASE";
    } else if (SSBASE_ORDER == number) {
      return "SSBASE";
    } else if (ESBASE_ORDER == number) {
      return "ESBASE";
    } else if (DSBASE_ORDER == number) {
      return "DSBASE";
    } else if (BRANCH_TAKEN_ORDER == number) {
      return "BRANCH_TAKEN";
    } else if (RETURN_PC_ORDER == number) {
      return "RETURN_PC";
    } else if (NEXT_PC_ORDER == number) {
      return "NEXT_PC";
    } else {
      LOG(FATAL) << "Unsupported x86-64 register. number: " << number;
    }
  }
  return "";
}

bool EcvReg::CheckPassedArgsRegs() const {
  return (0 <= number && number <= 8) || SP_ORDER == number;
}

bool EcvReg::CheckPassedReturnRegs() const {
  return (0 <= number && number <= 1) || SP_ORDER == number;
}

std::string ERC2str(ERC ecv_reg_class) {
  switch (ecv_reg_class) {
    case ERC::RegW: return "RegW"; break;
    case ERC::RegX: return "RegX"; break;
    case ERC::RegB: return "RegB"; break;
    case ERC::RegH: return "RegH"; break;
    case ERC::RegS: return "RegS"; break;
    case ERC::RegD: return "RegD"; break;
    case ERC::RegQ: return "RegQ"; break;
    case ERC::RegV: return "RegV"; break;
    case ERC::Reg8B: return "Reg8B"; break;
    case ERC::Reg16B: return "Reg16B"; break;
    case ERC::Reg4H: return "Reg4H"; break;
    case ERC::Reg8H: return "Reg8H"; break;
    case ERC::Reg2S: return "Reg2S"; break;
    case ERC::Reg2SF: return "Reg2SF"; break;
    case ERC::Reg4S: return "Reg4S"; break;
    case ERC::Reg4SF: return "Reg4SF"; break;
    case ERC::Reg1D: return "Reg1D"; break;
    case ERC::Reg1DF: return "Reg1DF"; break;
    case ERC::Reg2D: return "Reg2D"; break;
    case ERC::Reg2DF: return "Reg2DF"; break;
    case ERC::RegP: return "RegP"; break;
    case ERC::RegNULL: return "RegNULL"; break;
    default: break;
  }
}

uint64_t ERCSize(ERC ecv_reg_class) {
  switch (ecv_reg_class) {
    case ERC::RegB: return 8;
    case ERC::RegH: return 16;
    case ERC::RegW:
    case ERC::RegS: return 32;
    case ERC::RegX:
    case ERC::RegP:
    case ERC::RegD:
    case ERC::Reg8B:
    case ERC::Reg4H:
    case ERC::Reg2S:
    case ERC::Reg2SF:
    case ERC::Reg1D:
    case ERC::Reg1DF: return 64;
    case ERC::RegQ:
    case ERC::RegV:
    case ERC::Reg16B:
    case ERC::Reg8H:
    case ERC::Reg4S:
    case ERC::Reg4SF:
    case ERC::Reg2D:
    case ERC::Reg2DF: return 128;
    default:
      LOG(FATAL) << "Unexpected reg class: "
                 << static_cast<std::underlying_type<ERC>::type>(ecv_reg_class);
  }
}

BBRegInfoNode::BBRegInfoNode(llvm::Function *func, llvm::Value *state_val,
                             llvm::Value *runtime_val) {
  for (auto &arg : func->args()) {
    if (arg.getName().str() == "state") {
      r_fresh_inst_mp.insert(
          {EcvReg(RegKind::Special, STATE_ORDER), std::make_tuple(ERC::RegP, state_val, 0, false)});
    } else if (arg.getName().str() == "runtime_manager") {
      r_fresh_inst_mp.insert({EcvReg(RegKind::Special, RUNTIME_ORDER),
                              std::make_tuple(ERC::RegP, runtime_val, 0, false)});
    }
  }
  CHECK(r_fresh_inst_mp.size() == 2)
      << "[Bug] BBRegInfoNode cannot be initialized with invalid r_fresh_inst_mp.";
}

void BBRegInfoNode::join_reg_info_node(BBRegInfoNode *child) {
  // Join bb_ld_r_mp
  for (auto [_ecv_reg, _ecv_reg_class] : child->bb_ld_r_mp) {
    if (!bb_str_r_mp.contains(_ecv_reg)) {
      bb_ld_r_mp.insert({_ecv_reg, _ecv_reg_class});
    }
  }
  // Join bb_str_r_mp
  for (auto [_ecv_reg, _ecv_reg_class] : child->bb_str_r_mp) {
    bb_str_r_mp.insert_or_assign(_ecv_reg, _ecv_reg_class);
  }
  // Join r_fresh_inst_mp
  for (auto [_ecv_reg, reg_inst_value] : child->r_fresh_inst_mp) {
    if (!r_fresh_inst_mp.contains(_ecv_reg)) {
      r_fresh_inst_mp.insert({_ecv_reg, reg_inst_value});
    } else if (child->bb_str_r_mp.contains(_ecv_reg) ||
               ERCSize(std::get<ERC>(r_fresh_inst_mp.at(_ecv_reg))) <=
                   ERCSize(std::get<ERC>(reg_inst_value))) {
      r_fresh_inst_mp.insert_or_assign(_ecv_reg, reg_inst_value);
    }
  }
  // Join sema_call_written_reg_map
  for (auto key_value : child->sema_call_written_reg_map) {
    sema_call_written_reg_map.insert(key_value);
  }
  // Join sema_func_args_reg_map
  for (auto key_value : child->sema_func_args_reg_map) {
    sema_func_args_reg_map.insert(key_value);
  }
  // Join sema_func_pc_map
  for (auto key_value : child->sema_func_pc_map) {
    sema_func_pc_map.insert(key_value);
  }
}

LiftStatus
InstructionLifter::LiftAArch64EveryOperand(Instruction &arch_inst, llvm::BasicBlock *block,
                                           llvm::Value *state_ptr, llvm::Function *isel_func,
                                           BBRegInfoNode *bb_reg_info_node) {

  auto func = block->getParent();
  auto module = func->getParent();

  std::vector<llvm::Value *> args;
  uint32_t arg_num;

  auto &load_reg_map = bb_reg_info_node->bb_ld_r_mp;
  auto &store_reg_map = bb_reg_info_node->bb_str_r_mp;

  std::vector<std::pair<EcvReg, ERC>> sema_func_args_regs;

  auto runtime_ptr = NthArgument(func, kRuntimePointerArgNum);

  // set the State ptr or RuntimeManager ptr to the semantics function.
  switch (arch_inst.sema_func_arg_type) {
    case SemaFuncArgType::Nothing: arg_num = 0; break;
    case SemaFuncArgType::Runtime:
      arg_num = 1;
      args.push_back(runtime_ptr);
      break;
    case SemaFuncArgType::State:
      arg_num = 1;
      args.push_back(state_ptr);
      break;
    case SemaFuncArgType::StateRuntime:
      arg_num = 2;
      args.push_back(state_ptr);
      args.push_back(runtime_ptr);
      break;
    case SemaFuncArgType::Empty:
      LOG(FATAL) << "arch_inst.sema_func_arg_type is empty!"
                 << " at: 0x" << std::hex << arch_inst.pc
                 << ", inst.function: " << arch_inst.function;
      break;
    default: LOG(FATAL) << "arch_inst.sema_func_arg_type is invalid."; break;
  }

  std::vector<std::pair<EcvReg, ERC>> write_regs;

  // treats the every arguments for the semantics function.
  for (auto &op : arch_inst.operands) {
    Operand::Register *t_reg;

    bool is_reg = !op.reg.name.empty();
    bool is_shift_reg = !op.shift_reg.reg.name.empty();
    bool is_base_reg = !op.addr.base_reg.name.empty();

    if (uint64_t(is_reg) + uint64_t(is_shift_reg) + uint64_t(is_base_reg) > 1) {
      LOG(FATAL) << "[Bug] vailid operand regisrter set is invalid.";
    }

    if (is_reg) {
      t_reg = &op.reg;
    } else if (is_shift_reg) {
      t_reg = &op.shift_reg.reg;
    } else if (is_base_reg) {
      t_reg = &op.addr.base_reg;
    } else {
      t_reg = NULL;
    }

    auto [e_r, e_r_c] = t_reg ? EcvReg::GetRegInfo(t_reg->name)
                              : std::make_pair(EcvReg(RegKind(-1), -1), ERC::RegNULL);

    if (t_reg) {
      if (Operand::Action::kActionWrite == op.action) {
        CHECK(Operand::Type::kTypeRegister == op.type);
        if (!t_reg->name.starts_with("IGNORE_WRITE_TO")) {
          // skip the case where the store register is `XZR` or `WZR`.
          store_reg_map.insert({e_r, e_r_c});
        }
        write_regs.push_back({e_r, e_r_c});
        continue;
      } else if (Operand::Action::kActionRead == op.action) {
        // (FIXME) this check is specialized to the llvm ir store instruction of pre-post index in aarch64.
        // if (is_base_reg) {
        //   CHECK(op.addr.index_reg.name.empty())
        //       << "[Bug] addr.index_reg must not be added to operands list.";
        // }
        // Ignore `XZR` and `WZR` at load register counting.
        if ((31 == t_reg->number && ("XZR" == t_reg->name || "WZR" == t_reg->name))) {
          e_r_c = ERC::RegNULL;
        } else {
          load_reg_map.insert({e_r, e_r_c});
        }
      } else {
        LOG(FATAL) << "Operand::Action::kActionInvalid is unexpedted on LiftIntoBlock.";
      }
    }

    auto num_params = isel_func->getFunctionType()->getNumParams();
    if (!(arg_num < num_params)) {
      LOG(FATAL)
          << "lifted_status: kLiftedMismatchedISEL. The args num of the semantic function should be equal to it of the lifted instruction. "
          << arch_inst.function;
      return kLiftedMismatchedISEL;
    }

    auto arg = NthArgument(isel_func, arg_num);
    auto arg_type = arg->getType();
    auto operand = LiftOperand(arch_inst, block, state_ptr, arg, op);
    arg_num += 1;
    auto op_type = operand->getType();
    CHECK_EQ(op_type, arg_type) << "[Bug]: Lifted operand " << op.Serialize() << " to "
                                << arch_inst.function
                                << " does not have the correct type. Expected "
                                << LLVMThingToString(arg_type) << " but got "
                                << LLVMThingToString(op_type) << ". arg_num: " << arg_num - 1
                                << ", address: " << arch_inst.pc;
    args.push_back(operand);

    sema_func_args_regs.push_back({e_r, e_r_c});

    // insert the instruction which explains the latest specified register with kActinoRead.
    if (llvm::dyn_cast<llvm::LoadInst>(operand)) {
      bb_reg_info_node->r_fresh_inst_mp.insert_or_assign(e_r,
                                                         std::make_tuple(e_r_c, operand, 0, false));
    }
  }

  llvm::IRBuilder<> ir(block);

  if (arch_inst.lift_config.fork_emulation_emcc_fiber) {
    if (arch_inst.function.starts_with("SVC_EX")) {
      llvm::Value *fiber_fun_addr_ref, *pc_ref;
      // save fiber func addr
      fiber_fun_addr_ref = LoadRegAddress(block, state_ptr, kFiberFunAddrVariableName).first;
      pc_ref = LoadRegAddress(block, state_ptr, kPCVariableName).first;
      ir.CreateStore(remill::NthArgument(func, kPCArgNum), fiber_fun_addr_ref);
      // save next pc
      ir.CreateStore(
          llvm::ConstantInt::get(llvm::Type::getInt64Ty(module->getContext()), arch_inst.next_pc),
          pc_ref);
    }
  }

  // Call the function that implements the instruction semantics.
  auto sema_inst = ir.CreateCall(isel_func, args);
  bb_reg_info_node->sema_func_args_reg_map.insert({sema_inst, std::move(sema_func_args_regs)});
  Sema_func_vma_map.insert({sema_inst, arch_inst.pc});

  // Check the number of return values if the semantics function returns multiple values.
  if (write_regs.size() > 1) {
    if (auto struct_ty = llvm::dyn_cast<llvm::StructType>(sema_inst->getType())) {
      CHECK(struct_ty->getNumElements() == write_regs.size());
    } else if (auto array_ty = llvm::dyn_cast<llvm::ArrayType>(sema_inst->getType())) {
      CHECK(array_ty->getNumElements() == write_regs.size());
    } else if (auto vector_ty = llvm::dyn_cast<llvm::VectorType>(sema_inst->getType());
               vector_ty && (2 == vector_ty->getElementCount().getFixedValue())) {
      CHECK(vector_ty->getElementCount().getFixedValue() == write_regs.size());
    }
  }

  // Insert the instruction which explains the latest specified register.
  for (std::size_t i = 0; i < write_regs.size(); i++) {
    if (IGNORE_WRITE_TO_WZR_ORDER == write_regs[i].first.number ||
        IGNORE_WRITE_TO_XZR_ORDER == write_regs[i].first.number) {
      continue;
    }
    bb_reg_info_node->r_fresh_inst_mp.insert_or_assign(
        write_regs[i].first, std::make_tuple(write_regs[i].second, sema_inst, i,
                                             true));  // maybe 4th bool argumement is not matter.
  }

  // Update the sema_call_written_reg_map
  CHECK(!bb_reg_info_node->sema_call_written_reg_map.contains(sema_inst))
      << "Unexpected to multiple lift the call instruction.";
  bb_reg_info_node->sema_call_written_reg_map.insert({sema_inst, write_regs});

  bb_reg_info_node->sema_func_pc_map.insert({sema_inst, arch_inst.pc});

  // Update pre-post index for the target register.
  // (reason. If we update in the semantics function, we should increase the num of return variables and that will occur the returning through memory.)
  if (!arch_inst.prepost_updated_reg_op.reg.name.empty()) {
    const auto [update_reg_ptr_reg, _] =
        LoadRegAddress(block, state_ptr, arch_inst.prepost_updated_reg_op.reg.name);
    auto [updated_ecv_reg, updated_ecv_reg_class] =
        EcvReg::GetRegInfo(arch_inst.prepost_updated_reg_op.reg.name);
    auto new_addr_val =
        LiftAddressOperand(arch_inst, block, state_ptr, NULL, arch_inst.prepost_new_addr_op);
    ir.CreateStore(new_addr_val, update_reg_ptr_reg, false);
    // Update cache.
    store_reg_map.insert({updated_ecv_reg, updated_ecv_reg_class});
    bb_reg_info_node->r_fresh_inst_mp.insert_or_assign(
        updated_ecv_reg, std::make_tuple(updated_ecv_reg_class, new_addr_val, 0, true));
    // add index_reg (addr.index_reg is not treated in the operands list.)
    if (auto index_reg_name = arch_inst.prepost_new_addr_op.addr.index_reg.name;
        !index_reg_name.empty()) {
      auto [id_e_r, id_e_r_c] = EcvReg::GetRegInfo(index_reg_name);
      load_reg_map.insert({id_e_r, id_e_r_c});
    }
  }

  return kLiftedInstruction;
}

LiftStatus InstructionLifter::LiftX86EveryOperand(Instruction &arch_inst, llvm::BasicBlock *block,
                                                  llvm::Value *state_ptr, llvm::Function *isel_func,
                                                  BBRegInfoNode *bb_reg_info_node) {
  std::vector<llvm::Value *> args;
  uint32_t arg_num = 0;

  // treats the every arguments for the semantics function.
  for (auto &op : arch_inst.operands) {

    auto num_params = isel_func->getFunctionType()->getNumParams();
    if (!(arg_num < num_params)) {
      LOG(FATAL)
          << "lifted_status: kLiftedMismatchedISEL. The args num of the semantic function should be equal to it of the lifted instruction. "
          << arch_inst.function;
      return kLiftedMismatchedISEL;
    }

    auto arg = NthArgument(isel_func, arg_num);
    auto arg_type = arg->getType();
    auto operand = LiftOperand(arch_inst, block, state_ptr, arg, op);
    arg_num += 1;
    auto op_type = operand->getType();
    CHECK_EQ(op_type, arg_type) << "[Bug]: Lifted operand " << op.Serialize() << " to "
                                << arch_inst.function
                                << " does not have the correct type. Expected "
                                << LLVMThingToString(arg_type) << " but got "
                                << LLVMThingToString(op_type) << ". arg_num: " << arg_num - 1
                                << ", address: " << arch_inst.pc;
    args.push_back(operand);
  }

  return kLiftedInstruction;
}

}  // namespace remill