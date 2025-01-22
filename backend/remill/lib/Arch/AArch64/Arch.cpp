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

#include "remill/Arch/AArch64/AArch64Base.h"

#include <algorithm>
#include <cctype>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <iomanip>
#include <llvm/ADT/Triple.h>
#include <llvm/IR/Attributes.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <map>
#include <memory>
#include <remill/BC/HelperMacro.h>
#include <sstream>
#include <string>

#define REMILL_AARCH_STRICT_REGNUM

#include "Decode.h"
#include "remill/Arch/Instruction.h"
#include "remill/Arch/Name.h"
#include "remill/BC/ABI.h"
#include "remill/BC/Util.h"
#include "remill/BC/Version.h"
#include "remill/OS/OS.h"

#include <remill/Arch/ArchBase.h>

// clang-format off
#define INCLUDED_FROM_REMILL
#include "remill/Arch/AArch64/Runtime/State.h"

// clang-format on

namespace remill {
namespace {

static constexpr int kInstructionSize = 4;  // In bytes.
static constexpr int kPCWidth = 64;  // In bits.

template <uint32_t bit, typename T>
static inline T Select(T val) {
  return (val >> bit) & T(1);
}

Instruction::Category InstCategory(const aarch64::InstData &inst) {
  switch (inst.iclass) {
    case aarch64::InstName::INVALID: return Instruction::kCategoryInvalid;

    // TODO(pag): B.cond.
    case aarch64::InstName::B:
      if (aarch64::InstForm::B_ONLY_CONDBRANCH == inst.iform) {
        return Instruction::kCategoryConditionalBranch;
      } else {
        return Instruction::kCategoryDirectJump;
      }

    case aarch64::InstName::BR: return Instruction::kCategoryIndirectJump;

    case aarch64::InstName::CBZ:
    case aarch64::InstName::CBNZ:
    case aarch64::InstName::TBZ:
    case aarch64::InstName::TBNZ: return Instruction::kCategoryConditionalBranch;

    case aarch64::InstName::BL: return Instruction::kCategoryDirectFunctionCall;

    case aarch64::InstName::BLR: return Instruction::kCategoryIndirectFunctionCall;

    case aarch64::InstName::RET: return Instruction::kCategoryFunctionReturn;

    case aarch64::InstName::HLT: return Instruction::kCategoryError;

    case aarch64::InstName::HVC:
    case aarch64::InstName::SMC:
    case aarch64::InstName::SVC:
    case aarch64::InstName::SYS:  // Has aliases `IC`, `DC`, `AT`, and `TLBI`.
    case aarch64::InstName::SYSL: return Instruction::kCategoryAsyncHyperCall;

    case aarch64::InstName::HINT:
    case aarch64::InstName::NOP: return Instruction::kCategoryNoOp;

    // Note: These are implemented with synchronous hyper calls.
    case aarch64::InstName::BRK: return Instruction::kCategoryNormal;

    default: return Instruction::kCategoryNormal;
  }
}

class AArch64Arch final : public AArch64ArchBase, DefaultContextAndLifter {
 public:
  AArch64Arch(llvm::LLVMContext *context_, OSName os_name_, ArchName arch_name_);

  virtual ~AArch64Arch(void);

  // Decode an instruction.
  bool ArchDecodeInstruction(uint64_t address, std::string_view instr_bytes,
                             Instruction &inst) const final;

  void InstanceMinimumInst(Instruction &inst) const final;

 private:
  AArch64Arch(void) = delete;
};

AArch64Arch::AArch64Arch(llvm::LLVMContext *context_, OSName os_name_, ArchName arch_name_)
    : ArchBase(context_, os_name_, arch_name_),
      AArch64ArchBase(context_, os_name_, arch_name_),
      DefaultContextAndLifter(context_, os_name_, arch_name_) {}

AArch64Arch::~AArch64Arch(void) {}

enum RegClass {
  kRegX,  // 64-bit int.
  kRegW,  // Word, 32-bit int.
  kRegB,  // Byte.
  kRegH,  // Half-word, 16-bit float.
  kRegS,  // Single-precision float.
  kRegD,  // Doubleword, Double precision float.
  kRegQ,  // Quadword.
  kRegV,  // Vector
  kReg8B,  // 8B
  kReg16B,  // 16B
  kReg4H,  // 4H
  kReg8H,  // 8H
  kReg2S,  // 2S
  kReg2SF,  // 2SF
  kReg4S,  // 4S
  kReg4SF,  // 4SF
  kReg1D,  // 1D
  kReg1DF,  // 1DF
  kReg2D,  // 2D
  kReg2DF  // 2DF
};

#if defined(__x86_64__)
#  define K_REG_Q kReg2D
#else
#  define K_REG_Q kRegQ
#endif

enum RegUsage {
  kUseAsAddress,  // Interpret X31 == SP and W32 == WSP.
  kUseAsValue  // Interpret X31 == XZR and W31 == WZR.
};

enum Action { kActionRead, kActionWrite, kActionReadWrite };

// Immediate integer type.
enum ImmType { kUnsigned, kSigned };

// Note: Order is significant; extracted bits may be casted to this type.
enum Extend : uint8_t {
  kExtendUXTB,  // 0b000
  kExtendUXTH,  // 0b001
  kExtendUXTW,  // 0b010
  kExtendUXTX,  // 0b011
  kExtendSXTB,  // 0b100
  kExtendSXTH,  // 0b101
  kExtendSXTW,  // 0b110
  kExtendSXTX  // 0b111
};

static uint64_t ExtractSizeInBits(Extend extend) {
  switch (extend) {
    case kExtendUXTB: return 8;
    case kExtendUXTH: return 16;
    case kExtendUXTW: return 32;
    case kExtendUXTX: return 64;
    case kExtendSXTB: return 8;
    case kExtendSXTH: return 16;
    case kExtendSXTW: return 32;
    case kExtendSXTX: return 64;
  }
  return 0;
}

static RegClass ExtendTypeToRegClass(Extend extend) {
  switch (extend) {
    case kExtendUXTB: return kRegW;
    case kExtendUXTH: return kRegW;
    case kExtendUXTW: return kRegW;
    case kExtendUXTX: return kRegX;
    case kExtendSXTB: return kRegW;
    case kExtendSXTH: return kRegW;
    case kExtendSXTW: return kRegW;
    case kExtendSXTX: return kRegX;
  }
  return kRegX;
}

static Operand::ShiftRegister::Extend ShiftRegExtendType(Extend extend) {
  switch (extend) {
    case kExtendUXTB:
    case kExtendUXTH:
    case kExtendUXTW:
    case kExtendUXTX: return Operand::ShiftRegister::kExtendUnsigned;
    case kExtendSXTB:
    case kExtendSXTH:
    case kExtendSXTW:
    case kExtendSXTX: return Operand::ShiftRegister::kExtendSigned;
  }
  return Operand::ShiftRegister::kExtendInvalid;
}

// Note: Order is significant; extracted bits may be casted to this type.
enum Shift : uint8_t { kShiftLSL, kShiftLSR, kShiftASR, kShiftROR };

// Translate a shift encoding into an operand shift type used by the shift
// register class.
static Operand::ShiftRegister::Shift GetOperandShift(Shift s) {
  switch (s) {
    case kShiftLSL: return Operand::ShiftRegister::kShiftLeftWithZeroes;
    case kShiftLSR: return Operand::ShiftRegister::kShiftUnsignedRight;
    case kShiftASR: return Operand::ShiftRegister::kShiftSignedRight;
    case kShiftROR: return Operand::ShiftRegister::kShiftRightAround;
  }
  return Operand::ShiftRegister::kShiftInvalid;
}

// Get the name of an integer register.
static std::string RegNameXW(Action action, RegClass rclass, RegUsage rtype,
                             aarch64::RegNum number_) {
  auto number = static_cast<uint8_t>(number_);

  if (33 == number) {
    // Use on RET {<Xn>}
    return "PC";
  }

  std::stringstream ss;
  CHECK_LE(number, 31U);
  CHECK(kActionReadWrite != action);

  if (31 == number) {
    if (rtype == kUseAsValue) {
      if (action == kActionWrite) {
        ss << "IGNORE_WRITE_TO_XZR";
      } else {
        ss << (rclass == kRegX ? "XZR" : "WZR");
      }
    } else {
      if (action == kActionWrite) {
        ss << "SP";
      } else {
        ss << (rclass == kRegX ? "SP" : "WSP");
      }
    }
  } else {
    ss << (rclass == kRegX ? "X" : "W");
    ss << static_cast<unsigned>(number);
  }
  return ss.str();
}

// Get the name of a floating point register.
static std::string RegNameFP(Action action, RegClass rclass, RegUsage rtype,
                             aarch64::RegNum number_) {
  auto number = static_cast<uint8_t>(number_);
  CHECK_LE(number, 31U);

  std::stringstream ss;
  CHECK(kActionReadWrite != action);

  if (kRegB == rclass) {
    ss << "B";
  } else if (kRegH == rclass) {
    ss << "H";
  } else if (kRegS == rclass) {
    ss << "S";
  } else if (kRegD == rclass) {
    ss << "D";
  } else if (kRegQ == rclass) {
    ss << "Q";
  } else if (kRegV == rclass) {
    ss << "V";
  } else if (kReg8B == rclass) {
    ss << "8B";
  } else if (kReg16B == rclass) {
    ss << "16B";
  } else if (kReg4H == rclass) {
    ss << "4H";
  } else if (kReg8H == rclass) {
    ss << "8H";
  } else if (kReg2S == rclass) {
    ss << "2S";
  } else if (kReg2SF == rclass) {
    ss << "2SF";
  } else if (kReg4S == rclass) {
    ss << "4S";
  } else if (kReg4SF == rclass) {
    ss << "4SF";
  } else if (kReg1D == rclass) {
    ss << "1D";
  } else if (kReg1DF == rclass) {
    ss << "1DF";
  } else if (kReg2D == rclass) {
    ss << "2D";
  } else if (kReg2DF == rclass) {
    ss << "2DF";
  } else {
    LOG(FATAL) << "[Bug] Unexpected RegClass at RegNameFP.";
  }


  ss << static_cast<unsigned>(number);

  return ss.str();
}

static std::string RegName(Action action, RegClass rclass, RegUsage rtype, aarch64::RegNum number) {
  switch (rclass) {
    case kRegX:
    case kRegW: return RegNameXW(action, rclass, rtype, number);
    case kRegB:
    case kRegH:
    case kRegS:
    case kRegD:
    case kRegQ:
    case kRegV:
    case kReg8B:
    case kReg16B:
    case kReg4H:
    case kReg8H:
    case kReg2S:
    case kReg2SF:
    case kReg4S:
    case kReg4SF:
    case kReg1D:
    case kReg1DF:
    case kReg2D:
    case kReg2DF: return RegNameFP(action, rclass, rtype, number);
  }
  LOG(FATAL) << "[Bug] Unexpected RegClass at ReadName.";
  return "";
}

static uint64_t ReadRegSize(RegClass rclass) {
  switch (rclass) {
    case kRegX: return 64;
    case kRegW: return 32;
    case kRegB: return 8;
    case kRegH: return 16;
    case kRegS: return 32;
    case kRegD: return 64;
    case kReg8B:
    case kReg4H:
    case kReg2S:
    case kReg2SF:
    case kReg1D:
    case kReg1DF: return 64;
    case kRegQ:
    case kRegV:
    case kReg16B:
    case kReg8H:
    case kReg4S:
    case kReg4SF:
    case kReg2D:
    case kReg2DF: return 128;
  }
  LOG(FATAL) << "[Bug] Unexpected RegClass at ReadRegSize.";
  return 0;
}

static uint64_t WriteRegSize(RegClass rclass) {
  switch (rclass) {
    case kRegW: return 32;
    case kRegX: return 64;
    case kRegB: return 8;
    case kRegH: return 16;
    case kRegS: return 32;
    case kRegD:
    case kReg8B:
    case kReg4H:
    case kReg2S:
    case kReg2SF:
    case kReg1D:
    case kReg1DF: return 64;
    case kRegQ:
    case kRegV:
    case kReg16B:
    case kReg8H:
    case kReg4S:
    case kReg4SF:
    case kReg2D:
    case kReg2DF: return 128;
  }
  LOG(FATAL) << "[Bug] Unexpected RegClass at WriteRegSize.";
  return 0;
}

// This gives us a register operand. If we have an operand like `<Xn|SP>`,
// then the usage is `kTypeUsage`, otherwise (i.e. `<Xn>`), the usage is
// a `kTypeValue`.
static Operand::Register Reg(Action action, RegClass rclass, RegUsage rtype,
                             aarch64::RegNum reg_num) {
  Operand::Register reg;

  reg.number = std::underlying_type<aarch64::RegNum>::type(reg_num);
  if (kActionWrite == action) {
    reg.name = RegName(action, rclass, rtype, reg_num);
    reg.size = WriteRegSize(rclass);
  } else if (kActionRead == action) {
    reg.name = RegName(action, rclass, rtype, reg_num);
    reg.size = ReadRegSize(rclass);
  } else {
    LOG(FATAL) << "Reg function only takes a simple read or write action.";
  }
  return reg;
}

static void AddRegOperand(Instruction &inst, Action action, RegClass rclass, RegUsage rtype,
                          aarch64::RegNum reg_num) {
  Operand op;
  op.type = Operand::kTypeRegister;

  if (kActionWrite == action || kActionReadWrite == action) {
    op.reg = Reg(kActionWrite, rclass, rtype, reg_num);
    op.size = op.reg.size;
    op.action = Operand::kActionWrite;
    inst.operands.push_back(op);
  }

  if (kActionRead == action || kActionReadWrite == action) {
    op.reg = Reg(kActionRead, rclass, rtype, reg_num);
    op.size = op.reg.size;
    op.action = Operand::kActionRead;
    inst.operands.push_back(op);
  }
}

static void AddWriteRegMemOperand(Instruction &inst, RegClass rclass, RegUsage rtype,
                                  aarch64::RegNum reg_num) {
  Operand op;
  op.type = Operand::kTypeRegister;

  op.reg = Reg(kActionRead, rclass, rtype, reg_num);
  op.size = op.reg.size;
  op.action = Operand::kActionRead;
  inst.operands.push_back(op);
}

static void AddShiftRegOperand(Instruction &inst, RegClass rclass, RegUsage rtype,
                               aarch64::RegNum reg_num, Shift shift_type, uint64_t shift_size) {
  if (!shift_size) {
    AddRegOperand(inst, kActionRead, rclass, rtype, reg_num);
  } else {
    Operand op;
    op.shift_reg.reg = Reg(kActionRead, rclass, rtype, reg_num);
    op.shift_reg.shift_op = GetOperandShift(shift_type);
    op.shift_reg.shift_size = shift_size;

    op.type = Operand::kTypeShiftRegister;
    op.size = op.shift_reg.reg.size;
    op.action = Operand::kActionRead;
    inst.operands.push_back(op);
  }
}

// Add an extend register operand, e.g. `(<Wm>|<Xm>){, <extend> {<amount>}}`.
//
// NOTE(pag): `rclass` is explicitly passed instead of inferred because some
//            instructions, e.g. `ADD_32_ADDSUB_EXT` specify `Wm` only.
static void AddExtendRegOperand(Instruction &inst, RegClass reg_class, RegUsage rtype,
                                aarch64::RegNum reg_num, Extend extend_type, uint64_t output_size,
                                uint64_t shift_size = 0) {
  Operand op;
  op.shift_reg.reg = Reg(kActionRead, reg_class, rtype, reg_num);
  op.shift_reg.extend_op = ShiftRegExtendType(extend_type);
  op.shift_reg.extract_size = ExtractSizeInBits(extend_type);

  // No extraction needs to be done, and zero extension already happens.
  if (Operand::ShiftRegister::kExtendUnsigned == op.shift_reg.extend_op &&
      op.shift_reg.extract_size == op.shift_reg.reg.size) {
    op.shift_reg.extend_op = Operand::ShiftRegister::kExtendInvalid;
    op.shift_reg.extract_size = 0;

    // Extracting a value that is wider than the register.
  } else if (op.shift_reg.extract_size > op.shift_reg.reg.size) {
    op.shift_reg.extend_op = Operand::ShiftRegister::kExtendInvalid;
    op.shift_reg.extract_size = 0;
  }

  if (shift_size) {
    op.shift_reg.shift_op = Operand::ShiftRegister::kShiftLeftWithZeroes;
    op.shift_reg.shift_size = shift_size;
  }

  op.type = Operand::kTypeShiftRegister;
  op.size = output_size;
  op.action = Operand::kActionRead;
  inst.operands.push_back(op);
}

static void AddImmOperand(Instruction &inst, uint64_t val, ImmType signedness = kUnsigned,
                          unsigned size = 64) {
  Operand op;
  op.type = Operand::kTypeImmediate;
  op.action = Operand::kActionRead;
  op.size = size;
  op.imm.is_signed = signedness == kUnsigned ? false : true;
  op.imm.val = val;
  inst.operands.push_back(op);
}

static void AddMonitorOperand(Instruction &inst, Action action) {
  Operand op;
  op.reg.name = "MONITOR";
  op.reg.size = 64;
  op.size = 64;
  op.type = Operand::kTypeRegister;

  if (kActionWrite == action || kActionReadWrite == action) {
    op.action = Operand::kActionWrite;
    inst.operands.push_back(op);
  }

  if (kActionRead == action || kActionReadWrite == action) {
    op.action = Operand::kActionRead;
    inst.operands.push_back(op);
  }
}

static void AddEcvNZCVOperand(Instruction &inst, Action action) {
  Operand op;
  op.reg.name = "ECV_NZCV";
  op.reg.size = 64;
  op.size = 64;
  op.type = Operand::kTypeRegister;

  if (kActionWrite == action || kActionReadWrite == action) {
    op.action = Operand::kActionWrite;
    inst.operands.push_back(op);
  }

  if (kActionRead == action || kActionReadWrite == action) {
    op.action = Operand::kActionRead;
    inst.operands.push_back(op);
  }
}

static void AddPCRegOp(Instruction &inst, int64_t disp, Operand::Address::Kind op_kind) {
  Operand op;
  op.type = Operand::kTypeAddress;
  op.size = 64;
  op.addr.address_size = 64;
  op.addr.base_reg.name = "PC";
  op.addr.base_reg.size = 64;
  op.addr.displacement = disp;
  op.addr.kind = op_kind;
  op.action = Operand::kActionRead;
  inst.operands.push_back(op);
}

// Emit a memory read or write operand of the form `[PC + disp]`.
static void AddPCRegMemOp(Instruction &inst, int64_t disp) {
  AddPCRegOp(inst, disp, Operand::Address::kMemoryRead);
}

// Emit an address operand that computes `PC + disp`.
static void AddPCDisp(Instruction &inst, int64_t disp) {
  AddPCRegOp(inst, disp, Operand::Address::kAddressCalculation);
}

// Base+offset memory operands are equivalent to indexing into an array.
//
// We have something like this:
//    [<Xn|SP>, #<imm>]
//
// Which gets is:
//    addr = Xn + imm
//    ... deref addr and do stuff ...
static void AddBasePlusOffsetMemOp(Instruction &inst, uint64_t access_size,
                                   aarch64::RegNum base_reg, uint64_t disp) {
  Operand op;
  op.type = Operand::kTypeAddress;
  op.size = access_size;
  op.addr.address_size = 64;
  op.addr.base_reg = Reg(kActionRead, kRegX, kUseAsAddress, base_reg);
  op.addr.displacement = disp;
  op.action = Operand::kActionRead;
  op.addr.kind = Operand::Address::kMemoryRead;
  inst.operands.push_back(op);
}

static constexpr auto kInvalidReg = static_cast<aarch64::RegNum>(0xFF);

// Pre-index memory operands write back the result of the displaced address
// to the base register.
//
// We have something like this:
//    [<Xn|SP>, #<imm>]!
//
// Which gets us:
//    addr = Xn + imm
//    ... deref addr and do stuff ...
//    Xn = addr + imm
//
// So we add in two operands: one that is a register write operand for Xn,
// the other that is the value of (Xn + imm + imm).
static void AddPreIndexMemOp(Instruction &inst, uint64_t access_size, aarch64::RegNum base_reg,
                             uint64_t disp, aarch64::RegNum dest_reg1 = kInvalidReg,
                             aarch64::RegNum dest_reg2 = kInvalidReg) {
  AddBasePlusOffsetMemOp(inst, access_size, base_reg, disp);
  auto addr_op = inst.operands[inst.operands.size() - 1];

  // The register that will be updated
  Operand xn_op;
  xn_op.type = Operand::kTypeRegister;
  xn_op.action = Operand::kActionWrite;
  xn_op.size = 64;

  // We don't care about the case of `31` because then `base_reg` will be
  // `SP`, but `dest_reg1` or `dest_reg2` (if they are 31), will represent
  // one of `WZR` or `ZR`.
  if (static_cast<uint8_t>(base_reg) != 31 && (dest_reg1 == base_reg || dest_reg2 == base_reg)) {
    xn_op.reg.name = "SUPPRESS_WRITEBACK";
    xn_op.reg.size = 64;
  } else {
    xn_op.reg = Reg(kActionWrite, kRegX, kUseAsAddress, base_reg);
  }
  inst.prepost_updated_reg_op = xn_op;

  // The new address
  addr_op.addr.displacement = disp;
  inst.prepost_new_addr_op = addr_op;
}

// Post-index memory operands write back the result of the displaced address
// to the base register.
//
// We have something like this:
//    [<Xn|SP>], #<imm>
//
// Which gets us:
//    addr = Xn
//    ... deref addr and do stuff ...
//    Xn = addr + imm
//
// So we add in two operands: one that is a register write operand for Xn,
// the other that is the value of (Xn + imm).
static void AddPostIndexMemOp(Instruction &inst, uint64_t access_size, aarch64::RegNum base_reg,
                              uint64_t disp, aarch64::RegNum dest_reg1 = kInvalidReg,
                              aarch64::RegNum dest_reg2 = kInvalidReg) {
  AddBasePlusOffsetMemOp(inst, access_size, base_reg, 0);
  auto addr_op = inst.operands[inst.operands.size() - 1];

  // The register that will be updated
  Operand xn_op;
  xn_op.type = Operand::kTypeRegister;
  xn_op.action = Operand::kActionWrite;
  xn_op.size = 64;

  // We don't care about the case of `31` because then `base_reg` will be
  // `SP`, but `dest_reg1` or `dest_reg2` (if they are 31), will represent
  // one of `WZR` or `ZR`.
  if (static_cast<uint8_t>(base_reg) != 31 && (dest_reg1 == base_reg || dest_reg2 == base_reg)) {
    xn_op.reg.name = "SUPPRESS_WRITEBACK";
    xn_op.reg.size = 64;
  } else {
    xn_op.reg = Reg(kActionWrite, kRegX, kUseAsAddress, base_reg);
  }
  inst.prepost_updated_reg_op = xn_op;

  // The new address
  addr_op.addr.displacement = disp;
  inst.prepost_new_addr_op = addr_op;
}

// Post-index memory operands write back the result of the displaced address
// to the base register.
//
// We have something like this:
//    [<Xn|SP>], <Xm>
//
// Which gets us:
//    addr = Xn
//    ... deref addr and do stuff ...
//    Xn = addr + Xm
//
// So we add in two operands: one that is a register write operand for Xn,
// the other that is the value of (Xn + imm).
static void AddPostIndexMemOp(Instruction &inst, uint64_t access_size, aarch64::RegNum base_reg,
                              aarch64::RegNum disp_reg, aarch64::RegNum dest_reg1 = kInvalidReg,
                              aarch64::RegNum dest_reg2 = kInvalidReg) {
  AddBasePlusOffsetMemOp(inst, access_size, base_reg, 0);
  auto addr_op = inst.operands[inst.operands.size() - 1];

  // The register that will be updated
  Operand xn_op;
  xn_op.type = Operand::kTypeRegister;
  xn_op.action = Operand::kActionWrite;
  xn_op.size = 64;

  // We don't care about the case of `31` because then `base_reg` will be
  // `SP`, but `dest_reg1` or `dest_reg2` (if they are 31), will represent
  // one of `WZR` or `ZR`.
  if (static_cast<uint8_t>(base_reg) != 31 && (dest_reg1 == base_reg || dest_reg2 == base_reg)) {
    xn_op.reg.name = "SUPPRESS_WRITEBACK";
    xn_op.reg.size = 64;
  } else {
    xn_op.reg = Reg(kActionWrite, kRegX, kUseAsAddress, base_reg);
  }

  inst.prepost_updated_reg_op = xn_op;

  addr_op.addr.kind = Operand::Address::kAddressCalculation;
  addr_op.addr.scale = 1;
  addr_op.addr.index_reg = Reg(kActionRead, kRegX, kUseAsAddress, disp_reg);
  inst.prepost_new_addr_op = addr_op;
}

static bool MostSignificantSetBit(uint64_t val, uint64_t *highest_out) {
#if __has_builtin(__builtin_clzll)
  if (val) {
    *highest_out = 63 - (__builtin_clzll(val) - (sizeof(unsigned long long) * 8 - 64));
    return true;
  } else {
    return false;
  }
#else
  auto found = false;
  for (uint64_t i = 0; i < 64; ++i) {
    if ((val >> i) & 1) {
      *highest_out = i;
      found = true;
    }
  }
  return found;
#endif
}

static bool LeastSignificantSetBit(uint64_t val, uint64_t *highest_out) {
#if __has_builtin(__builtin_ctzll)
  if (val) {
    *highest_out = __builtin_ctzll(val);
    return true;
  } else {
    return false;
  }
#else
  for (uint64_t i = 0; i < 64; ++i) {
    if ((val >> i) & 1) {
      *highest_out = i;
      return true;
    }
  }
  return false;
#endif  // __has_builtin(__builtin_ctzll)
}

static constexpr uint64_t kOne = static_cast<uint64_t>(1);

inline static uint64_t Ones(uint64_t val) {
  uint64_t out = 0;
  for (; val != 0; --val) {
    out <<= kOne;
    out |= kOne;
  }
  return out;
}

static uint64_t ROR(uint64_t val, uint64_t val_size, uint64_t rotate_amount) {
  for (uint64_t i = 0; i < rotate_amount; ++i) {
    val = ((val & kOne) << (val_size - kOne)) | (val >> kOne);
  }
  return val;
}

// Take a bit string `val` of length `val_size` bits, and concatenate it to
// itself until it occupies at least `goal_size` bits.
static uint64_t Replicate(uint64_t val, uint64_t val_size, uint64_t goal_size) {
  uint64_t replicated_val = 0;
  for (uint64_t i = 0; i < goal_size; i += val_size) {
    replicated_val = (replicated_val << val_size) | val;
  }
  return replicated_val;
}

// Decode bitfield and logical immediate masks. There is a nice piece of code
// here for producing all valid (64-bit) inputs:
//
//      https://stackoverflow.com/a/33265035/247591
//
// The gist of the format is that you hav
static bool DecodeBitMasks(uint64_t N /* one bit */, uint64_t imms /* six bits */,
                           uint64_t immr /* six bits */, bool is_immediate, uint64_t data_size,
                           uint64_t *wmask_out = nullptr, uint64_t *tmask_out = nullptr) {
  uint64_t len = 0;
  if (!MostSignificantSetBit((N << 6ULL) | (~imms & 0x3fULL), &len)) {
    return false;
  }
  if (len < 1) {
    return false;
  }

  const uint64_t esize = kOne << len;
  if (esize > data_size) {
    return false;  // `len == 0` is a `ReservedValue()`.
  }

  const uint64_t levels = Ones(len);  // ZeroExtend(Ones(len), 6).
  const uint64_t R = immr & levels;
  const uint64_t S = imms & levels;

  if (is_immediate && S == levels) {
    return false;  // ReservedValue.
  }

  const uint64_t diff = (S - R) & static_cast<uint64_t>(0x3F);  // 6-bit sbb.
  const uint64_t d = diff & levels;  // `diff<len-1:0>`.
  const uint64_t welem = Ones(S + kOne);
  const uint64_t telem = Ones(d + kOne);
  const uint64_t wmask = Replicate(ROR(welem, esize, R), esize, data_size);
  const uint64_t tmask = Replicate(telem, esize, data_size);

  if (wmask_out) {
    *wmask_out = wmask;
  }

  if (tmask_out) {
    *tmask_out = tmask;
  }
  return true;
}
// Utility function for extracting [From, To] bits from a uint32_t.
static inline uint64_t Extract(uint64_t bits, unsigned from, unsigned to) {
  CHECK(from < 64 && to < 64 && from >= to);
  return (bits >> to) & ((1 << (from - to + 1)) - 1);
}

static uint64_t VFPExpandImmToFloat32(uint64_t imm) {
  uint64_t result = 0;
  uint64_t bit6 = Extract(imm, 6, 6);
  result |= Extract(imm, 7, 7) << 31;
  result |= Extract(imm, 5, 0) << 19;
  result |= bit6 ? (0x1FULL << 25) : (0x1ULL << 30);
  return result;
}

static uint64_t VFPExpandImmToFloat64(uint64_t imm) {
  uint64_t result = 0;
  uint64_t bit6 = Extract(imm, 6, 6);
  result |= Extract(imm, 7, 7) << 63;
  result |= Extract(imm, 5, 0) << 48;
  result |= bit6 ? (0xFFULL << 54) : (0x1ULL << 62);
  return result;
}

void AArch64Arch::InstanceMinimumInst(Instruction &inst) const {
  inst.arch = this;
  inst.arch_name = arch_name;
  inst.sub_arch_name = arch_name;  // TODO(pag): Thumb.
  inst.branch_taken_arch_name = arch_name;
  inst.category = Instruction::kCategoryInvalid;
  inst.sema_func_arg_type = SemaFuncArgType::Empty;
}

bool AArch64Arch::ArchDecodeInstruction(uint64_t address, std::string_view inst_bytes,
                                        Instruction &inst) const {

  aarch64::InstData dinst = {};
  auto bytes = reinterpret_cast<const uint8_t *>(inst_bytes.data());

  inst.arch = this;
  inst.arch_name = arch_name;
  inst.sub_arch_name = arch_name;  // TODO(pag): Thumb.
  inst.branch_taken_arch_name = arch_name;
  inst.pc = address;
  inst.next_pc = address + kInstructionSize;
  inst.category = Instruction::kCategoryInvalid;
  inst.sema_func_arg_type = SemaFuncArgType::Empty;

  if (kInstructionSize != inst_bytes.size()) {
    inst.category = Instruction::kCategoryInvalid;
    return false;
  } else if (0 != (address % kInstructionSize)) {
    inst.category = Instruction::kCategoryInvalid;
    return false;
  } else if (!aarch64::TryExtract(bytes, dinst)) {
    inst.category = Instruction::kCategoryInvalid;
#if defined(WARNING_OUTPUT)
    printf("[WARNING] Unsupported instruction at address: 0x%08lx (TryExtract)\n", address);
#endif
    return false;
  }

  if (!inst.bytes.empty() && inst.bytes.data() == inst_bytes.data()) {
    CHECK_LE(kInstructionSize, inst.bytes.size());
    inst.bytes.resize(kInstructionSize);
  } else {
    inst.bytes = inst_bytes.substr(0, kInstructionSize);
  }

  inst.category = InstCategory(dinst);
  inst.function =
      aarch64::InstFormToString(dinst.iform); /* SEM function symbol must be ISEL_<inst.function> */
  /* set operands of insn */
  if (!aarch64::TryDecode(dinst, inst)) {
    inst.category = Instruction::kCategoryInvalid;
#if defined(WARNING_OUTPUT)
    printf("[WARNING] Unsupported instruction at address: 0x%08lx (TryDecode), instForm: %s\n",
           address, inst.function.c_str());
#endif
    return false;
  }

  // Control flow operands update the next program counter.
  // if (inst.IsControlFlow()) {
  //   inst.operands.emplace_back();
  //   auto &dst_ret_pc = inst.operands.back();
  //   dst_ret_pc.type = Operand::kTypeRegister;
  //   dst_ret_pc.action = Operand::kActionWrite;
  //   dst_ret_pc.size = address_size;
  //   dst_ret_pc.reg.size = address_size;
  // }

  // The semantics will store the return address in `RETURN_PC`. This is to
  // help synchronize program counters when lifting instructions on an ISA
  // with delay slots.
  // if (inst.IsFunctionCall()) {
  //   inst.operands.emplace_back();
  //   auto &dst_ret_pc = inst.operands.back();
  //   dst_ret_pc.type = Operand::kTypeRegister;
  //   dst_ret_pc.action = Operand::kActionWrite;
  //   dst_ret_pc.size = address_size;
  //   dst_ret_pc.reg.name = "RETURN_PC";
  //   dst_ret_pc.reg.size = address_size;
  // }

  return true;
}

}  // namespace

namespace aarch64 {
namespace {

static void DecodeFallThroughPC(Instruction &inst) {
  Operand not_taken_op = {};
  not_taken_op.action = Operand::kActionRead;
  not_taken_op.type = Operand::kTypeAddress;
  not_taken_op.size = kPCWidth;
  not_taken_op.addr.address_size = kPCWidth;
  not_taken_op.addr.base_reg.name = "PC";
  not_taken_op.addr.base_reg.size = kPCWidth;
  not_taken_op.addr.displacement = kInstructionSize;
  not_taken_op.addr.kind = Operand::Address::kControlFlowTarget;
  inst.operands.push_back(not_taken_op);

  inst.branch_not_taken_pc = inst.next_pc;
}

static uint64_t DecodeScale(const InstData &data) {
  uint64_t scale = ((data.opc & 0x2ULL) << 1ULL) | data.size;
  return scale;
}

// <OPCODE>  <Xd>, <Xn>
static bool TryDecodeRdW_Rn(const InstData &data, Instruction &inst, RegClass rclass) {
  AddRegOperand(inst, kActionWrite, rclass, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rn);
  return true;
}

// <OPCODE>  <Xd>, <Xn>, <Xm>
static bool TryDecodeRdW_Rn_Rm(const InstData &data, Instruction &inst, RegClass rclass) {
  TryDecodeRdW_Rn(data, inst, rclass);
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rm);
  return true;
}

}  // namespace

static void AddArrangementSpecifier(Instruction &inst, uint64_t total_size, uint64_t element_size);
static void AddArrangementSpecifierFloat(Instruction &inst, uint64_t total_size,
                                         uint64_t element_size);
static RegClass ArrangementRegClass(uint64_t total_size, uint64_t element_size,
                                    bool is_float = false);

// RET  {<Xn>}
bool TryDecodeRET_64R_BRANCH_REG(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  // RegNum(33) expresses "PC".
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, RegNum(33));
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rn);
  return true;
}

// BLR  <Xn>
bool TryDecodeBLR_64_BRANCH_REG(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, RegNum(30));
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rn);
  DecodeFallThroughPC(inst);
  return true;
}

// STLR  <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeSTLR_SL32_LDSTEXCL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 32, data.Rn, 0);
  return true;
}

// STLR  <Xt>, [<Xn|SP>{,#0}]
bool TryDecodeSTLR_SL64_LDSTEXCL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 32, data.Rn, 0);
  return true;
}

// STP  <Wt1>, <Wt2>, [<Xn|SP>, #<imm>]!
bool TryDecodeSTP_32_LDSTPAIR_PRE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt2);
  uint64_t offset = static_cast<uint64_t>(data.imm7.simm7);
  AddPreIndexMemOp(inst, 64, data.Rn, offset << 2);
  return true;
}

// STP  <Xt1>, <Xt2>, [<Xn|SP>, #<imm>]!
bool TryDecodeSTP_64_LDSTPAIR_PRE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rt);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rt2);
  uint64_t offset = static_cast<uint64_t>(data.imm7.simm7);
  AddPreIndexMemOp(inst, 128, data.Rn, offset << 3);
  return true;
}

// STP  <St1>, <St2>, [<Xn|SP>, #<imm>]!
bool TryDecodeSTP_S_LDSTPAIR_PRE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kRegS, kUseAsValue, data.Rt);
  AddRegOperand(inst, kActionRead, kRegS, kUseAsValue, data.Rt2);
  uint64_t offset = static_cast<uint64_t>(data.imm7.simm7);
  AddPreIndexMemOp(inst, 64, data.Rn, offset << 2);
  return true;
}

// STP  <Dt1>, <Dt2>, [<Xn|SP>, #<imm>]!
bool TryDecodeSTP_D_LDSTPAIR_PRE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kRegD, kUseAsValue, data.Rt);
  AddRegOperand(inst, kActionRead, kRegD, kUseAsValue, data.Rt2);
  uint64_t offset = static_cast<uint64_t>(data.imm7.simm7);
  AddPreIndexMemOp(inst, 128, data.Rn, offset << 3);
  return true;
}

// STP  <Wt1>, <Wt2>, [<Xn|SP>], #<imm>
bool TryDecodeSTP_32_LDSTPAIR_POST(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt2);
  uint64_t offset = static_cast<uint64_t>(data.imm7.simm7);
  AddPostIndexMemOp(inst, 64, data.Rn, offset << 2);
  return true;
}

// STP  <Xt1>, <Xt2>, [<Xn|SP>], #<imm>
bool TryDecodeSTP_64_LDSTPAIR_POST(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rt);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rt2);
  uint64_t offset = static_cast<uint64_t>(data.imm7.simm7);
  AddPostIndexMemOp(inst, 128, data.Rn, offset << 3);
  return true;
}

// STP  <St1>, <St2>, [<Xn|SP>], #<imm>
bool TryDecodeSTP_S_LDSTPAIR_POST(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kRegS, kUseAsValue, data.Rt);
  AddRegOperand(inst, kActionRead, kRegS, kUseAsValue, data.Rt2);
  uint64_t offset = static_cast<uint64_t>(data.imm7.simm7);
  AddPostIndexMemOp(inst, 64, data.Rn, offset << 2);
  return true;
}

// STP  <Dt1>, <Dt2>, [<Xn|SP>], #<imm>
bool TryDecodeSTP_D_LDSTPAIR_POST(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kRegD, kUseAsValue, data.Rt);
  AddRegOperand(inst, kActionRead, kRegD, kUseAsValue, data.Rt2);
  uint64_t offset = static_cast<uint64_t>(data.imm7.simm7);
  AddPostIndexMemOp(inst, 128, data.Rn, offset << 3);
  return true;
}

// STP  <Wt1>, <Wt2>, [<Xn|SP>{, #<imm>}]
bool TryDecodeSTP_32_LDSTPAIR_OFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt2);
  AddBasePlusOffsetMemOp(inst, 64, data.Rn, static_cast<uint64_t>(data.imm7.simm7) << 2);
  return true;
}

// STP  <Xt1>, <Xt2>, [<Xn|SP>{, #<imm>}]
bool TryDecodeSTP_64_LDSTPAIR_OFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rt);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rt2);
  AddBasePlusOffsetMemOp(inst, 128, data.Rn, static_cast<uint64_t>(data.imm7.simm7) << 3);
  return true;
}

static bool TryDecodeSTP_Vn_LDSTPAIR_OFF(const InstData &data, Instruction &inst, RegClass rclass) {
  auto size = ReadRegSize(rclass);
  auto scale = 2U + data.opc;
  if (data.opc == 0x3) {
    return false;  // `if opc == '11' then UnallocatedEncoding();`.
  }
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rt);
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rt2);
  AddBasePlusOffsetMemOp(inst, size * 2, data.Rn, static_cast<uint64_t>(data.imm7.simm7) << scale);
  return true;
}

// STP  <St1>, <St2>, [<Xn|SP>{, #<imm>}]
bool TryDecodeSTP_S_LDSTPAIR_OFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeSTP_Vn_LDSTPAIR_OFF(data, inst, kRegS);
}

// STP  <Dt1>, <Dt2>, [<Xn|SP>{, #<imm>}]
bool TryDecodeSTP_D_LDSTPAIR_OFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeSTP_Vn_LDSTPAIR_OFF(data, inst, kRegD);
}

// STP  <Qt1>, <Qt2>, [<Xn|SP>{, #<imm>}]
bool TryDecodeSTP_Q_LDSTPAIR_OFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeSTP_Vn_LDSTPAIR_OFF(data, inst, K_REG_Q);
}

static bool TryDecodeSTP_Vn_LDSTPAIR_PRE(const InstData &data, Instruction &inst, RegClass rclass) {
  auto size = ReadRegSize(rclass);
  auto scale = 2U + data.opc;
  if (data.opc == 0x3) {
    return false;  // `if opc == '11' then UnallocatedEncoding();`.
  }
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rt);
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rt2);
  AddPreIndexMemOp(inst, size * 2, data.Rn, static_cast<uint64_t>(data.imm7.simm7) << scale);

  return true;
}

// STP  <Qt1>, <Qt2>, [<Xn|SP>, #<imm>]!
bool TryDecodeSTP_Q_LDSTPAIR_PRE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeSTP_Vn_LDSTPAIR_PRE(data, inst, K_REG_Q);
}

static bool TryDecodeSTP_Vn_LDSTPAIR_POST(const InstData &data, Instruction &inst,
                                          RegClass rclass) {
  auto size = ReadRegSize(rclass);
  auto scale = 2U + data.opc;
  if (data.opc == 0x3) {
    return false;  // `if opc == '11' then UnallocatedEncoding();`.
  }
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rt);
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rt2);
  AddPostIndexMemOp(inst, size * 2, data.Rn, static_cast<uint64_t>(data.imm7.simm7) << scale);

  return true;
}

// STP  <Qt1>, <Qt2>, [<Xn|SP>], #<imm>
bool TryDecodeSTP_Q_LDSTPAIR_POST(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeSTP_Vn_LDSTPAIR_POST(data, inst, K_REG_Q);
}

// LDP  <Wt1>, <Wt2>, [<Xn|SP>], #<imm>
bool TryDecodeLDP_32_LDSTPAIR_POST(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  // `if L:opc<0> == '01' || opc == '11' then UnallocatedEncoding();`.
  if ((!data.L && (data.opc & 1)) || data.opc == 3) {
    return false;
  }
  if (data.Rt == data.Rt2) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rt);
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rt2);
  AddPostIndexMemOp(inst, 64, data.Rn, static_cast<uint64_t>(data.imm7.simm7) << 2);
  return true;
}

// LDP  <Xt1>, <Xt2>, [<Xn|SP>], #<imm>
bool TryDecodeLDP_64_LDSTPAIR_POST(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  // `if L:opc<0> == '01' || opc == '11' then UnallocatedEncoding();`.
  if ((!data.L && (data.opc & 1)) || data.opc == 3) {
    return false;
  }
  if (data.Rt == data.Rt2) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rt);
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rt2);
  AddPostIndexMemOp(inst, 128, data.Rn, static_cast<uint64_t>(data.imm7.simm7) << 3);
  return true;
}

// LDPSW <Xt1>, <Xt2>, [<Xn|SP>], #<imm>
bool TryDecodeLDPSW_64_LDSTPAIR_OFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  if (data.Rt == data.Rt2) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rt);
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rt2);
  AddBasePlusOffsetMemOp(inst, 64, data.Rn, static_cast<uint64_t>(data.imm7.simm7) << 2);
  return true;
}

// LDPSW  <Xt1>, <Xt2>, [<Xn|SP>], #<imm>
bool TryDecodeLDPSW_64_LDSTPAIR_POST(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  if (data.Rt == data.Rt2) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rt);
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rt2);
  AddPostIndexMemOp(inst, 64, data.Rn, static_cast<uint64_t>(data.imm7.simm7) << 2);
  return true;
}

// LDPSW  <Xt1>, <Xt2>, [<Xn|SP>, #<imm>]!
bool TryDecodeLDPSW_64_LDSTPAIR_PRE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  if (data.Rt == data.Rt2) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rt);
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rt2);
  AddPreIndexMemOp(inst, 64, data.Rn, static_cast<uint64_t>(data.imm7.simm7) << 2, data.Rt,
                   data.Rt2);
  return true;
}

// LDP  <Wt1>, <Wt2>, [<Xn|SP>, #<imm>]!
bool TryDecodeLDP_32_LDSTPAIR_PRE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  // `if L:opc<0> == '01' || opc == '11' then UnallocatedEncoding();`.
  if ((!data.L && (data.opc & 1)) || data.opc == 3) {
    return false;
  }
  if (data.Rt == data.Rt2) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rt);
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rt2);
  AddPreIndexMemOp(inst, 64, data.Rn, static_cast<uint64_t>(data.imm7.simm7) << 2, data.Rt,
                   data.Rt2);
  return true;
}

// LDP  <Xt1>, <Xt2>, [<Xn|SP>, #<imm>]!
bool TryDecodeLDP_64_LDSTPAIR_PRE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  // `if L:opc<0> == '01' || opc == '11' then UnallocatedEncoding();`.
  if ((!data.L && (data.opc & 1)) || data.opc == 3) {
    return false;
  }
  if (data.Rt == data.Rt2) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rt);
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rt2);
  AddPreIndexMemOp(inst, 128, data.Rn, static_cast<uint64_t>(data.imm7.simm7) << 3, data.Rt,
                   data.Rt2);
  return true;
}

// LDP  <Wt1>, <Wt2>, [<Xn|SP>{, #<imm>}]
bool TryDecodeLDP_32_LDSTPAIR_OFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  // `if L:opc<0> == '01' || opc == '11' then UnallocatedEncoding();`.
  if ((!data.L && (data.opc & 1)) || data.opc == 3) {
    return false;
  }
  if (data.Rt == data.Rt2) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rt);
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rt2);
  AddBasePlusOffsetMemOp(inst, 64, data.Rn, static_cast<uint64_t>(data.imm7.simm7) << 2);
  return true;
}

// LDP  <Xt1>, <Xt2>, [<Xn|SP>{, #<imm>}]
bool TryDecodeLDP_64_LDSTPAIR_OFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  // `if L:opc<0> == '01' || opc == '11' then UnallocatedEncoding();`.
  if ((!data.L && (data.opc & 1)) || data.opc == 3) {
    return false;
  }
  if (data.Rt == data.Rt2) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rt);
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rt2);
  AddBasePlusOffsetMemOp(inst, 128, data.Rn, static_cast<uint64_t>(data.imm7.simm7) << 3);
  return true;
}

// LDR  <Wt>, [<Xn|SP>], #<simm>
bool TryDecodeLDR_32_LDST_IMMPOST(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rt);
  uint64_t offset = static_cast<uint64_t>(data.imm9.simm9);
  AddPostIndexMemOp(inst, 32, data.Rn, offset, data.Rt);
  return true;
}

// LDR  <Xt>, [<Xn|SP>], #<simm>
bool TryDecodeLDR_64_LDST_IMMPOST(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rt);
  uint64_t offset = static_cast<uint64_t>(data.imm9.simm9);
  AddPostIndexMemOp(inst, 64, data.Rn, offset, data.Rt);
  return true;
}

// LDR  <Wt>, [<Xn|SP>, #<simm>]!
bool TryDecodeLDR_32_LDST_IMMPRE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rt);
  uint64_t offset = static_cast<uint64_t>(data.imm9.simm9);
  AddPreIndexMemOp(inst, 32, data.Rn, offset, data.Rt);
  return true;
}

// LDR  <Xt>, [<Xn|SP>, #<simm>]!
bool TryDecodeLDR_64_LDST_IMMPRE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rt);
  uint64_t offset = static_cast<uint64_t>(data.imm9.simm9);
  AddPreIndexMemOp(inst, 64, data.Rn, offset, data.Rt);
  return true;
}

// LDR  <Wt>, [<Xn|SP>{, #<pimm>}]
bool TryDecodeLDR_32_LDST_POS(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 32, data.Rn, data.imm12.uimm << 2);
  return true;
}

// LDR  <Xt>, [<Xn|SP>{, #<pimm>}]
bool TryDecodeLDR_64_LDST_POS(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 64, data.Rn, data.imm12.uimm << 3);
  return true;
}

// LDR  <Wt>, <label>
bool TryDecodeLDR_32_LOADLIT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rt);
  AddPCRegMemOp(inst, static_cast<uint64_t>(data.imm19.simm19) << 2ULL);
  return true;
}

// LDR  <Xt>, <label>
bool TryDecodeLDR_64_LOADLIT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rt);
  AddPCRegMemOp(inst, static_cast<uint64_t>(data.imm19.simm19) << 2ULL);
  return true;
}

static bool TryDecodeLDR_n_LDST_REGOFF(const InstData &data, Instruction &inst,
                                       RegClass val_class) {
  if (!(data.option & 2)) {  // Sub word indexing.
    return false;  // `if option<1> == '0' then UnallocatedEncoding();`.
  }
  unsigned scale = data.size;
  auto shift = (data.S == 1) ? scale : 0U;
  auto extend_type = static_cast<Extend>(data.option);
  auto rclass = ExtendTypeToRegClass(extend_type);
  AddRegOperand(inst, kActionWrite, val_class, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 8U << scale, data.Rn, 0);
  AddExtendRegOperand(inst, rclass, kUseAsValue, data.Rm, extend_type, 64, shift);
  return true;
}

// LDR  <Wt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
bool TryDecodeLDR_32_LDST_REGOFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDR_n_LDST_REGOFF(data, inst, kRegW);
}

// LDR  <Xt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
bool TryDecodeLDR_64_LDST_REGOFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDR_n_LDST_REGOFF(data, inst, kRegX);
}

// STR  <Wt>, [<Xn|SP>], #<simm>
bool TryDecodeSTR_32_LDST_IMMPOST(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt);
  uint64_t offset = static_cast<uint64_t>(data.imm9.simm9);
  AddPostIndexMemOp(inst, 32, data.Rn, offset);
  return true;
}

// STR  <Xt>, [<Xn|SP>], #<simm>
bool TryDecodeSTR_64_LDST_IMMPOST(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rt);
  uint64_t offset = static_cast<uint64_t>(data.imm9.simm9);
  AddPostIndexMemOp(inst, 64, data.Rn, offset);
  return true;
}

// STR  <Bt>, [<Xn|SP>], #<simm>
bool TryDecodeSTR_B_LDST_IMMPOST(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kRegB, kUseAsValue, data.Rt);
  uint64_t offset = static_cast<uint64_t>(data.imm9.simm9);
  AddPostIndexMemOp(inst, 8, data.Rn, offset);
  return true;
}

// STR  <Ht>, [<Xn|SP>], #<simm>
bool TryDecodeSTR_H_LDST_IMMPOST(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kRegH, kUseAsValue, data.Rt);
  uint64_t offset = static_cast<uint64_t>(data.imm9.simm9);
  AddPostIndexMemOp(inst, 16, data.Rn, offset);
  return true;
}

// STR  <St>, [<Xn|SP>], #<simm>
bool TryDecodeSTR_S_LDST_IMMPOST(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kRegS, kUseAsValue, data.Rt);
  uint64_t offset = static_cast<uint64_t>(data.imm9.simm9);
  AddPostIndexMemOp(inst, 32, data.Rn, offset);
  return true;
}

// STR  <Dt>, [<Xn|SP>], #<simm>
bool TryDecodeSTR_D_LDST_IMMPOST(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kRegD, kUseAsValue, data.Rt);
  uint64_t offset = static_cast<uint64_t>(data.imm9.simm9);
  AddPostIndexMemOp(inst, 64, data.Rn, offset);
  return true;
}

// STR  <Qt>, [<Xn|SP>], #<simm>
bool TryDecodeSTR_Q_LDST_IMMPOST(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, K_REG_Q, kUseAsValue, data.Rt);
  uint64_t offset = static_cast<uint64_t>(data.imm9.simm9);
  AddPostIndexMemOp(inst, 128, data.Rn, offset);
  return true;
}

// STR  <Wt>, [<Xn|SP>, #<simm>]!
bool TryDecodeSTR_32_LDST_IMMPRE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt);
  uint64_t offset = static_cast<uint64_t>(data.imm9.simm9);
  AddPreIndexMemOp(inst, 32, data.Rn, offset);
  return true;
}

// STR  <Xt>, [<Xn|SP>, #<simm>]!
bool TryDecodeSTR_64_LDST_IMMPRE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rt);
  uint64_t offset = static_cast<uint64_t>(data.imm9.simm9);
  AddPreIndexMemOp(inst, 64, data.Rn, offset);
  return true;
}

// STR  <Bt>, [<Xn|SP>, #<simm>]!
bool TryDecodeSTR_B_LDST_IMMPRE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kRegB, kUseAsValue, data.Rt);
  uint64_t offset = static_cast<uint64_t>(data.imm9.simm9);
  AddPreIndexMemOp(inst, 8, data.Rn, offset);
  return true;
}

// STR  <Ht>, [<Xn|SP>, #<simm>]!
bool TryDecodeSTR_H_LDST_IMMPRE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kRegH, kUseAsValue, data.Rt);
  uint64_t offset = static_cast<uint64_t>(data.imm9.simm9);
  AddPreIndexMemOp(inst, 16, data.Rn, offset);
  return true;
}

// STR  <St>, [<Xn|SP>, #<simm>]!
bool TryDecodeSTR_S_LDST_IMMPRE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kRegS, kUseAsValue, data.Rt);
  uint64_t offset = static_cast<uint64_t>(data.imm9.simm9);
  AddPreIndexMemOp(inst, 32, data.Rn, offset);
  return true;
}

// STR  <Dt>, [<Xn|SP>, #<simm>]!
bool TryDecodeSTR_D_LDST_IMMPRE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kRegD, kUseAsValue, data.Rt);
  uint64_t offset = static_cast<uint64_t>(data.imm9.simm9);
  AddPreIndexMemOp(inst, 64, data.Rn, offset);
  return true;
}

// STR  <Wt>, [<Xn|SP>{, #<pimm>}]
bool TryDecodeSTR_32_LDST_POS(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 32, data.Rn, data.imm12.uimm << 2 /* size = 2 */);
  return true;
}

// STR  <Xt>, [<Xn|SP>{, #<pimm>}]
bool TryDecodeSTR_64_LDST_POS(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 64, data.Rn, data.imm12.uimm << 3 /* size = 3 */);
  return true;
}

static bool TryDecodeSTR_n_LDST_REGOFF(const InstData &data, Instruction &inst,
                                       RegClass val_class) {
  if (!(data.option & 2)) {  // Sub word indexing.
    return false;  // `if option<1> == '0' then UnallocatedEncoding();`.
  }
  unsigned scale = data.size;
  auto extend_type = static_cast<Extend>(data.option);
  auto shift = data.S ? scale : 0U;
  AddRegOperand(inst, kActionRead, val_class, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 8U << data.size, data.Rn, 0);
  AddExtendRegOperand(inst, ExtendTypeToRegClass(extend_type), kUseAsValue, data.Rm, extend_type,
                      64, shift);
  return true;
}

// STR  <Wt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
bool TryDecodeSTR_32_LDST_REGOFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeSTR_n_LDST_REGOFF(data, inst, kRegW);
}

// STR  <Xt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
bool TryDecodeSTR_64_LDST_REGOFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeSTR_n_LDST_REGOFF(data, inst, kRegX);
}

// STR  <Dt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
bool TryDecodeSTR_D_LDST_REGOFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeSTR_n_LDST_REGOFF(data, inst, kRegD);
}

// SWP  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeSWP_32_MEMOP(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rs);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 32, data.Rn, 0);
  return true;
}

// SWP  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeSWP_64_MEMOP(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rs);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 64, data.Rn, 0);
  return true;
}

// SWPA  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeSWPA_32_MEMOP(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rs);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 32, data.Rn, 0);
  return true;
}

// SWPA  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeSWPA_64_MEMOP(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rs);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 64, data.Rn, 0);
  return true;
}

// SWPL  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeSWPL_32_MEMOP(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rs);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 32, data.Rn, 0);
  return true;
}

// SWPL  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeSWPL_64_MEMOP(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rs);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 64, data.Rn, 0);
  return true;
}

// LDADD  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDADD_32_MEMOP(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rs);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 32, data.Rn, 0);
  return true;
}

// LDADD  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDADD_64_MEMOP(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rs);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 64, data.Rn, 0);
  return true;
}

// LDADDA  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDADDA_32_MEMOP(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rs);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 32, data.Rn, 0);
  return true;
}

// LDADDA  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDADDA_64_MEMOP(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rs);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 64, data.Rn, 0);
  return true;
}

// LDADDL  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDADDL_32_MEMOP(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rs);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 32, data.Rn, 0);
  return true;
}

// LDADDL  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDADDL_64_MEMOP(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rs);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 64, data.Rn, 0);
  return true;
}

// LDADDAL  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDADDAL_32_MEMOP(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rs);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 32, data.Rn, 0);
  return true;
}

// LDADDAL  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDADDAL_64_MEMOP(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rs);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 64, data.Rn, 0);
  return true;
}

// LDSET  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSET_32_MEMOP(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rs);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 32, data.Rn, 0);
  return true;
}

// LDSET  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDSET_64_MEMOP(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rs);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 64, data.Rn, 0);
  return true;
}

// LDSETA  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSETA_32_MEMOP(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rs);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 32, data.Rn, 0);
  return true;
}

// LDSETA  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDSETA_64_MEMOP(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rs);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 64, data.Rn, 0);
  return true;
}

// LDSETL  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSETL_32_MEMOP(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rs);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 32, data.Rn, 0);
  return true;
}

// LDSETL  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDSETL_64_MEMOP(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rs);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 64, data.Rn, 0);
  return true;
}

// LDSETAL  <Ws>, <Wt>, [<Xn|SP>]
bool TryDecodeLDSETAL_32_MEMOP(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rs);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 32, data.Rn, 0);
  return true;
}

// LDSETAL  <Xs>, <Xt>, [<Xn|SP>]
bool TryDecodeLDSETAL_64_MEMOP(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rs);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 64, data.Rn, 0);
  return true;
}

// MOVZ  <Wd>, #<imm>{, LSL #<shift>}
bool TryDecodeMOVZ_32_MOVEWIDE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (data.hw & 2) {  // Also if `sf` is zero (specifies 32-bit operands).
    return false;
  }
  auto shift = static_cast<uint64_t>(data.hw) << 4U;
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rd);
  AddImmOperand(inst, static_cast<uint32_t>(data.imm16.uimm << shift), kUnsigned, 32);
  return true;
}

// MOVZ  <Xd>, #<imm>{, LSL #<shift>}
bool TryDecodeMOVZ_64_MOVEWIDE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  auto shift = static_cast<uint64_t>(data.hw) << 4U;
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rd);
  AddImmOperand(inst, (data.imm16.uimm << shift));
  return true;
}

// MOVK  <Wd>, #<imm>{, LSL #<shift>}
bool TryDecodeMOVK_32_MOVEWIDE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if ((data.hw >> 1) & 1) {
    return false;  // if sf == '0' && hw<1> == '1' then UnallocatedEncoding();
  }
  AddRegOperand(inst, kActionReadWrite, kRegW, kUseAsValue, data.Rd);
  AddImmOperand(inst, data.imm16.uimm, kUnsigned, 16);
  AddImmOperand(inst, data.hw << 4, kUnsigned, 8);  // pos = UInt(hw:'0000');
  return true;
}

// MOVK  <Xd>, #<imm>{, LSL #<shift>}
bool TryDecodeMOVK_64_MOVEWIDE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  AddRegOperand(inst, kActionReadWrite, kRegX, kUseAsValue, data.Rd);
  AddImmOperand(inst, data.imm16.uimm, kUnsigned, 16);
  AddImmOperand(inst, data.hw << 4, kUnsigned, 8);  // pos = UInt(hw:'0000');
  return true;
}

// MOVN  <Wd>, #<imm>{, LSL #<shift>}
bool TryDecodeMOVN_32_MOVEWIDE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if ((data.hw >> 1) & 1) {
    return false;  // if sf == '0' && hw<1> == '1' then UnallocatedEncoding();
  }
  auto shift = static_cast<uint64_t>(data.hw << 4);
  auto imm = data.imm16.uimm << shift;
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rd);
  AddImmOperand(inst, static_cast<uint64_t>(static_cast<uint32_t>(~imm)));
  return true;
}

// MOVN  <Xd>, #<imm>{, LSL #<shift>}
bool TryDecodeMOVN_64_MOVEWIDE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  auto shift = static_cast<uint64_t>(data.hw << 4);
  auto imm = data.imm16.uimm << shift;
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rd);
  AddImmOperand(inst, ~imm);
  return true;
}

// ADR  <Xd>, <label>
bool TryDecodeADR_ONLY_PCRELADDR(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rd);
  AddPCDisp(inst, static_cast<int64_t>(data.immhi_immlo.simm21));
  return true;
}

// ADRP  <Xd>, <label>
bool TryDecodeADRP_ONLY_PCRELADDR(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rd);
  AddPCDisp(inst, static_cast<int64_t>(data.immhi_immlo.simm21) << 12ULL);
  return true;
}

// B  <label>
bool TryDecodeB_ONLY_BRANCH_IMM(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  inst.branch_taken_pc =
      static_cast<uint64_t>(static_cast<int64_t>(inst.pc) + (data.imm26.simm26 << 2ULL));
  inst.branch_taken_arch_name = inst.arch_name;
  return true;
}

// Decode a relative branch target.
// for using `R8W cond`.
static void DecodeCondBranchNotUsingPCArg(Instruction &inst, int64_t disp) {
  // Condition variable.
  Operand cond_op = {};
  cond_op.action = Operand::kActionWrite;
  cond_op.type = Operand::kTypeRegister;
  cond_op.reg.name = "BRANCH_TAKEN";
  cond_op.reg.size = 64;
  cond_op.size = 64;
  inst.operands.push_back(cond_op);

  inst.branch_taken_pc = static_cast<uint64_t>(static_cast<int64_t>(inst.pc) + disp);
  inst.branch_not_taken_pc = inst.next_pc;

  if (inst.branch_taken_pc % 2u) {
    inst.branch_taken_arch_name = ArchName::kArchThumb2LittleEndian;
    inst.branch_taken_pc -= 1u;
  } else {
    inst.branch_taken_arch_name = inst.arch_name;
  }
}

static bool DecodeBranchRegLabelNotUsingPCArg(const InstData &data, Instruction &inst,
                                              RegClass reg_class) {
  DecodeCondBranchNotUsingPCArg(inst, data.imm19.simm19 << 2);
  AddRegOperand(inst, kActionRead, reg_class, kUseAsValue, data.Rt);
  return true;
}

// CBZ  <Wt>, <label>
bool TryDecodeCBZ_32_COMPBRANCH(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return DecodeBranchRegLabelNotUsingPCArg(data, inst, kRegW);
}

// CBZ  <Xt>, <label>
bool TryDecodeCBZ_64_COMPBRANCH(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return DecodeBranchRegLabelNotUsingPCArg(data, inst, kRegX);
}

// CBNZ  <Wt>, <label>
bool TryDecodeCBNZ_32_COMPBRANCH(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return DecodeBranchRegLabelNotUsingPCArg(data, inst, kRegW);
}

// CBNZ  <Xt>, <label>
bool TryDecodeCBNZ_64_COMPBRANCH(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return DecodeBranchRegLabelNotUsingPCArg(data, inst, kRegX);
}

bool DecodeTestBitBranch(const InstData &data, Instruction &inst) {
  uint8_t bit_pos = (data.b5 << 5U) | data.b40;
  AddImmOperand(inst, bit_pos, kUnsigned, 8);
  DecodeCondBranchNotUsingPCArg(inst, data.imm14.simm14 << 2);
  RegClass reg_class;
  if (data.b5 == 1) {
    reg_class = kRegX;
    inst.function += "_64";
  } else {
    reg_class = kRegW;
    inst.function += "_32";
  }
  AddRegOperand(inst, kActionRead, reg_class, kUseAsValue, data.Rt);
  return true;
}

// TBZ  <R><t>, #<imm>, <label>
bool TryDecodeTBZ_ONLY_TESTBRANCH(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return DecodeTestBitBranch(data, inst);
}

// TBNZ  <R><t>, #<imm>, <label>
bool TryDecodeTBNZ_ONLY_TESTBRANCH(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return DecodeTestBitBranch(data, inst);
}

// BL  <label>
bool TryDecodeBL_ONLY_BRANCH_IMM(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  inst.branch_taken_arch_name = inst.arch_name;
  inst.branch_taken_pc =
      static_cast<uint64_t>(static_cast<int64_t>(inst.pc) + (data.imm26.simm26 << 2ULL));
  inst.branch_not_taken_pc = inst.next_pc;
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, RegNum(30));
  AddPCDisp(inst, data.imm26.simm26 << 2LL);
  DecodeFallThroughPC(inst);
  return true;
}

// BR  <Xn>
bool TryDecodeBR_64_BRANCH_REG(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  AddRegOperand(inst, kActionRead, kRegX, kUseAsAddress, data.Rn);
  return true;
}

static bool ShiftImmediate(uint64_t &value, uint8_t shift) {
  switch (shift) {
    case 0:  // Shift 0 to left.
      break;
    case 1:  // Shift left 12 bits.
      value = value << 12;
      break;
    default: LOG(ERROR) << "Decoding reserved bit for shift value."; return false;
  }
  return true;
}

// ADD  <Wd|WSP>, <Wn|WSP>, #<imm>{, <shift>}
bool TryDecodeADD_32_ADDSUB_IMM(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  auto imm = data.imm12.uimm;
  if (!ShiftImmediate(imm, data.shift)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsAddress, data.Rd);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsAddress, data.Rn);
  AddImmOperand(inst, imm);
  return true;
}

// ADD  <Xd|SP>, <Xn|SP>, #<imm>{, <shift>}
bool TryDecodeADD_64_ADDSUB_IMM(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  auto imm = data.imm12.uimm;
  if (!ShiftImmediate(imm, data.shift)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsAddress, data.Rd);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsAddress, data.Rn);
  AddImmOperand(inst, imm);
  return true;
}

// ADD  <Wd>, <Wn>, <Wm>{, <shift> #<amount>}
bool TryDecodeADD_32_ADDSUB_SHIFT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (1 & (data.imm6.uimm >> 5)) {
    return false;  // `if sf == '0' && imm6<5> == '1' then ReservedValue();`.
  }
  auto shift_type = static_cast<Shift>(data.shift);
  if (shift_type == kShiftROR) {
    return false;  // Shift type '11' is a reserved value.
  }
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rn);
  AddShiftRegOperand(inst, kRegW, kUseAsValue, data.Rm, shift_type, data.imm6.uimm);
  return true;
}

// ADD  <Xd>, <Xn>, <Xm>{, <shift> #<amount>}
bool TryDecodeADD_64_ADDSUB_SHIFT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  auto shift_type = static_cast<Shift>(data.shift);
  if (shift_type == kShiftROR) {
    return false;  // Shift type '11' is a reserved value.
  }
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rn);
  AddShiftRegOperand(inst, kRegX, kUseAsValue, data.Rm, shift_type, data.imm6.uimm);
  return true;
}

// ADD  <Wd|WSP>, <Wn|WSP>, <Wm>{, <extend> {#<amount>}}
bool TryDecodeADD_32_ADDSUB_EXT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  auto extend_type = static_cast<Extend>(data.option);
  auto shift = data.imm3.uimm;
  if (shift > 4) {
    return false;  // `if shift > 4 then ReservedValue();`.
  }
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsAddress, data.Rd);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsAddress, data.Rn);
  AddExtendRegOperand(inst, kRegW, kUseAsValue, data.Rm, extend_type, 32, shift);
  return true;
}

// ADD  <Xd|SP>, <Xn|SP>, <R><m>{, <extend> {#<amount>}}
bool TryDecodeADD_64_ADDSUB_EXT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  auto extend_type = static_cast<Extend>(data.option);
  auto shift = data.imm3.uimm;
  if (shift > 4) {
    return false;  // `if shift > 4 then ReservedValue();`.
  }
  auto reg_class = ExtendTypeToRegClass(extend_type);
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsAddress, data.Rd);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsAddress, data.Rn);
  AddExtendRegOperand(inst, reg_class, kUseAsValue, data.Rm, extend_type, 64, shift);
  return true;
}

// SUB  <Wd|WSP>, <Wn|WSP>, #<imm>{, <shift>}
bool TryDecodeSUB_32_ADDSUB_IMM(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeADD_32_ADDSUB_IMM(data, inst);
}

// SUB  <Xd|SP>, <Xn|SP>, #<imm>{, <shift>}
bool TryDecodeSUB_64_ADDSUB_IMM(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeADD_64_ADDSUB_IMM(data, inst);
}

// SUB  <Wd>, <Wn>, <Wm>{, <shift> #<amount>}
bool TryDecodeSUB_32_ADDSUB_SHIFT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeADD_32_ADDSUB_SHIFT(data, inst);
}

// SUB  <Xd>, <Xn>, <Xm>{, <shift> #<amount>}
bool TryDecodeSUB_64_ADDSUB_SHIFT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeADD_64_ADDSUB_SHIFT(data, inst);
}

// SUB  <Wd|WSP>, <Wn|WSP>, <Wm>{, <extend> {#<amount>}}
bool TryDecodeSUB_32_ADDSUB_EXT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeADD_32_ADDSUB_EXT(data, inst);
}

// SUB  <Xd|SP>, <Xn|SP>, <R><m>{, <extend> {#<amount>}}
bool TryDecodeSUB_64_ADDSUB_EXT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeADD_64_ADDSUB_EXT(data, inst);
}

// SUBS  <Wd>, <Wn>, <Wm>{, <shift> #<amount>}
bool TryDecodeSUBS_32_ADDSUB_SHIFT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  auto shift_type = static_cast<Shift>(data.shift);
  if (shift_type == kShiftROR) {
    return false;  // Shift type '11' is a reserved value.
  } else if ((data.imm6.uimm >> 5) & 1) {
    return false;  // `if sf == '0' && imm6<5> == '1' then ReservedValue();`.
  }
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rn);
  AddShiftRegOperand(inst, kRegW, kUseAsValue, data.Rm, shift_type, data.imm6.uimm);
  AddEcvNZCVOperand(inst, kActionWrite);
  return true;
}

// SUBS  <Xd>, <Xn>, <Xm>{, <shift> #<amount>}
bool TryDecodeSUBS_64_ADDSUB_SHIFT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  auto shift_type = static_cast<Shift>(data.shift);
  if (shift_type == kShiftROR) {
    return false;  // Shift type '11' is a reserved value.
  }
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rn);
  AddShiftRegOperand(inst, kRegX, kUseAsValue, data.Rm, shift_type, data.imm6.uimm);
  AddEcvNZCVOperand(inst, kActionWrite);
  return true;
}

// SUBS  <Wd>, <Wn|WSP>, #<imm>{, <shift>}
bool TryDecodeSUBS_32S_ADDSUB_IMM(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  auto imm = data.imm12.uimm;
  if (!ShiftImmediate(imm, data.shift)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsAddress, data.Rn);
  AddImmOperand(inst, imm);
  AddEcvNZCVOperand(inst, kActionWrite);
  return true;
}

// SUBS  <Xd>, <Xn|SP>, #<imm>{, <shift>}
bool TryDecodeSUBS_64S_ADDSUB_IMM(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  auto imm = data.imm12.uimm;
  if (!ShiftImmediate(imm, data.shift)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsAddress, data.Rn);
  AddImmOperand(inst, imm);
  AddEcvNZCVOperand(inst, kActionWrite);
  return true;
}

// SUBS  <Wd>, <Wn|WSP>, <Wm>{, <extend> {#<amount>}}
bool TryDecodeSUBS_32S_ADDSUB_EXT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  auto extend_type = static_cast<Extend>(data.option);
  auto shift = data.imm3.uimm;
  if (shift > 4) {
    return false;  // `if shift > 4 then ReservedValue();`.
  }
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsAddress, data.Rn);
  AddExtendRegOperand(inst, kRegW, kUseAsValue, data.Rm, extend_type, 32, shift);
  AddEcvNZCVOperand(inst, kActionWrite);
  return true;
}

// SUBS  <Xd>, <Xn|SP>, <R><m>{, <extend> {#<amount>}}
bool TryDecodeSUBS_64S_ADDSUB_EXT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  auto extend_type = static_cast<Extend>(data.option);
  auto shift = data.imm3.uimm;
  if (shift > 4) {
    return false;  // `if shift > 4 then ReservedValue();`.
  }
  auto reg_class = ExtendTypeToRegClass(extend_type);
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsAddress, data.Rn);
  AddExtendRegOperand(inst, reg_class, kUseAsValue, data.Rm, extend_type, 64, shift);
  AddEcvNZCVOperand(inst, kActionWrite);
  return true;
}

// ADDS  <Wd>, <Wn|WSP>, #<imm>{, <shift>}
bool TryDecodeADDS_32S_ADDSUB_IMM(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeSUBS_32S_ADDSUB_IMM(data, inst);
}

// ADDS  <Xd>, <Xn|SP>, #<imm>{, <shift>}
bool TryDecodeADDS_64S_ADDSUB_IMM(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeSUBS_64S_ADDSUB_IMM(data, inst);
}

// ADDS  <Wd>, <Wn>, <Wm>{, <shift> #<amount>}
bool TryDecodeADDS_32_ADDSUB_SHIFT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeSUBS_32_ADDSUB_SHIFT(data, inst);
}

// ADDS  <Xd>, <Xn>, <Xm>{, <shift> #<amount>}
bool TryDecodeADDS_64_ADDSUB_SHIFT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeSUBS_64_ADDSUB_SHIFT(data, inst);
}

// ADDS  <Wd>, <Wn|WSP>, <Wm>{, <extend> {#<amount>}}
bool TryDecodeADDS_32S_ADDSUB_EXT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeSUBS_32S_ADDSUB_EXT(data, inst);
}

// ADDS  <Xd>, <Xn|SP>, <R><m>{, <extend> {#<amount>}}
bool TryDecodeADDS_64S_ADDSUB_EXT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeSUBS_64S_ADDSUB_EXT(data, inst);
}

static const char *kCondName[] = {"EQ", "CS", "MI", "VS", "HI", "GE", "GT", "AL"};

static const char *kNegCondName[] = {"NE", "CC", "PL", "VC", "LS", "LT", "LE", "AL"};

static const char *CondName(uint8_t cond) {
  if (cond & 1) {
    return kNegCondName[(cond >> 1) & 0x7];
  } else {
    return kCondName[(cond >> 1) & 0x7];
  }
}

// `if option<1> == '0' then UnallocatedEncoding();`
static bool IsSubWordIndex(const InstData &data) {
  return !(data.option & 0x2);
}

static void SetConditionalFunctionName(const InstData &data, Instruction &inst,
                                       bool invert_condition = false) {
  uint8_t cond = 0;
  if (invert_condition) {
    cond = data.cond ^ 1;
  } else {
    cond = data.cond;
  }

  std::stringstream ss;
  ss << inst.function << "_" << CondName(cond);
  inst.function = ss.str();
}

// B.<cond>  <label>
bool TryDecodeB_ONLY_CONDBRANCH(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  // Add in the condition to the isel name.
  SetConditionalFunctionName(data, inst);
  DecodeCondBranchNotUsingPCArg(inst, data.imm19.simm19 << 2);
  AddEcvNZCVOperand(inst, kActionRead);
  return true;
}

// STRB  <Wt>, [<Xn|SP>{, #<pimm>}]
bool TryDecodeSTRB_32_LDST_POS(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 8, data.Rn, data.imm12.uimm);
  return true;
}

// STRB  <Wt>, [<Xn|SP>], #<simm>
bool TryDecodeSTRB_32_LDST_IMMPOST(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt);
  uint64_t offset = static_cast<uint64_t>(data.imm9.simm9);
  AddPostIndexMemOp(inst, 8, data.Rn, offset, data.Rt);
  return true;
}

// STRB  <Wt>, [<Xn|SP>, #<simm>]!
bool TryDecodeSTRB_32_LDST_IMMPRE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt);
  uint64_t offset = static_cast<uint64_t>(data.imm9.simm9);
  AddPreIndexMemOp(inst, 8, data.Rn, offset, data.Rt);
  return true;
}

// STRB  <Wt>, [<Xn|SP>, (<Wm>|<Xm>), <extend> {<amount>}]
bool TryDecodeSTRB_32B_LDST_REGOFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  if (IsSubWordIndex(data)) {
    return false;
  }
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt);
  AddWriteRegMemOperand(inst, kRegX, kUseAsAddress, data.Rn);
  auto extend_type = static_cast<Extend>(data.option);
  auto rclass = ExtendTypeToRegClass(extend_type);
  AddExtendRegOperand(inst, rclass, kUseAsValue, data.Rm, extend_type, 64, 0);
  return true;
}

// STRB  <Wt>, [<Xn|SP>, <Xm>{, LSL <amount>}]
bool TryDecodeSTRB_32BL_LDST_REGOFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  if (IsSubWordIndex(data)) {  // Sub-word index.
    return false;  // `if option<1> == '0' then UnallocatedEncoding();`
  }
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt);
  AddWriteRegMemOperand(inst, kRegX, kUseAsAddress, data.Rn);
  AddShiftRegOperand(inst, kRegX, kUseAsValue, data.Rm, kShiftLSL, 0);
  return true;
}

static bool TryDecodeLDRn_m_LDST_REGOFF(const InstData &data, Instruction &inst,
                                        RegClass dest_rclass, uint64_t scale) {
  if (IsSubWordIndex(data)) {  // Sub-word index.
    return false;  // `if option<1> == '0' then UnallocatedEncoding();`
  }
  AddRegOperand(inst, kActionWrite, dest_rclass, kUseAsValue, data.Rt);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsAddress, data.Rn);
  auto extend_type = static_cast<Extend>(data.option);
  auto rclass = ExtendTypeToRegClass(extend_type);
  AddExtendRegOperand(inst, rclass, kUseAsValue, data.Rm, extend_type, 64, data.S * scale);
  return true;
}

// LDRB  <Wt>, [<Xn|SP>, (<Wm>|<Xm>), <extend> {<amount>}]
bool TryDecodeLDRB_32B_LDST_REGOFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDRn_m_LDST_REGOFF(data, inst, kRegW, 0);
}

// LDRB  <Wt>, [<Xn|SP>, <Xm>{, LSL <amount>}]
bool TryDecodeLDRB_32BL_LDST_REGOFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  if (IsSubWordIndex(data)) {  // Sub-word index.
    return false;  // `if option<1> == '0' then UnallocatedEncoding();`
  }
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rt);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsAddress, data.Rn);
  AddShiftRegOperand(inst, kRegX, kUseAsValue, data.Rm, kShiftLSL, 0);
  return true;
}

// LDRH  <Wt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
bool TryDecodeLDRH_32_LDST_REGOFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDRn_m_LDST_REGOFF(data, inst, kRegW, 1);
}

// STRH  <Wt>, [<Xn|SP>{, #<pimm>}]
bool TryDecodeSTRH_32_LDST_POS(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 16, data.Rn, data.imm12.uimm << 1);
  return true;
}

static bool TryDecodeSTRn_m_LDST_REGOFF(const InstData &data, Instruction &inst,
                                        RegClass dest_rclass) {
  uint64_t scale = DecodeScale(data);
  if (scale > 4 || IsSubWordIndex(data)) {  // Sub-word index.
    return false;  // `if option<1> == '0' then UnallocatedEncoding();`
  }
  auto shift = (data.S == 1) ? scale : 0U;
  auto extend_type = static_cast<Extend>(data.option);
  auto rclass = ExtendTypeToRegClass(extend_type);
  AddRegOperand(inst, kActionRead, dest_rclass, kUseAsValue, data.Rt);
  AddWriteRegMemOperand(inst, kRegX, kUseAsAddress, data.Rn);
  AddExtendRegOperand(inst, rclass, kUseAsValue, data.Rm, extend_type, 64, shift);
  return true;
}

// STRH  <Wt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
bool TryDecodeSTRH_32_LDST_REGOFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeSTRn_m_LDST_REGOFF(data, inst, kRegW);
}

// STRH  <Wt>, [<Xn|SP>, #<simm>]!
bool TryDecodeSTRH_32_LDST_IMMPRE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt);
  uint64_t offset = static_cast<uint64_t>(data.imm9.simm9);
  AddPreIndexMemOp(inst, 16, data.Rn, offset, data.Rt);
  return true;
}

// STRH  <Wt>, [<Xn|SP>], #<simm>
bool TryDecodeSTRH_32_LDST_IMMPOST(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt);
  uint64_t offset = static_cast<uint64_t>(data.imm9.simm9);
  AddPostIndexMemOp(inst, 16, data.Rn, offset, data.Rt);
  return true;
}

// NOP
bool TryDecodeNOP_HI_SYSTEM(const InstData &, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return true;
}

// ORN  <Wd>, <Wn>, <Wm>{, <shift> #<amount>}
bool TryDecodeORN_32_LOG_SHIFT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeEOR_32_LOG_SHIFT(data, inst);
}

// ORN  <Xd>, <Xn>, <Xm>{, <shift> #<amount>}
bool TryDecodeORN_64_LOG_SHIFT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeEOR_64_LOG_SHIFT(data, inst);
}

// EON  <Wd>, <Wn>, <Wm>{, <shift> #<amount>}
bool TryDecodeEON_32_LOG_SHIFT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeEOR_32_LOG_SHIFT(data, inst);
}

// EON  <Xd>, <Xn>, <Xm>{, <shift> #<amount>}
bool TryDecodeEON_64_LOG_SHIFT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeEOR_64_LOG_SHIFT(data, inst);
}

// EOR  <Wd>, <Wn>, <Wm>{, <shift> #<amount>}
bool TryDecodeEOR_32_LOG_SHIFT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (1 & (data.imm6.uimm >> 5)) {
    return false;  // `if sf == '0' && imm6<5> == '1' then ReservedValue();`.
  }
  TryDecodeRdW_Rn(data, inst, kRegW);
  AddShiftRegOperand(inst, kRegW, kUseAsValue, data.Rm, static_cast<Shift>(data.shift),
                     data.imm6.uimm);
  return true;
}

// EOR  <Xd>, <Xn>, <Xm>{, <shift> #<amount>}
bool TryDecodeEOR_64_LOG_SHIFT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  TryDecodeRdW_Rn(data, inst, kRegX);
  AddShiftRegOperand(inst, kRegX, kUseAsValue, data.Rm, static_cast<Shift>(data.shift),
                     data.imm6.uimm);
  return true;
}

// EOR  <Wd|WSP>, <Wn>, #<imm>
bool TryDecodeEOR_32_LOG_IMM(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  uint64_t wmask = 0;
  if (data.N) {
    return false;  // `if sf == '0' && N != '0' then ReservedValue();`.
  }
  if (!DecodeBitMasks(data.N, data.imms.uimm, data.immr.uimm, true, 32, &wmask)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsAddress, data.Rd);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rn);
  AddImmOperand(inst, wmask, kUnsigned, 32);
  return true;
}

// EOR  <Xd|SP>, <Xn>, #<imm>
bool TryDecodeEOR_64_LOG_IMM(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  uint64_t wmask = 0;
  if (!DecodeBitMasks(data.N, data.imms.uimm, data.immr.uimm, true, 64, &wmask)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsAddress, data.Rd);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rn);
  AddImmOperand(inst, wmask, kUnsigned, 64);
  return true;
}

// AND  <Wd|WSP>, <Wn>, #<imm>
bool TryDecodeAND_32_LOG_IMM(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeEOR_32_LOG_IMM(data, inst);
}

// AND  <Xd|SP>, <Xn>, #<imm>
bool TryDecodeAND_64_LOG_IMM(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeEOR_64_LOG_IMM(data, inst);
}

// AND  <Wd>, <Wn>, <Wm>{, <shift> #<amount>}
bool TryDecodeAND_32_LOG_SHIFT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeEOR_32_LOG_SHIFT(data, inst);
}

// AND  <Xd>, <Xn>, <Xm>{, <shift> #<amount>}
bool TryDecodeAND_64_LOG_SHIFT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeEOR_64_LOG_SHIFT(data, inst);
}

// ORR  <Wd|WSP>, <Wn>, #<imm>
bool TryDecodeORR_32_LOG_IMM(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeEOR_32_LOG_IMM(data, inst);
}

// ORR  <Xd|SP>, <Xn>, #<imm>
bool TryDecodeORR_64_LOG_IMM(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeEOR_64_LOG_IMM(data, inst);
}

// ORR  <Wd>, <Wn>, <Wm>{, <shift> #<amount>}
bool TryDecodeORR_32_LOG_SHIFT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeEOR_32_LOG_SHIFT(data, inst);
}

// ORR  <Xd>, <Xn>, <Xm>{, <shift> #<amount>}
bool TryDecodeORR_64_LOG_SHIFT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeEOR_64_LOG_SHIFT(data, inst);
}

// BIC  <Wd>, <Wn>, <Wm>{, <shift> #<amount>}
bool TryDecodeBIC_32_LOG_SHIFT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeEOR_32_LOG_SHIFT(data, inst);
}

// BIC  <Xd>, <Xn>, <Xm>{, <shift> #<amount>}
bool TryDecodeBIC_64_LOG_SHIFT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeEOR_64_LOG_SHIFT(data, inst);
}

static bool TryDecodeLDUR_Vn_LDST_UNSCALED(const InstData &data, Instruction &inst,
                                           RegClass val_class) {
  uint64_t scale = DecodeScale(data);
  if (scale > 4) {
    return false;
  }
  auto num_bits = ReadRegSize(val_class);
  AddRegOperand(inst, kActionWrite, val_class, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, num_bits, data.Rn, static_cast<uint64_t>(data.imm9.simm9));
  return true;
}

// LDUR  <Bt>, [<Xn|SP>{, #<simm>}]
bool TryDecodeLDUR_B_LDST_UNSCALED(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDUR_Vn_LDST_UNSCALED(data, inst, kRegB);
}

// LDUR  <Ht>, [<Xn|SP>{, #<simm>}]
bool TryDecodeLDUR_H_LDST_UNSCALED(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDUR_Vn_LDST_UNSCALED(data, inst, kRegH);
}

// LDUR  <St>, [<Xn|SP>{, #<simm>}]
bool TryDecodeLDUR_S_LDST_UNSCALED(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDUR_Vn_LDST_UNSCALED(data, inst, kRegS);
}

// LDUR  <Dt>, [<Xn|SP>{, #<simm>}]
bool TryDecodeLDUR_D_LDST_UNSCALED(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDUR_Vn_LDST_UNSCALED(data, inst, kRegD);
}

// LDUR  <Qt>, [<Xn|SP>{, #<simm>}]
bool TryDecodeLDUR_Q_LDST_UNSCALED(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDUR_Vn_LDST_UNSCALED(data, inst, K_REG_Q);
}

static bool TryDecodeLDUR_n_LDST_UNSCALED(const InstData &data, Instruction &inst, RegClass rclass,
                                          uint64_t mem_size) {
  AddRegOperand(inst, kActionWrite, rclass, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, mem_size, data.Rn, static_cast<uint64_t>(data.imm9.simm9));
  return true;
}

// LDURB  <Wt>, [<Xn|SP>{, #<simm>}]
bool TryDecodeLDURB_32_LDST_UNSCALED(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDUR_n_LDST_UNSCALED(data, inst, kRegW, 8);
}

// LDURSB  <Wt>, [<Xn|SP>{, #<simm>}]
bool TryDecodeLDURSB_32_LDST_UNSCALED(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDUR_n_LDST_UNSCALED(data, inst, kRegW, 8);
}

// LDURH  <Wt>, [<Xn|SP>{, #<simm>}]
bool TryDecodeLDURH_32_LDST_UNSCALED(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDUR_n_LDST_UNSCALED(data, inst, kRegW, 16);
}

// LDURSH  <Wt>, [<Xn|SP>{, #<simm>}]
bool TryDecodeLDURSH_32_LDST_UNSCALED(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDUR_n_LDST_UNSCALED(data, inst, kRegW, 16);
}

// LDUR  <Wt>, [<Xn|SP>{, #<simm>}]
bool TryDecodeLDUR_32_LDST_UNSCALED(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDUR_n_LDST_UNSCALED(data, inst, kRegW, 32);
}

// LDUR  <Xt>, [<Xn|SP>{, #<simm>}]
bool TryDecodeLDUR_64_LDST_UNSCALED(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDUR_n_LDST_UNSCALED(data, inst, kRegX, 64);
}

// LDURSH  <Xt>, [<Xn|SP>{, #<simm>}]
bool TryDecodeLDURSH_64_LDST_UNSCALED(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDUR_n_LDST_UNSCALED(data, inst, kRegX, 16);
}

// LDURSW  <Xt>, [<Xn|SP>{, #<simm>}]
bool TryDecodeLDURSW_64_LDST_UNSCALED(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDUR_n_LDST_UNSCALED(data, inst, kRegX, 64);
}

static bool TryDecodeSTUR_Vn_LDST_UNSCALED(const InstData &data, Instruction &inst,
                                           RegClass val_class) {
  uint64_t scale = DecodeScale(data);
  if (scale > 4) {
    return false;
  }
  auto num_bits = ReadRegSize(val_class);
  AddRegOperand(inst, kActionRead, val_class, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, num_bits, data.Rn, static_cast<uint64_t>(data.imm9.simm9));
  return true;
}

// STUR  <Bt>, [<Xn|SP>{, #<simm>}]
bool TryDecodeSTUR_B_LDST_UNSCALED(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeSTUR_Vn_LDST_UNSCALED(data, inst, kRegB);
}

// STUR  <Ht>, [<Xn|SP>{, #<simm>}]
bool TryDecodeSTUR_H_LDST_UNSCALED(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeSTUR_Vn_LDST_UNSCALED(data, inst, kRegH);
}

// STUR  <St>, [<Xn|SP>{, #<simm>}]
bool TryDecodeSTUR_S_LDST_UNSCALED(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeSTUR_Vn_LDST_UNSCALED(data, inst, kRegS);
}

// STUR  <Dt>, [<Xn|SP>{, #<simm>}]
bool TryDecodeSTUR_D_LDST_UNSCALED(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeSTUR_Vn_LDST_UNSCALED(data, inst, kRegD);
}

// STUR  <Qt>, [<Xn|SP>{, #<simm>}]
bool TryDecodeSTUR_Q_LDST_UNSCALED(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeSTUR_Vn_LDST_UNSCALED(data, inst, K_REG_Q);
}

static bool TryDecodeSTUR_n_LDST_UNSCALED(const InstData &data, Instruction &inst, RegClass rclass,
                                          uint64_t mem_size) {
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, mem_size, data.Rn, static_cast<uint64_t>(data.imm9.simm9));
  return true;
}

// STURB  <Wt>, [<Xn|SP>{, #<simm>}]
bool TryDecodeSTURB_32_LDST_UNSCALED(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeSTUR_n_LDST_UNSCALED(data, inst, kRegW, 8);
}

// STURH  <Wt>, [<Xn|SP>{, #<simm>}]
bool TryDecodeSTURH_32_LDST_UNSCALED(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeSTUR_n_LDST_UNSCALED(data, inst, kRegW, 16);
}

// STUR  <Wt>, [<Xn|SP>{, #<simm>}]
bool TryDecodeSTUR_32_LDST_UNSCALED(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeSTUR_n_LDST_UNSCALED(data, inst, kRegW, 32);
}

// STUR  <Xt>, [<Xn|SP>{, #<simm>}]
bool TryDecodeSTUR_64_LDST_UNSCALED(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeSTUR_n_LDST_UNSCALED(data, inst, kRegX, 64);
}

static bool TryDecodeLDRSn_m_LDST_IMMPOST(const InstData &data, Instruction &inst, RegClass rclass,
                                          uint64_t mem_size) {
  AddRegOperand(inst, kActionWrite, rclass, kUseAsValue, data.Rt);
  AddPostIndexMemOp(inst, mem_size, data.Rn, static_cast<uint64_t>(data.imm9.simm9), data.Rt);
  return true;
}

// LDRB  <Wt>, [<Xn|SP>], #<simm>
bool TryDecodeLDRB_32_LDST_IMMPOST(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDRSB_32_LDST_IMMPOST(data, inst);
}

// LDRSB  <Wt>, [<Xn|SP>], #<simm>
bool TryDecodeLDRSB_32_LDST_IMMPOST(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDRSn_m_LDST_IMMPOST(data, inst, kRegW, 8);
}

// LDRSB  <Xt>, [<Xn|SP>], #<simm>
bool TryDecodeLDRSB_64_LDST_IMMPOST(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDRSn_m_LDST_IMMPOST(data, inst, kRegX, 8);
}

// LDRH  <Wt>, [<Xn|SP>], #<simm>
bool TryDecodeLDRH_32_LDST_IMMPOST(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDRSH_32_LDST_IMMPOST(data, inst);
}

// LDRSH  <Wt>, [<Xn|SP>], #<simm>
bool TryDecodeLDRSH_32_LDST_IMMPOST(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDRSn_m_LDST_IMMPOST(data, inst, kRegW, 16);
}

// LDRSH  <Xt>, [<Xn|SP>], #<simm>
bool TryDecodeLDRSH_64_LDST_IMMPOST(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDRSn_m_LDST_IMMPOST(data, inst, kRegX, 16);
}

// LDRSW  <Xt>, [<Xn|SP>], #<simm>
bool TryDecodeLDRSW_64_LDST_IMMPOST(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDRSn_m_LDST_IMMPOST(data, inst, kRegX, 32);
}

static bool TryDecodeLDRSn_m_LDST_IMMPRE(const InstData &data, Instruction &inst, RegClass rclass,
                                         uint64_t mem_size) {
  AddRegOperand(inst, kActionWrite, rclass, kUseAsValue, data.Rt);
  AddPreIndexMemOp(inst, mem_size, data.Rn, static_cast<uint64_t>(data.imm9.simm9), data.Rt);
  return true;
}

// LDRB  <Wt>, [<Xn|SP>, #<simm>]!
bool TryDecodeLDRB_32_LDST_IMMPRE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDRSB_32_LDST_IMMPRE(data, inst);
}

// LDRSB  <Wt>, [<Xn|SP>, #<simm>]!
bool TryDecodeLDRSB_32_LDST_IMMPRE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDRSn_m_LDST_IMMPRE(data, inst, kRegW, 8);
}

// LDRSB  <Xt>, [<Xn|SP>, #<simm>]!
bool TryDecodeLDRSB_64_LDST_IMMPRE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDRSn_m_LDST_IMMPRE(data, inst, kRegX, 8);
}

// LDRH  <Wt>, [<Xn|SP>, #<simm>]!
bool TryDecodeLDRH_32_LDST_IMMPRE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDRSH_32_LDST_IMMPRE(data, inst);
}

// LDRSH  <Wt>, [<Xn|SP>, #<simm>]!
bool TryDecodeLDRSH_32_LDST_IMMPRE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDRSn_m_LDST_IMMPRE(data, inst, kRegW, 16);
}

// LDRSH  <Xt>, [<Xn|SP>, #<simm>]!
bool TryDecodeLDRSH_64_LDST_IMMPRE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDRSn_m_LDST_IMMPRE(data, inst, kRegX, 16);
}

// LDRSW  <Xt>, [<Xn|SP>, #<simm>]!
bool TryDecodeLDRSW_64_LDST_IMMPRE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDRSn_m_LDST_IMMPRE(data, inst, kRegX, 32);
}

static bool TryDecodeLDRSn_m_LDST_POS(const InstData &data, Instruction &inst, RegClass rclass,
                                      uint64_t mem_size, uint64_t scale) {
  AddRegOperand(inst, kActionWrite, rclass, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, mem_size, data.Rn, data.imm12.uimm << scale);
  return true;
}

// LDRB  <Wt>, [<Xn|SP>{, #<pimm>}]
bool TryDecodeLDRB_32_LDST_POS(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDRSB_32_LDST_POS(data, inst);
}

// LDRSB  <Wt>, [<Xn|SP>{, #<pimm>}]
bool TryDecodeLDRSB_32_LDST_POS(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDRSn_m_LDST_POS(data, inst, kRegW, 8, 0);
}

// LDRSB  <Xt>, [<Xn|SP>{, #<pimm>}]
bool TryDecodeLDRSB_64_LDST_POS(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDRSn_m_LDST_POS(data, inst, kRegX, 8, 0);
}

// LDRH  <Wt>, [<Xn|SP>{, #<pimm>}]
bool TryDecodeLDRH_32_LDST_POS(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDRSH_32_LDST_POS(data, inst);
}

// LDRSH  <Wt>, [<Xn|SP>{, #<pimm>}]
bool TryDecodeLDRSH_32_LDST_POS(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDRSn_m_LDST_POS(data, inst, kRegW, 16, 1);
}

// LDRSH  <Xt>, [<Xn|SP>{, #<pimm>}]
bool TryDecodeLDRSH_64_LDST_POS(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDRSn_m_LDST_POS(data, inst, kRegX, 16, 1);
}

// LDRSW  <Xt>, [<Xn|SP>{, #<pimm>}]
bool TryDecodeLDRSW_64_LDST_POS(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDRSn_m_LDST_POS(data, inst, kRegX, 32, 2);
}

// LDRSB  <Wt>, [<Xn|SP>, (<Wm>|<Xm>), <extend> {<amount>}]
bool TryDecodeLDRSB_32B_LDST_REGOFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDRn_m_LDST_REGOFF(data, inst, kRegW, 0);
}

// LDRSB  <Wt>, [<Xn|SP>, <Xm>{, LSL <amount>}]
bool TryDecodeLDRSB_32BL_LDST_REGOFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDRB_32BL_LDST_REGOFF(data, inst);
}

// LDRSB  <Xt>, [<Xn|SP>, (<Wm>|<Xm>), <extend> {<amount>}]
bool TryDecodeLDRSB_64B_LDST_REGOFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDRn_m_LDST_REGOFF(data, inst, kRegX, 0);
}

// LDRSB  <Xt>, [<Xn|SP>, <Xm>{, LSL <amount>}]
bool TryDecodeLDRSB_64BL_LDST_REGOFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  // NOTE(pag): This decoder specifies `Wt` as the dest reg, but it will be
  //            converted into `Xt` because writes to `W` regs affect the whole
  //            `X` reg.
  return TryDecodeLDRB_32BL_LDST_REGOFF(data, inst);
}

// LDRSH  <Wt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
bool TryDecodeLDRSH_32_LDST_REGOFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDRn_m_LDST_REGOFF(data, inst, kRegW, 1);
}

// LDRSH  <Xt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
bool TryDecodeLDRSH_64_LDST_REGOFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDRn_m_LDST_REGOFF(data, inst, kRegX, 1);
}

// LDRSW  <Xt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
bool TryDecodeLDRSW_64_LDST_REGOFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDRn_m_LDST_REGOFF(data, inst, kRegX, 2);
}

// LDRSW  <Xt>, <label>
bool TryDecodeLDRSW_64_LOADLIT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDR_64_LOADLIT(data, inst);
}

// ADC  <Wd>, <Wn>, <Wm>
bool TryDecodeADC_32_ADDSUB_CARRY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rn);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rm);
  AddEcvNZCVOperand(inst, kActionRead);
  return true;
}

// ADC  <Xd>, <Xn>, <Xm>
bool TryDecodeADC_64_ADDSUB_CARRY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rn);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rm);
  AddEcvNZCVOperand(inst, kActionRead);
  return true;
}

// HINT  #<imm>
bool TryDecodeHINT_1(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return true;  // NOP.
}

// HINT  #<imm>
bool TryDecodeHINT_2(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return true;  // NOP.
}

// HINT  #<imm>
bool TryDecodeHINT_3(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return true;  // NOP.
}

// UMADDL  <Xd>, <Wn>, <Wm>, <Xa>
bool TryDecodeUMADDL_64WA_DP_3SRC(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rn);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rm);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Ra);
  return true;
}

// UMSUBL  <Xd>, <Wn>, <Wm>, <Xa>
bool TryDecodeUMSUBL_64WA_DP_3SRC(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rn);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rm);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Ra);
  return true;
}

// UMULH  <Xd>, <Xn>, <Xm>
bool TryDecodeUMULH_64_DP_3SRC(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeRdW_Rn_Rm(data, inst, kRegX);
}

// SMADDL  <Xd>, <Wn>, <Wm>, <Xa>
bool TryDecodeSMADDL_64WA_DP_3SRC(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeUMADDL_64WA_DP_3SRC(data, inst);
}

// SMULH  <Xd>, <Xn>, <Xm>
bool TryDecodeSMULH_64_DP_3SRC(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeUMULH_64_DP_3SRC(data, inst);
}

// UDIV  <Wd>, <Wn>, <Wm>
bool TryDecodeUDIV_32_DP_2SRC(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeRdW_Rn_Rm(data, inst, kRegW);
}

// UDIV  <Xd>, <Xn>, <Xm>
bool TryDecodeUDIV_64_DP_2SRC(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeRdW_Rn_Rm(data, inst, kRegX);
}

// UBFM  <Wd>, <Wn>, #<immr>, #<imms>
bool TryDecodeUBFM_32M_BITFIELD(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  // if sf == '0' && (N != '0' || immr<5> != '0' || imms<5> != '0')
  //    then ReservedValue();
  if (data.N || (data.immr.uimm & 0x20) || (data.imms.uimm & 0x20)) {
    return false;
  }

  uint64_t wmask = 0;
  uint64_t tmask = 0;
  if (!DecodeBitMasks(data.N, data.imms.uimm, data.immr.uimm, false, 32, &wmask, &tmask)) {
    return false;
  }

  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rd);
  AddShiftRegOperand(inst, kRegW, kUseAsValue, data.Rn, kShiftROR, data.immr.uimm);
  AddImmOperand(inst, wmask & tmask, kUnsigned, 32);
  return true;
}

// UBFM  <Xd>, <Xn>, #<immr>, #<imms>
bool TryDecodeUBFM_64M_BITFIELD(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (!data.N) {
    return false;  // `if sf == '1' && N != '1' then ReservedValue();`.
  }

  uint64_t wmask = 0;
  uint64_t tmask = 0;
  if (!DecodeBitMasks(data.N, data.imms.uimm, data.immr.uimm, false, 64, &wmask, &tmask)) {
    return false;
  }

  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rd);
  AddShiftRegOperand(inst, kRegX, kUseAsValue, data.Rn, kShiftROR, data.immr.uimm);
  AddImmOperand(inst, wmask & tmask, kUnsigned, 64);
  return true;
}

// SBFM  <Wd>, <Wn>, #<immr>, #<imms>
bool TryDecodeSBFM_32M_BITFIELD(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  // if sf == '0' && (N != '0' || immr<5> != '0' || imms<5> != '0')
  //    then ReservedValue();
  if (data.N || (data.immr.uimm & 0x20) || (data.imms.uimm & 0x20)) {
    return false;
  }
  uint64_t wmask = 0;
  uint64_t tmask = 0;
  if (!DecodeBitMasks(data.N, data.imms.uimm, data.immr.uimm, false, 32, &wmask, &tmask)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rn);
  AddImmOperand(inst, data.immr.uimm, kUnsigned, 32);
  AddImmOperand(inst, data.imms.uimm, kUnsigned, 32);
  AddImmOperand(inst, wmask, kUnsigned, 32);
  AddImmOperand(inst, tmask, kUnsigned, 32);
  return true;
}

// SBFM  <Xd>, <Xn>, #<immr>, #<imms>
bool TryDecodeSBFM_64M_BITFIELD(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (!data.N) {
    return false;  // `if sf == '1' && N != '1' then ReservedValue();`.
  }
  uint64_t wmask = 0;
  uint64_t tmask = 0;
  if (!DecodeBitMasks(data.N, data.imms.uimm, data.immr.uimm, false, 64, &wmask, &tmask)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rn);
  AddImmOperand(inst, data.immr.uimm, kUnsigned, 64);
  AddImmOperand(inst, data.imms.uimm, kUnsigned, 64);
  AddImmOperand(inst, wmask, kUnsigned, 64);
  AddImmOperand(inst, tmask, kUnsigned, 64);
  return true;
}

// BFM  <Wd>, <Wn>, #<immr>, #<imms>
bool TryDecodeBFM_32M_BITFIELD(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  // if sf == '0' && (N != '0' || immr<5> != '0' || imms<5> != '0')
  //    then ReservedValue();
  if (data.N || (data.immr.uimm & 0x20) || (data.imms.uimm & 0x20)) {
    return false;
  }
  uint64_t wmask = 0;
  uint64_t tmask = 0;
  if (!DecodeBitMasks(data.N, data.imms.uimm, data.immr.uimm, false, 32, &wmask, &tmask)) {
    return false;
  }
  AddRegOperand(inst, kActionReadWrite, kRegW, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rn);
  AddImmOperand(inst, data.immr.uimm, kUnsigned, 32);
  AddImmOperand(inst, wmask, kUnsigned, 32);
  AddImmOperand(inst, tmask, kUnsigned, 32);
  return true;
}

// BFM  <Xd>, <Xn>, #<immr>, #<imms>
bool TryDecodeBFM_64M_BITFIELD(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (!data.N) {
    return false;  // `if sf == '1' && N != '1' then ReservedValue();`.
  }
  uint64_t wmask = 0;
  uint64_t tmask = 0;
  if (!DecodeBitMasks(data.N, data.imms.uimm, data.immr.uimm, false, 64, &wmask, &tmask)) {
    return false;
  }
  AddRegOperand(inst, kActionReadWrite, kRegX, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rn);
  AddImmOperand(inst, data.immr.uimm, kUnsigned, 64);
  AddImmOperand(inst, wmask, kUnsigned, 64);
  AddImmOperand(inst, tmask, kUnsigned, 64);
  return true;
}

// ANDS  <Wd>, <Wn>, #<imm>
bool TryDecodeANDS_32S_LOG_IMM(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (data.N) {
    return false;  // `if sf == '0' && N != '0' then ReservedValue();`.
  }
  uint64_t imm = 0;
  if (!DecodeBitMasks(data.N, data.imms.uimm, data.immr.uimm, true, 32, &imm)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rn);
  AddImmOperand(inst, imm, kUnsigned, 32);
  AddEcvNZCVOperand(inst, kActionWrite);
  return true;
}

// ANDS  <Xd>, <Xn>, #<imm>
bool TryDecodeANDS_64S_LOG_IMM(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  uint64_t imm = 0;
  if (!DecodeBitMasks(data.N, data.imms.uimm, data.immr.uimm, true, 64, &imm)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rn);
  AddImmOperand(inst, imm, kUnsigned, 64);
  AddEcvNZCVOperand(inst, kActionWrite);
  return true;
}

// ANDS  <Wd>, <Wn>, <Wm>{, <shift> #<amount>}
bool TryDecodeANDS_32_LOG_SHIFT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  TryDecodeAND_32_LOG_SHIFT(data, inst);
  AddEcvNZCVOperand(inst, kActionWrite);
  return true;
}

// ANDS  <Xd>, <Xn>, <Xm>{, <shift> #<amount>}
bool TryDecodeANDS_64_LOG_SHIFT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  TryDecodeAND_64_LOG_SHIFT(data, inst);
  AddEcvNZCVOperand(inst, kActionWrite);
  return true;
}

// MADD  <Wd>, <Wn>, <Wm>, <Wa>
bool TryDecodeMADD_32A_DP_3SRC(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  TryDecodeRdW_Rn_Rm(data, inst, kRegW);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Ra);
  return true;
}

// MADD  <Xd>, <Xn>, <Xm>, <Xa>
bool TryDecodeMADD_64A_DP_3SRC(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  TryDecodeRdW_Rn_Rm(data, inst, kRegX);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Ra);
  return true;
}

// MSUB  <Wd>, <Wn>, <Wm>, <Wa>
bool TryDecodeMSUB_32A_DP_3SRC(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeMADD_32A_DP_3SRC(data, inst);
}

// MSUB  <Xd>, <Xn>, <Xm>, <Xa>
bool TryDecodeMSUB_64A_DP_3SRC(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeMADD_64A_DP_3SRC(data, inst);
}

// EXTR  <Wd>, <Wn>, <Wm>, #<lsb>
bool TryDecodeEXTR_32_EXTRACT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (data.N != data.sf) {
    return false;  // `if N != sf then UnallocatedEncoding();`
  }
  if (data.imms.uimm & 0x20) {
    return false;  // `if sf == '0' && imms<5> == '1' then ReservedValue();`
  }
  TryDecodeRdW_Rn_Rm(data, inst, kRegW);
  AddImmOperand(inst, data.imms.uimm, kUnsigned, 32);
  return true;
}

// EXTR  <Xd>, <Xn>, <Xm>, #<lsb>
bool TryDecodeEXTR_64_EXTRACT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (data.N != data.sf) {
    return false;  // `if N != sf then UnallocatedEncoding();`
  }
  TryDecodeRdW_Rn_Rm(data, inst, kRegX);
  AddImmOperand(inst, data.imms.uimm, kUnsigned, 64);
  return true;
}

// LSLV  <Wd>, <Wn>, <Wm>
bool TryDecodeLSLV_32_DP_2SRC(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeRdW_Rn_Rm(data, inst, kRegW);
}

// LSLV  <Xd>, <Xn>, <Xm>
bool TryDecodeLSLV_64_DP_2SRC(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeRdW_Rn_Rm(data, inst, kRegX);
}

// LSRV  <Wd>, <Wn>, <Wm>
bool TryDecodeLSRV_32_DP_2SRC(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeLSLV_32_DP_2SRC(data, inst);
}

// LSRV  <Xd>, <Xn>, <Xm>
bool TryDecodeLSRV_64_DP_2SRC(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeLSLV_64_DP_2SRC(data, inst);
}

// ASRV  <Wd>, <Wn>, <Wm>
bool TryDecodeASRV_32_DP_2SRC(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeLSLV_32_DP_2SRC(data, inst);
}

// ASRV  <Xd>, <Xn>, <Xm>
bool TryDecodeASRV_64_DP_2SRC(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeLSLV_64_DP_2SRC(data, inst);
}

// RORV  <Wd>, <Wn>, <Wm>
bool TryDecodeRORV_32_DP_2SRC(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeLSLV_32_DP_2SRC(data, inst);
}

// RORV  <Xd>, <Xn>, <Xm>
bool TryDecodeRORV_64_DP_2SRC(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeLSLV_64_DP_2SRC(data, inst);
}

// SBC  <Wd>, <Wn>, <Wm>
bool TryDecodeSBC_32_ADDSUB_CARRY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  TryDecodeRdW_Rn_Rm(data, inst, kRegW);
  AddEcvNZCVOperand(inst, kActionRead);
  return true;
}

// SBC  <Xd>, <Xn>, <Xm>
bool TryDecodeSBC_64_ADDSUB_CARRY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  TryDecodeRdW_Rn_Rm(data, inst, kRegX);
  AddEcvNZCVOperand(inst, kActionRead);
  return true;
}

// SBCS  <Wd>, <Wn>, <Wm>
bool TryDecodeSBCS_32_ADDSUB_CARRY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  TryDecodeSBC_32_ADDSUB_CARRY(data, inst);
  AddEcvNZCVOperand(inst, kActionRead);
  return true;
}

// SBCS  <Xd>, <Xn>, <Xm>
bool TryDecodeSBCS_64_ADDSUB_CARRY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeSBC_64_ADDSUB_CARRY(data, inst);
}

static bool TryDecodeUCVTF_Un_FLOAT2INT(const InstData &data, Instruction &inst,
                                        RegClass dest_class, RegClass src_class) {
  AddRegOperand(inst, kActionWrite, dest_class, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, src_class, kUseAsValue, data.Rn);
  return true;
}

// UCVTF  <Hd>, <Wn>
bool TryDecodeUCVTF_H32_FLOAT2INT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  TryDecodeUCVTF_Un_FLOAT2INT(data, inst, kRegH, kRegW);
  return true;
}

// UCVTF  <Sd>, <Wn>
bool TryDecodeUCVTF_S32_FLOAT2INT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  TryDecodeUCVTF_Un_FLOAT2INT(data, inst, kRegS, kRegW);
  return true;
}

// UCVTF  <Dd>, <Wn>
bool TryDecodeUCVTF_D32_FLOAT2INT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  TryDecodeUCVTF_Un_FLOAT2INT(data, inst, kRegD, kRegW);
  return true;
}

// UCVTF  <Hd>, <Xn>
bool TryDecodeUCVTF_H64_FLOAT2INT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  TryDecodeUCVTF_Un_FLOAT2INT(data, inst, kRegH, kRegX);

  return true;
}

// UCVTF  <Sd>, <Xn>
bool TryDecodeUCVTF_S64_FLOAT2INT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  TryDecodeUCVTF_Un_FLOAT2INT(data, inst, kRegS, kRegX);
  return true;
}

// UCVTF  <Dd>, <Xn>
bool TryDecodeUCVTF_D64_FLOAT2INT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  TryDecodeUCVTF_Un_FLOAT2INT(data, inst, kRegD, kRegX);
  return true;
}

// UCVTF  <V><d>, <V><n>
bool TryDecodeUCVTF_ASISDMISC_R(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  RegClass rclass;
  if (1 == data.sz) {
    inst.function += "_64";
    rclass = kReg2D;
  } else {
    inst.function += "_32";
    rclass = kReg4S;
  }
  return TryDecodeUCVTF_Un_FLOAT2INT(data, inst, rclass, rclass);
}

// FRINTA  <Dd>, <Dn>
bool TryDecodeFRINTA_D_FLOATDP1(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  AddRegOperand(inst, kActionWrite, kRegD, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegD, kUseAsValue, data.Rn);
  return true;
}

bool IsUnallocatedFloatEncoding(const InstData &data) {

  // when type `10` UnallocatedEncoding()
  // if opcode<2:1>:rmode != '11 01`
  if (data.type == 2) {
    uint8_t v_sig = ((data.opcode >> 1U) << 2) | data.rmode;
    return (v_sig != 0xD);
  }
  return false;
}

// FCVT  <Dd>, <Sn>
bool TryDecodeFCVT_DS_FLOATDP1(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (IsUnallocatedFloatEncoding(data) || data.opc == 2) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegD, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegS, kUseAsValue, data.Rn);
  return true;
}

// FCVT  <Hd>, <Dn>
bool TryDecodeFCVT_HD_FLOATDP1(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return false;
}

// FCVT  <Sd>, <Dn>
bool TryDecodeFCVT_SD_FLOATDP1(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (IsUnallocatedFloatEncoding(data) || data.opc == 2) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegS, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegD, kUseAsValue, data.Rn);
  return true;
}

// FCVTZS  <Wd>, <Sn>
bool TryDecodeFCVTZS_32S_FLOAT2INT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (IsUnallocatedFloatEncoding(data)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegS, kUseAsValue, data.Rn);
  return true;
}

// FCVTZS  <Xd>, <Sn>
bool TryDecodeFCVTZS_64S_FLOAT2INT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (IsUnallocatedFloatEncoding(data)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegS, kUseAsValue, data.Rn);
  return true;
}

// FCVTZS  <Wd>, <Dn>
bool TryDecodeFCVTZS_32D_FLOAT2INT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (IsUnallocatedFloatEncoding(data)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegD, kUseAsValue, data.Rn);
  return true;
}

// FCVTZS  <Xd>, <Dn>
bool TryDecodeFCVTZS_64D_FLOAT2INT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (IsUnallocatedFloatEncoding(data)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegD, kUseAsValue, data.Rn);
  return true;
}

// FCVTAS  <Xd>, <Dn>
bool TryDecodeFCVTAS_64D_FLOAT2INT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegD, kUseAsValue, data.Rn);
  return true;
}

// FCVTZU  <Wd>, <Sn>
bool TryDecodeFCVTZU_32S_FLOAT2INT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (IsUnallocatedFloatEncoding(data)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegS, kUseAsValue, data.Rn);
  return true;
}

// FCVTZU  <Wd>, <Dn>
bool TryDecodeFCVTZU_32D_FLOAT2INT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (IsUnallocatedFloatEncoding(data)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegD, kUseAsValue, data.Rn);
  return true;
}

// FCVTZU  <Xd>, <Sn>
bool TryDecodeFCVTZU_64S_FLOAT2INT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (IsUnallocatedFloatEncoding(data)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegS, kUseAsValue, data.Rn);
  return true;
}

// FCVTZU  <Xd>, <Dn>
bool TryDecodeFCVTZU_64D_FLOAT2INT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (IsUnallocatedFloatEncoding(data)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegD, kUseAsValue, data.Rn);
  return true;
}

// FMOV  <Hd>, #<imm>
bool TryDecodeFMOV_H_FLOATIMM(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (IsUnallocatedFloatEncoding(data)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegH, kUseAsValue, data.Rd);
  auto float_val = VFPExpandImmToFloat32(data.imm8.uimm);
  AddImmOperand(inst, float_val);
  return true;
}

// FMOV  <Sd>, #<imm>
bool TryDecodeFMOV_S_FLOATIMM(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (IsUnallocatedFloatEncoding(data)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegS, kUseAsValue, data.Rd);
  auto float_val = VFPExpandImmToFloat32(data.imm8.uimm);
  AddImmOperand(inst, float_val);
  return true;
}

// FMOV  <Dd>, #<imm>
bool TryDecodeFMOV_D_FLOATIMM(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (IsUnallocatedFloatEncoding(data)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegD, kUseAsValue, data.Rd);
  auto float_val = VFPExpandImmToFloat64(data.imm8.uimm);
  AddImmOperand(inst, float_val);
  return true;
}

// FMOV  <Sd>, <Wn>
bool TryDecodeFMOV_S32_FLOAT2INT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (IsUnallocatedFloatEncoding(data)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegS, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rn);
  return true;
}

// FMOV  <Wd>, <Sn>
bool TryDecodeFMOV_32S_FLOAT2INT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (IsUnallocatedFloatEncoding(data)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegS, kUseAsValue, data.Rn);
  return true;
}

// FMOV  <Dd>, <Xn>
bool TryDecodeFMOV_D64_FLOAT2INT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (IsUnallocatedFloatEncoding(data)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegD, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rn);
  return true;
}
// FMOV  <Xd>, <Dn>
bool TryDecodeFMOV_64D_FLOAT2INT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (IsUnallocatedFloatEncoding(data)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegD, kUseAsValue, data.Rn);
  return true;
}

// FMOV  <Sd>, <Sn>
bool TryDecodeFMOV_S_FLOATDP1(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (IsUnallocatedFloatEncoding(data)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegS, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegS, kUseAsValue, data.Rn);
  return true;
}

// FMOV  <Dd>, <Dn>
bool TryDecodeFMOV_D_FLOATDP1(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (IsUnallocatedFloatEncoding(data)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegD, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegD, kUseAsValue, data.Rn);
  return true;
}

// FMOV  <Vd>.D[1], <Xn>
bool TryDecodeFMOV_V64I_FLOAT2INT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (IsUnallocatedFloatEncoding(data)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kReg2D, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rn);
  return true;
}

// FMOV  <Xd>, <Vn>.D[1]
bool TryDecodeFMOV_64VX_FLOAT2INT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (IsUnallocatedFloatEncoding(data)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kReg2D, kUseAsValue, data.Rn);
  return true;
}

static bool TryDecodeFn_Fm(const InstData &data, Instruction &inst, RegClass rclass) {
  if (IsUnallocatedFloatEncoding(data)) {
    return false;
  }
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rn);
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rm);
  return true;
}

static bool TryDecodeFn_Fm_nzcvW(const InstData &data, Instruction &inst, RegClass rclass) {
  if (IsUnallocatedFloatEncoding(data)) {
    return false;
  }
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rn);
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rm);
  AddEcvNZCVOperand(inst, kActionWrite);
  return true;
}

static bool TryDecodeFdW_Fn_Fm(const InstData &data, Instruction &inst, RegClass rclass) {
  if (IsUnallocatedFloatEncoding(data)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, rclass, kUseAsValue, data.Rd);
  return TryDecodeFn_Fm(data, inst, rclass);
}

// FADD  <Hd>, <Hn>, <Hm>
bool TryDecodeFADD_H_FLOATDP2(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::State;
  return TryDecodeFdW_Fn_Fm(data, inst, kRegH);
}

// FADD  <Sd>, <Sn>, <Sm>
bool TryDecodeFADD_S_FLOATDP2(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::State;
  return TryDecodeFdW_Fn_Fm(data, inst, kRegS);
}

// FADD  <Dd>, <Dn>, <Dm>
bool TryDecodeFADD_D_FLOATDP2(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::State;
  return TryDecodeFdW_Fn_Fm(data, inst, kRegD);
}

// FMUL  <Hd>, <Hn>, <Hm>
bool TryDecodeFMUL_H_FLOATDP2(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::State;
  return TryDecodeFdW_Fn_Fm(data, inst, kRegH);
}

// FMUL  <Sd>, <Sn>, <Sm>
bool TryDecodeFMUL_S_FLOATDP2(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::State;
  return TryDecodeFdW_Fn_Fm(data, inst, kRegS);
}

// FMUL  <Dd>, <Dn>, <Dm>
bool TryDecodeFMUL_D_FLOATDP2(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::State;
  return TryDecodeFdW_Fn_Fm(data, inst, kRegD);
}

// FDIV  <Hd>, <Hn>, <Hm>
bool TryDecodeFDIV_H_FLOATDP2(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::State;
  return TryDecodeFdW_Fn_Fm(data, inst, kRegH);
}

// FDIV  <Sd>, <Sn>, <Sm>
bool TryDecodeFDIV_S_FLOATDP2(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::State;
  return TryDecodeFdW_Fn_Fm(data, inst, kRegS);
}

// FDIV  <Dd>, <Dn>, <Dm>
bool TryDecodeFDIV_D_FLOATDP2(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::State;
  return TryDecodeFdW_Fn_Fm(data, inst, kRegD);
}

// FDIV  <Vd>.<T>, <Vn>.<T>, <Vm>.<T> (only 32bit or 64bit)
bool TryDecodeFDIV_ASIMDSAME_ONLY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  uint64_t total_size, elem_size;
  if (1 == data.sz && 0 == data.Q) {
    return false;
  }
  total_size = data.Q ? 128 : 64;
  elem_size = 32 << data.sz;
  AddArrangementSpecifierFloat(inst, total_size, elem_size);
  auto rclass = ArrangementRegClass(total_size, elem_size, true);
  return TryDecodeRdW_Rn_Rm(data, inst, rclass);
}

// FSUB  <Hd>, <Hn>, <Hm>
bool TryDecodeFSUB_H_FLOATDP2(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::State;
  return TryDecodeFdW_Fn_Fm(data, inst, kRegH);
}

// FSUB  <Sd>, <Sn>, <Sm>
bool TryDecodeFSUB_S_FLOATDP2(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::State;
  return TryDecodeFdW_Fn_Fm(data, inst, kRegS);
}

// FSUB  <Dd>, <Dn>, <Dm>
bool TryDecodeFSUB_D_FLOATDP2(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::State;
  return TryDecodeFdW_Fn_Fm(data, inst, kRegD);
}

// FMADD  <Sd>, <Sn>, <Sm>, <Sa>
bool TryDecodeFMADD_S_FLOATDP3(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::State;
  if (IsUnallocatedFloatEncoding(data)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegS, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegS, kUseAsValue, data.Rn);
  AddRegOperand(inst, kActionRead, kRegS, kUseAsValue, data.Rm);
  AddRegOperand(inst, kActionRead, kRegS, kUseAsValue, data.Ra);
  return true;
}

// FMADD  <Dd>, <Dn>, <Dm>, <Da>
bool TryDecodeFMADD_D_FLOATDP3(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::State;
  if (IsUnallocatedFloatEncoding(data)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegD, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegD, kUseAsValue, data.Rn);
  AddRegOperand(inst, kActionRead, kRegD, kUseAsValue, data.Rm);
  AddRegOperand(inst, kActionRead, kRegD, kUseAsValue, data.Ra);
  return true;
}

// FMSUB  <Sd>, <Sn>, <Sm>, <Sa>
bool TryDecodeFMSUB_S_FLOATDP3(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::State;
  if (IsUnallocatedFloatEncoding(data)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegS, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegS, kUseAsValue, data.Rn);
  AddRegOperand(inst, kActionRead, kRegS, kUseAsValue, data.Rm);
  AddRegOperand(inst, kActionRead, kRegS, kUseAsValue, data.Ra);
  return true;
}

// FMSUB  <Dd>, <Dn>, <Dm>, <Da>
bool TryDecodeFMSUB_D_FLOATDP3(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::State;
  if (IsUnallocatedFloatEncoding(data)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegD, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegD, kUseAsValue, data.Rn);
  AddRegOperand(inst, kActionRead, kRegD, kUseAsValue, data.Rm);
  AddRegOperand(inst, kActionRead, kRegD, kUseAsValue, data.Ra);
  return true;
}

// FCMPE  <Sn>, <Sm>
bool TryDecodeFCMPE_S_FLOATCMP(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::State;
  return TryDecodeFn_Fm_nzcvW(data, inst, kRegS);
}

// FCMPE  <Hn>, <Hm>
bool TryDecodeFCMPE_H_FLOATCMP(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::State;
  return TryDecodeFn_Fm_nzcvW(data, inst, kRegH);
}

// FCMPE  <Dn>, <Dm>
bool TryDecodeFCMPE_D_FLOATCMP(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::State;
  return TryDecodeFn_Fm_nzcvW(data, inst, kRegD);
}

static bool TryDecodeFCMP_ToZero(const InstData &data, Instruction &inst, RegClass rclass) {
  if (IsUnallocatedFloatEncoding(data)) {
    return false;
  }
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rn);
  AddEcvNZCVOperand(inst, kActionWrite);
  return true;
}

// FCMPE  <Hn>, #0.0
bool TryDecodeFCMPE_HZ_FLOATCMP(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::State;
  return TryDecodeFCMP_ToZero(data, inst, kRegH);
}

// FCMPE  <Sn>, #0.0
bool TryDecodeFCMPE_SZ_FLOATCMP(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::State;
  return TryDecodeFCMP_ToZero(data, inst, kRegS);
}

// FCMPE  <Dn>, #0.0
bool TryDecodeFCMPE_DZ_FLOATCMP(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::State;
  return TryDecodeFCMP_ToZero(data, inst, kRegD);
}

// FCMP  <Dn>, #0.0
bool TryDecodeFCMP_DZ_FLOATCMP(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::State;
  return TryDecodeFCMP_ToZero(data, inst, kRegD);
}

// FCMP  <Sn>, #0.0
bool TryDecodeFCMP_SZ_FLOATCMP(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::State;
  return TryDecodeFCMP_ToZero(data, inst, kRegS);
}

// FCMP  <Dn>, <Dm>
bool TryDecodeFCMP_D_FLOATCMP(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::State;
  return TryDecodeFn_Fm_nzcvW(data, inst, kRegD);
}

// FCMP  <Sn>, <Sm>
bool TryDecodeFCMP_S_FLOATCMP(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::State;
  return TryDecodeFn_Fm_nzcvW(data, inst, kRegS);
}

// FABS  <Sd>, <Sn>
bool TryDecodeFABS_S_FLOATDP1(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (IsUnallocatedFloatEncoding(data)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegS, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegS, kUseAsValue, data.Rn);
  return true;
}

// FABS  <Dd>, <Dn>
bool TryDecodeFABS_D_FLOATDP1(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (IsUnallocatedFloatEncoding(data)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegD, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegD, kUseAsValue, data.Rn);
  return true;
}

// FNEG  <Sd>, <Sn>
bool TryDecodeFNEG_S_FLOATDP1(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (IsUnallocatedFloatEncoding(data)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegS, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegS, kUseAsValue, data.Rn);
  return true;
}

// FNEG  <Dd>, <Dn>
bool TryDecodeFNEG_D_FLOATDP1(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (IsUnallocatedFloatEncoding(data)) {
    return false;
  }
  AddRegOperand(inst, kActionWrite, kRegD, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegD, kUseAsValue, data.Rn);
  return true;
}

// SVC  #<imm>
bool TryDecodeSVC_EX_EXCEPTION(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::StateRuntime;
  AddImmOperand(inst, data.imm16.uimm, kUnsigned, 32);
  return true;
}

// BRK  #<imm>
bool TryDecodeBRK_EX_EXCEPTION(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::StateRuntime;
  AddImmOperand(inst, data.imm16.uimm, kUnsigned, 32);
  return true;
}

union SystemReg {
  uint64_t flat;
  enum Name : uint64_t {
    kFPCR = 0xDA20,
    kFPSR = 0xDA21,
    kTPIDR_EL0 = 0xDE82,
    kTPIDRRO_EL0 = 0xDE83,
    kCTR_EL0 = 0xD801,
    kDCZID_EL0 = 0xD807,
    kMIDR_EL1 = 0xC000
  } name;
  struct {
    uint64_t op2 : 3;
    uint64_t crm : 4;
    uint64_t crn : 4;
    uint64_t op1 : 3;
    uint64_t op0 : 2;

    uint64_t _rest : 64 - 16;
  } __attribute__((packed));
} __attribute__((packed));

static_assert(sizeof(SystemReg) == sizeof(uint64_t), "Invalid packing of `union SystemReg`.");

static bool AppendSysRegName(Instruction &inst, SystemReg bits) {
  std::stringstream ss;
  ss << inst.function << "_";

  switch (bits.name) {
    case SystemReg::kFPCR: ss << "FPCR"; break;
    case SystemReg::kFPSR: ss << "FPSR"; break;
    case SystemReg::kTPIDR_EL0: ss << "TPIDR_EL0"; break;
    case SystemReg::kTPIDRRO_EL0: ss << "TPIDRRO_EL0"; break;
    case SystemReg::kCTR_EL0: ss << "CTR_EL0"; break;
    case SystemReg::kDCZID_EL0: ss << "DCZID_EL0"; break;
    case SystemReg::kMIDR_EL1: ss << "MIDR_EL1"; break;
    default:
      LOG(ERROR) << "Unrecognized system register " << std::hex << bits.flat
                 << " with op0=" << bits.op0 << ", op1=" << bits.op1 << ", crn=" << bits.crn
                 << ", crm=" << bits.crm << ", op2=" << bits.op2 << ", bits.name=0x" << bits.name
                 << std::dec;
      return false;
  }

  inst.function = ss.str();
  return true;
}

// MRS  <Xt>, (<systemreg>|S<op0>_<op1>_<Cn>_<Cm>_<op2>)
bool TryDecodeMRS_RS_SYSTEM(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::State;
  SystemReg bits = {};
  bits.op0 = data.o0 + 2ULL;  // 2 bits.
  bits.op1 = data.op1;  // 3 bits.
  bits.crn = data.CRn;  // 4 bits.
  bits.crm = data.CRm;  // 4 bits.
  bits.op2 = data.op2;  // 3 bits.
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rt);
  return AppendSysRegName(inst, bits);
}

// MSR  (<systemreg>|S<op0>_<op1>_<Cn>_<Cm>_<op2>), <Xt>
bool TryDecodeMSR_SR_SYSTEM(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::State;
  SystemReg bits = {};
  bits.op0 = data.o0 + 2ULL;  // 2 bits.
  bits.op1 = data.op1;  // 3 bits.
  bits.crn = data.CRn;  // 4 bits.
  bits.crm = data.CRm;  // 4 bits.
  bits.op2 = data.op2;  // 3 bits.
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rt);
  return AppendSysRegName(inst, bits);
}

static bool TryDecodeSTR_Vn_LDST_POS(const InstData &data, Instruction &inst, RegClass val_class) {
  uint64_t scale = DecodeScale(data);
  if (scale > 4) {
    return false;
  }
  auto num_bits = ReadRegSize(val_class);
  AddRegOperand(inst, kActionRead, val_class, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, num_bits, data.Rn, static_cast<uint64_t>(data.imm12.uimm) << scale);
  return true;
}
// STR  <Bt>, [<Xn|SP>{, #<pimm>}]
bool TryDecodeSTR_B_LDST_POS(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeSTR_Vn_LDST_POS(data, inst, kRegB);
}

// STR  <Ht>, [<Xn|SP>{, #<pimm>}]
bool TryDecodeSTR_H_LDST_POS(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeSTR_Vn_LDST_POS(data, inst, kRegH);
}

// STR  <St>, [<Xn|SP>{, #<pimm>}]
bool TryDecodeSTR_S_LDST_POS(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeSTR_Vn_LDST_POS(data, inst, kRegS);
}

// STR  <Dt>, [<Xn|SP>{, #<pimm>}]
bool TryDecodeSTR_D_LDST_POS(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeSTR_Vn_LDST_POS(data, inst, kRegD);
}

// STR  <Qt>, [<Xn|SP>{, #<pimm>}]
bool TryDecodeSTR_Q_LDST_POS(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeSTR_Vn_LDST_POS(data, inst, K_REG_Q);
}

static bool TryDecodeSTR_Vn_LDST_REGOFF(const InstData &data, Instruction &inst,
                                        RegClass val_class) {
  uint64_t scale = DecodeScale(data);
  if (scale > 4) {
    return false;
  } else if (!(data.option & 2)) {  // Sub word indexing.
    return false;  // `if option<1> == '0' then UnallocatedEncoding();`.
  }
  auto shift = (data.S == 1) ? scale : 0U;
  auto extend_type = static_cast<Extend>(data.option);
  auto rclass = ExtendTypeToRegClass(extend_type);
  AddRegOperand(inst, kActionRead, val_class, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 8U << scale, data.Rn, 0);
  AddExtendRegOperand(inst, rclass, kUseAsValue, data.Rm, extend_type, 64, shift);
  return true;
}

// STR  <St>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
bool TryDecodeSTR_S_LDST_REGOFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeSTR_Vn_LDST_REGOFF(data, inst, kRegS);
}

// STR  <Qt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
bool TryDecodeSTR_Q_LDST_REGOFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeSTR_Vn_LDST_REGOFF(data, inst, K_REG_Q);
}

static bool TryDecodeSTR_Vn_LDST_IMMPRE(const InstData &data, Instruction &inst,
                                        RegClass val_class) {
  uint64_t scale = DecodeScale(data);
  if (scale < 4) {
    return false;
  }
  auto num_bits = ReadRegSize(val_class);
  AddRegOperand(inst, kActionRead, val_class, kUseAsValue, data.Rt);
  uint64_t offset = static_cast<uint64_t>(data.imm9.simm9);
  AddPreIndexMemOp(inst, num_bits, data.Rn, offset);
  return true;
}

// STR  <Qt>, [<Xn|SP>, #<simm>]!
bool TryDecodeSTR_Q_LDST_IMMPRE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeSTR_Vn_LDST_IMMPRE(data, inst, K_REG_Q);
}

static bool TryDecodeLDR_Vn_LDST_POS(const InstData &data, Instruction &inst, RegClass val_class) {
  uint64_t scale = DecodeScale(data);
  if (scale > 4) {
    return false;
  }
  auto num_bits = ReadRegSize(val_class);
  AddRegOperand(inst, kActionWrite, val_class, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, num_bits, data.Rn, static_cast<uint64_t>(data.imm12.uimm) << scale);
  return true;
}

// LDR  <Bt>, [<Xn|SP>{, #<pimm>}]
bool TryDecodeLDR_B_LDST_POS(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDR_Vn_LDST_POS(data, inst, kRegB);
}

// LDR  <Ht>, [<Xn|SP>{, #<pimm>}]
bool TryDecodeLDR_H_LDST_POS(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDR_Vn_LDST_POS(data, inst, kRegH);
}

// LDR  <St>, [<Xn|SP>{, #<pimm>}]
bool TryDecodeLDR_S_LDST_POS(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDR_Vn_LDST_POS(data, inst, kRegS);
}
// LDR  <Dt>, [<Xn|SP>{, #<pimm>}]
bool TryDecodeLDR_D_LDST_POS(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDR_Vn_LDST_POS(data, inst, kRegD);
}

// LDR  <Qt>, [<Xn|SP>{, #<pimm>}]
bool TryDecodeLDR_Q_LDST_POS(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDR_Vn_LDST_POS(data, inst, K_REG_Q);
}

static bool TryDecodeLDR_Vn_LDST_REGOFF(const InstData &data, Instruction &inst,
                                        RegClass val_class) {
  uint64_t scale = DecodeScale(data);
  if (scale > 4) {
    return false;
  } else if (!(data.option & 2)) {  // Sub word indexing.
    return false;  // `if option<1> == '0' then UnallocatedEncoding();`.
  }
  auto shift = (data.S == 1) ? scale : 0U;
  auto extend_type = static_cast<Extend>(data.option);
  auto rclass = ExtendTypeToRegClass(extend_type);
  AddRegOperand(inst, kActionWrite, val_class, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 8U << scale, data.Rn, 0);
  AddExtendRegOperand(inst, rclass, kUseAsValue, data.Rm, extend_type, 64, shift);
  return true;
}

// LDR  <Bt>, [<Xn|SP>, (<Wm>|<Xm>), <extend> {<amount>}]
bool TryDecodeLDR_B_LDST_REGOFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDR_Vn_LDST_REGOFF(data, inst, kRegB);
}

// LDR  <Bt>, [<Xn|SP>, <Xm>{, LSL <amount>}]
bool TryDecodeLDR_BL_LDST_REGOFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDR_Vn_LDST_REGOFF(data, inst, kRegB);
}

// LDR  <Ht>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
bool TryDecodeLDR_H_LDST_REGOFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDR_Vn_LDST_REGOFF(data, inst, kRegH);
}

// LDR  <St>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
bool TryDecodeLDR_S_LDST_REGOFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDR_Vn_LDST_REGOFF(data, inst, kRegS);
}

// LDR  <Dt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
bool TryDecodeLDR_D_LDST_REGOFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDR_Vn_LDST_REGOFF(data, inst, kRegD);
}

// LDR  <Qt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
bool TryDecodeLDR_Q_LDST_REGOFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDR_Vn_LDST_REGOFF(data, inst, K_REG_Q);
}

static bool TryDecodeLDR_Vn_LDST_IMMPOST(const InstData &data, Instruction &inst,
                                         RegClass val_class) {
  uint64_t scale = DecodeScale(data);
  if (scale > 4) {
    return false;
  }
  auto num_bits = ReadRegSize(val_class);
  AddRegOperand(inst, kActionWrite, val_class, kUseAsValue, data.Rt);
  uint64_t offset = static_cast<uint64_t>(data.imm9.simm9);
  AddPostIndexMemOp(inst, num_bits, data.Rn, offset);
  return true;
}

// LDR  <Bt>, [<Xn|SP>], #<simm>
bool TryDecodeLDR_B_LDST_IMMPOST(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDR_Vn_LDST_IMMPOST(data, inst, kRegB);
}

// LDR  <Ht>, [<Xn|SP>], #<simm>
bool TryDecodeLDR_H_LDST_IMMPOST(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDR_Vn_LDST_IMMPOST(data, inst, kRegH);
}

// LDR  <St>, [<Xn|SP>], #<simm>
bool TryDecodeLDR_S_LDST_IMMPOST(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDR_Vn_LDST_IMMPOST(data, inst, kRegS);
}

// LDR  <Dt>, [<Xn|SP>], #<simm>
bool TryDecodeLDR_D_LDST_IMMPOST(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDR_Vn_LDST_IMMPOST(data, inst, kRegD);
}

// LDR  <Qt>, [<Xn|SP>], #<simm>
bool TryDecodeLDR_Q_LDST_IMMPOST(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDR_Vn_LDST_IMMPOST(data, inst, K_REG_Q);
}

static bool TryDecodeLDR_Vn_LDST_IMMPRE(const InstData &data, Instruction &inst,
                                        RegClass val_class) {
  uint64_t scale = DecodeScale(data);
  if (scale > 4) {
    return false;
  }
  auto num_bits = ReadRegSize(val_class);
  AddRegOperand(inst, kActionWrite, val_class, kUseAsValue, data.Rt);
  uint64_t offset = static_cast<uint64_t>(data.imm9.simm9);
  AddPreIndexMemOp(inst, num_bits, data.Rn, offset);
  return true;
}

// LDR  <Bt>, [<Xn|SP>, #<simm>]!
bool TryDecodeLDR_B_LDST_IMMPRE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDR_Vn_LDST_IMMPRE(data, inst, kRegB);
}

// LDR  <Ht>, [<Xn|SP>, #<simm>]!
bool TryDecodeLDR_H_LDST_IMMPRE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDR_Vn_LDST_IMMPRE(data, inst, kRegH);
}

// LDR  <St>, [<Xn|SP>, #<simm>]!
bool TryDecodeLDR_S_LDST_IMMPRE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDR_Vn_LDST_IMMPRE(data, inst, kRegS);
}

// LDR  <Dt>, [<Xn|SP>, #<simm>]!
bool TryDecodeLDR_D_LDST_IMMPRE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDR_Vn_LDST_IMMPRE(data, inst, kRegD);
}

// LDR  <Qt>, [<Xn|SP>, #<simm>]!
bool TryDecodeLDR_Q_LDST_IMMPRE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDR_Vn_LDST_IMMPRE(data, inst, K_REG_Q);
}

// LDR  <St>, <label>
bool TryDecodeLDR_S_LOADLIT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegS, kUseAsValue, data.Rt);
  AddPCRegMemOp(inst, static_cast<uint64_t>(data.imm19.simm19) << 2ULL);
  return true;
}

// LDR  <Dt>, <label>
bool TryDecodeLDR_D_LOADLIT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegD, kUseAsValue, data.Rt);
  AddPCRegMemOp(inst, static_cast<uint64_t>(data.imm19.simm19) << 2ULL);
  return true;
}

// LDR  <Qt>, <label>
bool TryDecodeLDR_Q_LOADLIT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, K_REG_Q, kUseAsValue, data.Rt);
  AddPCRegMemOp(inst, static_cast<uint64_t>(data.imm19.simm19) << 2ULL);
  return true;
}

static bool TryDecodeLDP_Vn_LDSTPAIR_POST(const InstData &data, Instruction &inst,
                                          RegClass rclass) {
  auto size = ReadRegSize(rclass);
  auto scale = 2U + data.opc;
  if (data.opc == 0x3) {
    return false;  // `if opc == '11' then UnallocatedEncoding();`.
  }
  AddRegOperand(inst, kActionWrite, rclass, kUseAsValue, data.Rt);
  AddRegOperand(inst, kActionWrite, rclass, kUseAsValue, data.Rt2);
  AddPostIndexMemOp(inst, size * 2, data.Rn, static_cast<uint64_t>(data.imm7.simm7) << scale);
  return true;
}

// LDP  <St1>, <St2>, [<Xn|SP>], #<imm>
bool TryDecodeLDP_S_LDSTPAIR_POST(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDP_Vn_LDSTPAIR_POST(data, inst, kRegS);
}

// LDP  <Dt1>, <Dt2>, [<Xn|SP>], #<imm>
bool TryDecodeLDP_D_LDSTPAIR_POST(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDP_Vn_LDSTPAIR_POST(data, inst, kRegD);
}

// LDP  <Qt1>, <Qt2>, [<Xn|SP>], #<imm>
bool TryDecodeLDP_Q_LDSTPAIR_POST(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDP_Vn_LDSTPAIR_POST(data, inst, K_REG_Q);
}

static bool TryDecodeLDP_Vn_LDSTPAIR_PRE(const InstData &data, Instruction &inst, RegClass rclass) {
  auto size = ReadRegSize(rclass);
  auto scale = 2U + data.opc;
  if (data.opc == 0x3) {
    return false;  // `if opc == '11' then UnallocatedEncoding();`.
  }
  AddRegOperand(inst, kActionWrite, rclass, kUseAsValue, data.Rt);
  AddRegOperand(inst, kActionWrite, rclass, kUseAsValue, data.Rt2);
  AddPreIndexMemOp(inst, size * 2, data.Rn, static_cast<uint64_t>(data.imm7.simm7) << scale);
  return true;
}

// LDP  <St1>, <St2>, [<Xn|SP>, #<imm>]!
bool TryDecodeLDP_S_LDSTPAIR_PRE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDP_Vn_LDSTPAIR_PRE(data, inst, kRegS);
}

// LDP  <Dt1>, <Dt2>, [<Xn|SP>, #<imm>]!
bool TryDecodeLDP_D_LDSTPAIR_PRE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDP_Vn_LDSTPAIR_PRE(data, inst, kRegD);
}

// LDP  <Qt1>, <Qt2>, [<Xn|SP>, #<imm>]!
bool TryDecodeLDP_Q_LDSTPAIR_PRE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDP_Vn_LDSTPAIR_PRE(data, inst, K_REG_Q);
}

static bool TryDecodeLDP_Vn_LDSTPAIR_OFF(const InstData &data, Instruction &inst, RegClass rclass) {
  auto size = ReadRegSize(rclass);
  auto scale = 2U + data.opc;
  if (data.opc == 0x3) {
    return false;  // `if opc == '11' then UnallocatedEncoding();`.
  }
  AddRegOperand(inst, kActionWrite, rclass, kUseAsValue, data.Rt);
  AddRegOperand(inst, kActionWrite, rclass, kUseAsValue, data.Rt2);
  AddBasePlusOffsetMemOp(inst, size * 2, data.Rn, static_cast<uint64_t>(data.imm7.simm7) << scale);
  return true;
}

// LDP  <St1>, <St2>, [<Xn|SP>{, #<imm>}]
bool TryDecodeLDP_S_LDSTPAIR_OFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDP_Vn_LDSTPAIR_OFF(data, inst, kRegS);
}

// LDP  <Dt1>, <Dt2>, [<Xn|SP>{, #<imm>}]
bool TryDecodeLDP_D_LDSTPAIR_OFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDP_Vn_LDSTPAIR_OFF(data, inst, kRegD);
}

// LDP  <Qt1>, <Qt2>, [<Xn|SP>{, #<imm>}]
bool TryDecodeLDP_Q_LDSTPAIR_OFF(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDP_Vn_LDSTPAIR_OFF(data, inst, K_REG_Q);
}

// CLZ  <Wd>, <Wn>
bool TryDecodeCLZ_32_DP_1SRC(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rn);
  return true;
}

// CLZ  <Xd>, <Xn>
bool TryDecodeCLZ_64_DP_1SRC(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rn);
  return true;
}

static bool DecodeConditionalRegSelect(const InstData &data, Instruction &inst, RegClass r_class,
                                       int n_regs, bool invert_cond = false) {
  CHECK(1 <= n_regs && n_regs <= 3);

  AddRegOperand(inst, kActionWrite, r_class, kUseAsValue, data.Rd);
  if (--n_regs > 0) {
    AddRegOperand(inst, kActionRead, r_class, kUseAsValue, data.Rn);
  }
  if (--n_regs > 0) {
    AddRegOperand(inst, kActionRead, r_class, kUseAsValue, data.Rm);
  }

  // Condition will be part of the isel, not an operand.
  SetConditionalFunctionName(data, inst, invert_cond);
  return true;
}

// CSEL  <Wd>, <Wn>, <Wm>, <cond>
bool TryDecodeCSEL_32_CONDSEL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  DecodeConditionalRegSelect(data, inst, kRegW, 3);
  AddEcvNZCVOperand(inst, kActionRead);
  return true;
}

// CSEL  <Xd>, <Xn>, <Xm>, <cond>
bool TryDecodeCSEL_64_CONDSEL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  DecodeConditionalRegSelect(data, inst, kRegX, 3);
  AddEcvNZCVOperand(inst, kActionRead);
  return true;
}

// FCSEL  <Sd>, <Sn>, <Sm>, <cond>
bool TryDecodeFCSEL_S_FLOATSEL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  DecodeConditionalRegSelect(data, inst, kRegS, 3);
  AddEcvNZCVOperand(inst, kActionRead);
  return true;
}

// FCSEL  <Dd>, <Dn>, <Dm>, <cond>
bool TryDecodeFCSEL_D_FLOATSEL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  DecodeConditionalRegSelect(data, inst, kRegD, 3);
  AddEcvNZCVOperand(inst, kActionRead);
  return true;
}

// CSINC  <Wd>, <Wn>, <Wm>, <cond>
bool TryDecodeCSINC_32_CONDSEL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  DecodeConditionalRegSelect(data, inst, kRegW, 3);
  AddEcvNZCVOperand(inst, kActionRead);
  return true;
}

// CSINC  <Xd>, <Xn>, <Xm>, <cond>
bool TryDecodeCSINC_64_CONDSEL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  DecodeConditionalRegSelect(data, inst, kRegX, 3);
  AddEcvNZCVOperand(inst, kActionRead);
  return true;
}

// CSINV  <Wd>, <Wn>, <Wm>, <cond>
bool TryDecodeCSINV_32_CONDSEL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  DecodeConditionalRegSelect(data, inst, kRegW, 3);
  AddEcvNZCVOperand(inst, kActionRead);
  return true;
}

// CSINV  <Xd>, <Xn>, <Xm>, <cond>
bool TryDecodeCSINV_64_CONDSEL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  DecodeConditionalRegSelect(data, inst, kRegX, 3);
  AddEcvNZCVOperand(inst, kActionRead);
  return true;
}

// CSNEG  <Wd>, <Wn>, <Wm>, <cond>
bool TryDecodeCSNEG_32_CONDSEL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  DecodeConditionalRegSelect(data, inst, kRegW, 3);
  AddEcvNZCVOperand(inst, kActionRead);
  return true;
}

// CSNEG  <Xd>, <Xn>, <Xm>, <cond>
bool TryDecodeCSNEG_64_CONDSEL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  DecodeConditionalRegSelect(data, inst, kRegX, 3);
  AddEcvNZCVOperand(inst, kActionRead);
  return true;
}

// CCMP  <Wn>, #<imm>, #<nzcv>, <cond>
bool TryDecodeCCMP_32_CONDCMP_IMM(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  SetConditionalFunctionName(data, inst);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rn);
  AddImmOperand(inst, data.imm5.uimm);
  AddImmOperand(inst, data.nzcv);
  AddEcvNZCVOperand(inst, kActionReadWrite);
  return true;
}

// CCMP  <Xn>, #<imm>, #<nzcv>, <cond>
bool TryDecodeCCMP_64_CONDCMP_IMM(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  SetConditionalFunctionName(data, inst);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rn);
  AddImmOperand(inst, data.imm5.uimm);
  AddImmOperand(inst, data.nzcv);
  AddEcvNZCVOperand(inst, kActionReadWrite);
  return true;
}

// CCMP  <Wn>, <Wm>, #<nzcv>, <cond>
bool TryDecodeCCMP_32_CONDCMP_REG(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  SetConditionalFunctionName(data, inst);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rn);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rm);
  AddImmOperand(inst, data.nzcv);
  AddEcvNZCVOperand(inst, kActionReadWrite);
  return true;
}

// CCMP  <Xn>, <Xm>, #<nzcv>, <cond>
bool TryDecodeCCMP_64_CONDCMP_REG(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  SetConditionalFunctionName(data, inst);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rn);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rm);
  AddImmOperand(inst, data.nzcv);
  AddEcvNZCVOperand(inst, kActionReadWrite);
  return true;
}

// CCMN  <Wn>, #<imm>, #<nzcv>, <cond>
bool TryDecodeCCMN_32_CONDCMP_IMM(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  SetConditionalFunctionName(data, inst);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rn);
  AddImmOperand(inst, data.imm5.uimm);
  AddImmOperand(inst, data.nzcv);
  AddEcvNZCVOperand(inst, kActionReadWrite);
  return true;
}

// CCMN  <Xn>, #<imm>, #<nzcv>, <cond>
bool TryDecodeCCMN_64_CONDCMP_IMM(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  SetConditionalFunctionName(data, inst);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rn);
  AddImmOperand(inst, data.imm5.uimm);
  AddImmOperand(inst, data.nzcv);
  AddEcvNZCVOperand(inst, kActionReadWrite);
  return true;
}

// ORR  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeORR_ASIMDSAME_ONLY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  std::stringstream ss;
  ss << inst.function << "_" << (data.Q ? "16B" : "8B");
  auto rclass = data.Q ? kReg2D : kReg1D;
  inst.function = ss.str();
  AddRegOperand(inst, kActionWrite, rclass, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rn);
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rm);
  return true;
}

// AND  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeAND_ASIMDSAME_ONLY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeORR_ASIMDSAME_ONLY(data, inst);
}

// BICS  <Wd>, <Wn>, <Wm>{, <shift> #<amount>}
bool TryDecodeBICS_32_LOG_SHIFT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  TryDecodeBIC_32_LOG_SHIFT(data, inst);
  AddEcvNZCVOperand(inst, kActionWrite);
  return true;
}

// BICS  <Xd>, <Xn>, <Xm>{, <shift> #<amount>}
bool TryDecodeBICS_64_LOG_SHIFT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  TryDecodeBIC_64_LOG_SHIFT(data, inst);
  AddEcvNZCVOperand(inst, kActionWrite);
  return true;
}

// LDARB  <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeLDARB_LR32_LDSTEXCL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 8, data.Rn, 0);
  return true;
}

// LDARH  <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeLDARH_LR32_LDSTEXCL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 16, data.Rn, 0);
  return true;
}

// LDAR  <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeLDAR_LR32_LDSTEXCL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 32, data.Rn, 0);
  return true;
}

// LDAR  <Xt>, [<Xn|SP>{,#0}]
bool TryDecodeLDAR_LR64_LDSTEXCL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 64, data.Rn, 0);
  return true;
}

// REV16  <Wd>, <Wn>
bool TryDecodeREV16_32_DP_1SRC(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeRdW_Rn(data, inst, kRegW);
}

// REV16  <Xd>, <Xn>
bool TryDecodeREV16_64_DP_1SRC(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeRdW_Rn(data, inst, kRegX);
}

// REV  <Wd>, <Wn>
bool TryDecodeREV_32_DP_1SRC(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeRdW_Rn(data, inst, kRegW);
}

// REV32  <Xd>, <Xn>
bool TryDecodeREV32_64_DP_1SRC(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeRdW_Rn(data, inst, kRegX);
}

// REV  <Xd>, <Xn>
bool TryDecodeREV_64_DP_1SRC(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeRdW_Rn(data, inst, kRegX);
}

// REV16  <Vd>.<T>, <Vn>.<T>
bool TryDecodeREV16_ASIMDMISC_R(const InstData &, Instruction &) {
  return false;
}

// REV32  <Vd>.<T>, <Vn>.<T>
bool TryDecodeREV32_ASIMDMISC_R(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  uint64_t total_size, elem_size;
  total_size = data.Q ? 128 : 64;
  elem_size = data.size ? 16 : 8;
  AddArrangementSpecifier(inst, total_size, elem_size);
  auto rclass = ArrangementRegClass(total_size, elem_size);
  AddRegOperand(inst, kActionWrite, rclass, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rn);
  return true;
}

// REV64  <Vd>.<T>, <Vn>.<T>
bool TryDecodeREV64_ASIMDMISC_R(const InstData &data, Instruction &inst) {
  return false;
}

static void AddQArrangementSpecifier(const InstData &data, Instruction &inst, const char *if_Q,
                                     const char *if_not_Q) {
  std::stringstream ss;
  ss << inst.function << "_" << (data.Q ? if_Q : if_not_Q);
  inst.function = ss.str();
}

static const char *ArrangementSpecifier(uint64_t total_size, uint64_t element_size,
                                        bool is_float = false) {
  if (128 == total_size) {
    switch (element_size) {
      case 8: return "16B";
      case 16: return "8H";
      case 32: return is_float ? "4SF" : "4S";
      case 64: return is_float ? "2DF" : "2D";
      default: break;
    }
  } else if (64 == total_size) {
    switch (element_size) {
      case 8: return "8B";
      case 16: return "4H";
      case 32: return is_float ? "2SF" : "2S";
      case 64: return is_float ? "1DF" : "1D";
      default: break;
    }
  }

  LOG(FATAL) << "Can't deduce specifier for " << total_size << "-vector with " << element_size
             << "-bit elements";
  return nullptr;
}

static void AddArrangementSpecifierUSHLL(Instruction &inst, uint64_t d_total_size,
                                         uint64_t d_elem_size, uint64_t s_total_size,
                                         uint64_t s_elem_size) {
  std::stringstream ss;
  ss << inst.function;
  ss << "_" << ArrangementSpecifier(d_total_size, d_elem_size)
     << ArrangementSpecifier(s_total_size, s_elem_size);
  inst.function = ss.str();
}

static void AddArrangementSpecifier(Instruction &inst, uint64_t total_size, uint64_t element_size) {
  std::stringstream ss;
  ss << inst.function;
  ss << "_" << ArrangementSpecifier(total_size, element_size);
  inst.function = ss.str();
}

static void AddArrangementSpecifierFloat(Instruction &inst, uint64_t total_size,
                                         uint64_t element_size) {
  std::stringstream ss;
  ss << inst.function;
  ss << "_" << ArrangementSpecifier(total_size, element_size, true);
  inst.function = ss.str();
}

static RegClass ArrangementRegClass(uint64_t total_size, uint64_t element_size, bool is_float) {
  if (128 == total_size) {
    switch (element_size) {
      case 8: return kReg16B;
      case 16: return kReg8H;
      case 32: return is_float ? kReg4SF : kReg4S;
      case 64: return is_float ? kReg2DF : kReg2D;
      default: break;
    }
  } else if (64 == total_size) {
    switch (element_size) {
      case 8: return kReg8B;
      case 16: return kReg4H;
      case 32: return is_float ? kReg2SF : kReg2S;
      case 64: return is_float ? kReg1DF : kReg1D;
      default: break;
    }
  }

  LOG(FATAL) << "Can't deduce specifier for " << total_size << "-vector with " << element_size
             << "-bit elements";
  return kReg16B;
}

// DUP  <Vd>.<T>, <R><n>
bool TryDecodeDUP_ASIMDINS_DR_R(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  uint64_t size = 0;
  uint64_t total_size, elem_size;
  if (!LeastSignificantSetBit(data.imm5.uimm, &size) || size > 3) {
    return false;  // `if size > 3 then UnallocatedEncoding();`
  } else if (size == 3 && !data.Q) {
    return false;  // `if size == 3 && Q == '0' then ReservedValue();`
  }
  total_size = data.Q ? 128 : 64;
  elem_size = 8UL << size;
  AddArrangementSpecifier(inst, total_size, elem_size);
  auto rclass = ArrangementRegClass(total_size, elem_size);
  AddRegOperand(inst, kActionWrite, rclass, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, size == 3 ? kRegX : kRegW, kUseAsValue, data.Rn);
  return true;
}

// DUP  <Vd>.<T>, <Vn>.<Ts>[<index>]
bool TryDecodeDUP_ASIMDINS_DV_V(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  uint64_t size = 4;
  auto imm5 = data.imm5.uimm;
  for (uint8_t i = 0; i < 4; i++) {
    if ((imm5 >> i) & 1) {
      size = i;
      break;
    }
  }
  if (4 == size) {
    std::__throw_runtime_error("[ERROR] invalid imm5 at TryDecodeDUP_ASIMDINS_DV_V\n");
  }
  AddArrangementSpecifier(inst, data.Q ? 128 : 64, 8UL << size);
  auto rclass = ArrangementRegClass(data.Q ? 128 : 64, 8UL << size);
  AddRegOperand(inst, kActionWrite, rclass, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rn);
  AddImmOperand(inst, data.imm5.uimm >> (size + 1), kUnsigned, 32);
  return true;
}

// ADD  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeADD_ASIMDSAME_ONLY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  uint64_t total_size, elem_size;
  if (0x3 == data.size && !data.Q) {
    return false;  // `if size:Q == '110' then ReservedValue();`.
  }
  total_size = data.Q ? 128 : 64;
  elem_size = 8UL << data.size;
  AddArrangementSpecifier(inst, total_size, elem_size);
  auto rclass = ArrangementRegClass(total_size, elem_size);
  return TryDecodeRdW_Rn_Rm(data, inst, rclass);
}

// SUB  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeSUB_ASIMDSAME_ONLY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeADD_ASIMDSAME_ONLY(data, inst);
}

static bool TryDecodeLDnSTnOpcode(uint8_t opcode, uint64_t *rpt, uint64_t *selem) {
  switch (opcode) {
    case 0:  // `0000`, LD/ST4 (4 registers).
      *rpt = 1;
      *selem = 4;
      return true;
    case 2:  // `0010`, LD/ST1 (4 registers).
      *rpt = 4;
      *selem = 1;
      return true;
    case 4:  // `0100`, LD/ST3 (3 registers).
      *rpt = 1;
      *selem = 3;
      return true;
    case 6:  // `0110`, LD/ST1 (3 registers).
      *rpt = 3;
      *selem = 1;
      return true;
    case 7:  // `0111`, LD/ST1 (1 register).
      *rpt = 1;
      *selem = 1;
      return true;
    case 8:  // `1000`, LD/ST2 (2 registers).
      *rpt = 1;
      *selem = 2;
      return true;
    case 10:  // `1010`, LD/ST1 (2 registers).
      *rpt = 2;
      *selem = 1;
      return true;
    default: return false;  // `UnallocatedEncoding();`.
  }
}

// EXT  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>, #<index>
bool TryDecodeEXT_ASIMDEXT_ONLY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (!data.Q && data.imm4.uimm & 0x8) {
    return false;  // `if Q == '0' and imm4<3> == '1' then UnallocatedEncoding();`
  }
  AddQArrangementSpecifier(data, inst, "16B", "8B");
  auto rclass = data.Q ? kReg16B : kReg8B;
  TryDecodeRdW_Rn_Rm(data, inst, rclass);
  AddImmOperand(inst, data.imm4.uimm, kUnsigned, 32);
  return true;
}

// Store one or more data structures.
bool TryDecodeSTn(const InstData &data, Instruction &inst, uint64_t *total_num_bytes) {
  uint64_t rpt = 0;
  uint64_t selem = 0;
  if (!TryDecodeLDnSTnOpcode(data.opcode, &rpt, &selem)) {
    return false;
  } else if (0x3 == data.size && !data.Q && selem != 1) {
    return false;  // `if size:Q == '110' && selem != 1 then ReservedValue()`.
  }
  uint64_t data_size = data.Q ? 128 : 64;
  uint64_t esize = 8UL << data.size;
  uint64_t elements = data_size / esize;
  uint64_t ebytes = esize / 8;
  if (total_num_bytes) {
    *total_num_bytes = ebytes * rpt * elements * selem;
  }
  AddArrangementSpecifier(inst, data_size, 8UL << data.size);
  auto t = static_cast<uint8_t>(data.Rt);
  auto num_regs = static_cast<uint8_t>(rpt * selem);
  for (uint8_t i = 0; i < num_regs; ++i) {
    auto tt = static_cast<aarch64::RegNum>((t + i) % 32);
    AddRegOperand(inst, kActionWrite, data.Q ? K_REG_Q : kRegD, kUseAsValue, tt);
  }
  return true;
}

// Load one or more data structures.
bool TryDecodeLDn(const InstData &data, Instruction &inst, uint64_t *total_num_bytes) {
  uint64_t rpt = 0;
  uint64_t selem = 0;
  if (!TryDecodeLDnSTnOpcode(data.opcode, &rpt, &selem)) {
    return false;
  } else if (0x3 == data.size && !data.Q && selem != 1) {
    return false;  // `if size:Q == '110' && selem != 1 then ReservedValue()`.
  }
  uint64_t data_size = data.Q ? 128 : 64;
  uint64_t esize = 8UL << data.size;
  uint64_t elements = data_size / esize;
  uint64_t ebytes = esize / 8;
  if (total_num_bytes) {
    *total_num_bytes = ebytes * rpt * elements * selem;
  }
  AddArrangementSpecifier(inst, data_size, 8UL << data.size);
  auto t = static_cast<uint8_t>(data.Rt);
  auto num_regs = static_cast<uint8_t>(rpt * selem);
  for (uint8_t i = 0; i < num_regs; ++i) {
    auto tt = static_cast<aarch64::RegNum>((t + i) % 32);
    AddRegOperand(inst, kActionWrite, ArrangementRegClass(data_size, esize), kUseAsValue, tt);
  }
  return true;
}

// ST1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>
bool TryDecodeST1_ASISDLSEP_I2_I2(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  uint64_t offset = 0;
  if (!TryDecodeSTn(data, inst, &offset)) {
    return false;
  }
  AddPostIndexMemOp(inst, offset * 8, data.Rn, offset);
  return true;
}

// ST1  { <Vt>.<T> }, [<Xn|SP>]
bool TryDecodeST1_ASISDLSE_R1_1V(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  uint64_t num_bytes = 0;
  if (!TryDecodeSTn(data, inst, &num_bytes)) {
    return false;
  }
  AddBasePlusOffsetMemOp(inst, num_bytes * 8, data.Rn, 0);
  return true;
}

// ST1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]
bool TryDecodeST1_ASISDLSE_R2_2V(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeST1_ASISDLSE_R1_1V(data, inst);
}

// ST1  { <Vt>.B }[<index>], [<Xn|SP>]
bool TryDecodeST1_ASISDLSO_B1_1B(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kReg16B, kUseAsValue, data.Rt);
  auto index = data.Q << 3 | data.S << 2 | data.size;
  AddImmOperand(inst, index);
  AddBasePlusOffsetMemOp(inst, 8, data.Rn, 0);
  return true;
}

// ST1  { <Vt>.H }[<index>], [<Xn|SP>]
bool TryDecodeST1_ASISDLSO_H1_1H(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kReg8H, kUseAsValue, data.Rt);
  auto index = data.Q << 2 | data.S << 1 | data.size >> 1;
  AddImmOperand(inst, index);
  AddBasePlusOffsetMemOp(inst, 16, data.Rn, 0);
  return true;
}

// ST1  { <Vt>.S }[<index>], [<Xn|SP>]
bool TryDecodeST1_ASISDLSO_S1_1S(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kReg4S, kUseAsValue, data.Rt);
  auto index = data.Q << 1 | data.S;
  AddImmOperand(inst, index);
  AddBasePlusOffsetMemOp(inst, 32, data.Rn, 0);
  return true;
}

// ST1  { <Vt>.D }[<index>], [<Xn|SP>]
bool TryDecodeST1_ASISDLSO_D1_1D(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kReg2D, kUseAsValue, data.Rt);
  auto index = data.Q;
  AddImmOperand(inst, index);
  AddBasePlusOffsetMemOp(inst, 64, data.Rn, 0);
  return true;
}

// ST1  { <Vt>.B }[<index>], [<Xn|SP>], #1
bool TryDecodeST1_ASISDLSOP_B1_I1B(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kReg16B, kUseAsValue, data.Rt);
  auto index = data.Q << 3 | data.S << 2 | data.size;
  AddImmOperand(inst, index);
  AddPostIndexMemOp(inst, 8, data.Rn, 1);
  return true;
}

// ST1  { <Vt>.B }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeST1_ASISDLSOP_BX1_R1B(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kReg16B, kUseAsValue, data.Rt);
  auto index = data.Q << 3 | data.S << 2 | data.size;
  AddImmOperand(inst, index);
  AddPostIndexMemOp(inst, 8, data.Rn, data.Rm);
  return true;
}

// ST1  { <Vt>.H }[<index>], [<Xn|SP>], #2
bool TryDecodeST1_ASISDLSOP_H1_I1H(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kReg8H, kUseAsValue, data.Rt);
  auto index = data.Q << 2 | data.S << 1 | data.size >> 1;
  AddImmOperand(inst, index);
  AddPostIndexMemOp(inst, 16, data.Rn, 2);
  return true;
}

// ST1  { <Vt>.H }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeST1_ASISDLSOP_HX1_R1H(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kReg8H, kUseAsValue, data.Rt);
  auto index = data.Q << 2 | data.S << 1 | data.size >> 1;
  AddImmOperand(inst, index);
  AddPostIndexMemOp(inst, 16, data.Rn, data.Rm);
  return true;
}

// ST1  { <Vt>.S }[<index>], [<Xn|SP>], #4
bool TryDecodeST1_ASISDLSOP_S1_I1S(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kReg4S, kUseAsValue, data.Rt);
  auto index = data.Q << 1 | data.S;
  AddImmOperand(inst, index);
  AddPostIndexMemOp(inst, 32, data.Rn, 4);
  return true;
}

// ST1  { <Vt>.S }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeST1_ASISDLSOP_SX1_R1S(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kReg4S, kUseAsValue, data.Rt);
  auto index = data.Q << 1 | data.S;
  AddImmOperand(inst, index);
  AddPostIndexMemOp(inst, 32, data.Rn, data.Rm);
  return true;
}

// ST1  { <Vt>.D }[<index>], [<Xn|SP>], #8
bool TryDecodeST1_ASISDLSOP_D1_I1D(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kReg2D, kUseAsValue, data.Rt);
  auto index = data.Q;
  AddImmOperand(inst, index);
  AddPostIndexMemOp(inst, 64, data.Rn, 8);
  return true;
}

// ST1  { <Vt>.D }[<index>], [<Xn|SP>], <Xm>
bool TryDecodeST1_ASISDLSOP_DX1_R1D(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionRead, kReg2D, kUseAsValue, data.Rt);
  auto index = data.Q;
  AddImmOperand(inst, index);
  AddPostIndexMemOp(inst, 64, data.Rn, data.Rm);
  return true;
}

// LD1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>
bool TryDecodeLD1_ASISDLSEP_I2_I2(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  uint64_t offset = 0;
  if (!TryDecodeLDn(data, inst, &offset)) {
    return false;
  }
  AddPostIndexMemOp(inst, offset * 8, data.Rn, offset);
  return true;
}

// LD1  { <Vt>.<T> }, [<Xn|SP>], <imm>
bool TryDecodeLD1_ASISDLSEP_I1_I1(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLD1_ASISDLSEP_I2_I2(data, inst);
}

// LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>], <imm>
bool TryDecodeLD1_ASISDLSEP_I3_I3(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLD1_ASISDLSEP_I2_I2(data, inst);
}

// LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>], <imm>
bool TryDecodeLD1_ASISDLSEP_I4_I4(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLD1_ASISDLSEP_I2_I2(data, inst);
}

// CMEQ  <Vd>.<T>, <Vn>.<T>, #0
bool TryDecodeCMEQ_ASIMDMISC_Z(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  uint64_t total_size, elem_size;
  if (data.size == 3 && !data.Q) {
    return false;  // `if size:Q == '110' then ReservedValue();`.
  }
  total_size = data.Q ? 128 : 64;
  elem_size = 8UL << data.size;
  AddArrangementSpecifier(inst, total_size, elem_size);
  TryDecodeRdW_Rn(data, inst, ArrangementRegClass(total_size, elem_size));
  AddImmOperand(inst, 0, kUnsigned, 8UL << data.size);
  return true;
}

// CMLT  <Vd>.<T>, <Vn>.<T>, #0
bool TryDecodeCMLT_ASIMDMISC_Z(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeCMEQ_ASIMDMISC_Z(data, inst);
}

// CMLE  <Vd>.<T>, <Vn>.<T>, #0
bool TryDecodeCMLE_ASIMDMISC_Z(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeCMEQ_ASIMDMISC_Z(data, inst);
}

// CMGT  <Vd>.<T>, <Vn>.<T>, #0
bool TryDecodeCMGT_ASIMDMISC_Z(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeCMEQ_ASIMDMISC_Z(data, inst);
}

// CMGE  <Vd>.<T>, <Vn>.<T>, #0
bool TryDecodeCMGE_ASIMDMISC_Z(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeCMEQ_ASIMDMISC_Z(data, inst);
}

// CMGE  <V><d>, <V><n>, #0
bool TryDecodeCMGE_ASISDMISC_Z(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (data.size != 0b11) {
    return false;  // size must be 0b11
  }
  AddRegOperand(inst, kActionWrite, kReg2D, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kReg2D, kUseAsValue, data.Rn);
  return true;
}

// CMEQ  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeCMEQ_ASIMDSAME_ONLY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  uint64_t total_size, elem_size;
  if (data.size == 3 && !data.Q) {
    return false;  // `if size:Q == '110' then ReservedValue();`.
  }
  total_size = data.Q ? 128 : 64;
  elem_size = 8UL << data.size;
  AddArrangementSpecifier(inst, total_size, elem_size);
  return TryDecodeRdW_Rn_Rm(data, inst, ArrangementRegClass(total_size, elem_size));
}

// CMGE  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeCMGE_ASIMDSAME_ONLY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeCMEQ_ASIMDSAME_ONLY(data, inst);
}

// CMGT  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeCMGT_ASIMDSAME_ONLY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeCMEQ_ASIMDSAME_ONLY(data, inst);
}

// CMTST  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeCMTST_ASIMDSAME_ONLY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeCMEQ_ASIMDSAME_ONLY(data, inst);
}

// CMHS  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeCMHS_ASIMDSAME_ONLY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeCMEQ_ASIMDSAME_ONLY(data, inst);
}

// ADDP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeADDP_ASIMDSAME_ONLY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeADD_ASIMDSAME_ONLY(data, inst);
}

// UMAXP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeUMAXP_ASIMDSAME_ONLY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  uint64_t total_size, elem_size;
  if (0x3 == data.size) {
    return false;  // `if size == '11' then ReservedValue();`.
  }
  total_size = data.Q ? 128 : 64;
  elem_size = 8UL << data.size;
  AddArrangementSpecifier(inst, total_size, elem_size);
  return TryDecodeRdW_Rn_Rm(data, inst, ArrangementRegClass(total_size, elem_size));
}

// SMAXP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeSMAXP_ASIMDSAME_ONLY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeUMAXP_ASIMDSAME_ONLY(data, inst);
}

// UMINP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeUMINP_ASIMDSAME_ONLY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeUMAXP_ASIMDSAME_ONLY(data, inst);
}

// SMINP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeSMINP_ASIMDSAME_ONLY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeUMAXP_ASIMDSAME_ONLY(data, inst);
}

// UMIN  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeUMIN_ASIMDSAME_ONLY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeUMAXP_ASIMDSAME_ONLY(data, inst);
}

// UMAX  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeUMAX_ASIMDSAME_ONLY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeUMAXP_ASIMDSAME_ONLY(data, inst);
}

// SMIN  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeSMIN_ASIMDSAME_ONLY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeUMAXP_ASIMDSAME_ONLY(data, inst);
}

// SMAX  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeSMAX_ASIMDSAME_ONLY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeUMAXP_ASIMDSAME_ONLY(data, inst);
}

// FMLA  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFMLA_ASIMDSAME_ONLY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  uint64_t total_size, elem_size;
  total_size = data.Q ? 128 : 64;
  if (0b00001 /* half-precistion */ == data.opcode) {
    elem_size = 16;
  } else if (0b11001 /* (single | double)-precision */ == data.opcode) {
    elem_size = data.sz ? 64 : 32;
  } else {
    std::__throw_runtime_error(
        "[ERROR] invalid opcode of InstData at 'TryDecodeFMLA_ASIMDSAME_ONLY'\n");
  }
  AddArrangementSpecifier(inst, total_size, elem_size);
  auto rclass = ArrangementRegClass(total_size, elem_size, true);
  AddRegOperand(inst, kActionReadWrite, rclass, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rn);
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rm);
  return true;
}

// FMLA  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
bool TryDecodeFMLA_ASIMDELEM_R_SD(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  uint64_t total_size, elem_size, index;
  total_size = data.Q ? 128 : 64;
  if (0b011111 /* (single | double)-precision */ == data.opcode) {
    elem_size = data.sz ? 64 : 32;
  } else {
    std::__throw_runtime_error(
        "[ERROR] invalid opcode of InstData at 'TryDecodeFMLA_ASIMDELEM_R_SD'\n");
  }
  if (0 == data.sz) {
    index = (data.H << 1) + data.L;
  } else if (1 == data.sz && 0 == data.L) {
    index = data.H;
  } else {
    std::__throw_runtime_error(
        "[ERROR] invalid 'sz' or 'L' of InstData at TryDecodeFMLA_ASIMDELEM_R_SD\n");
  }
  AddArrangementSpecifier(inst, total_size, elem_size);
  auto rclass = ArrangementRegClass(total_size, elem_size, true);
  AddRegOperand(inst, kActionReadWrite, rclass, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rn);
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rm);
  AddImmOperand(inst, index, kUnsigned, 64);
  return true;
}

// FADD  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFADD_ASIMDSAME_ONLY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  uint64_t total_size, elem_size;
  total_size = data.Q ? 128 : 64;
  if (0b00010 /* half-precision */ == data.opcode) {
    elem_size = 16;
  } else if (0b11010 /* (single | double)-precision */ == data.opcode) {
    elem_size = data.sz ? 64 : 32;
  } else {
    std::__throw_runtime_error(
        "[ERROR] invaild opcode of InstData at TryDecodeFADD_ASIMDSAME_ONLY\n");
  }
  AddArrangementSpecifier(inst, total_size, elem_size);
  auto rclass = ArrangementRegClass(total_size, elem_size, true);
  AddRegOperand(inst, kActionWrite, rclass, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rn);
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rm);
  return true;
}

// FSUB  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFSUB_ASIMDSAME_ONLY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  uint64_t total_size, elem_size;
  if (1 == data.sz && 0 == data.Q) {
    return false;
  }
  total_size = data.Q ? 128 : 64;
  elem_size = 32 << data.sz;
  AddArrangementSpecifierFloat(inst, total_size, elem_size);
  auto rclass = ArrangementRegClass(total_size, elem_size, true);
  return TryDecodeRdW_Rn_Rm(data, inst, rclass);
}

// FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeFMUL_ASIMDSAME_ONLY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  uint64_t total_size, elem_size;
  total_size = data.Q ? 128 : 64;
  if (0b00011 /* half-precision */ == data.opcode) {
    elem_size = 16;
  } else if (0b11011 /* (single | double)-precision */ == data.opcode) {
    elem_size = data.sz ? 64 : 32;
  } else {
    std::__throw_runtime_error(
        "[ERROR] invalid opcode of InstData at 'TryDecodeFMUL_ASIMDSAME_ONLY'\n");
  }
  AddArrangementSpecifier(inst, total_size, elem_size);
  auto rclass = ArrangementRegClass(total_size, elem_size, true);
  AddRegOperand(inst, kActionWrite, rclass, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rn);
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rm);
  return true;
}

// FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
bool TryDecodeFMUL_ASIMDELEM_R_SD(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  int index;
  uint64_t total_size, elem_size;
  total_size = data.Q ? 128 : 64;
  elem_size = data.sz ? 64 : 32;
  if (0 == data.sz) {
    index = (data.H << 1) + data.L;
  } else if (1 == data.sz && 0 == data.L) {
    index = data.H;
  } else {
    std::__throw_runtime_error(
        "[ERROR] invalid 'sz' or 'L' of InstData at TryDecodeFMUL_ASIMDELEM_R_SD\n");
  }
  AddArrangementSpecifier(inst, total_size, elem_size);
  auto rclass = ArrangementRegClass(total_size, elem_size, true);
  AddRegOperand(inst, kActionWrite, rclass, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rn);
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rm);
  AddImmOperand(inst, index, kUnsigned, 32);
  return true;
}

// UMOV  <Wd>, <Vn>.<Ts>[<index>]
bool TryDecodeUMOV_ASIMDINS_W_W(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  uint64_t size = 0;
  if (!LeastSignificantSetBit(data.imm5.uimm, &size) || size > 3) {
    return false;  // `if size > 3 then UnallocatedEncoding();`
  } else if (data.Q && size < 3) {
    return false;
  }
  RegClass rclass;
  std::stringstream ss;
  ss << inst.function;
  switch (size) {
    case 0:
      ss << "_B";
      rclass = kReg16B;
      break;
    case 1:
      ss << "_H";
      rclass = kReg8H;
      break;
    case 2:
      ss << "_S";
      rclass = kReg4S;
      break;
    case 3:
      ss << "_D";
      rclass = kReg2D;
      break;
    default: return false;
  }
  inst.function = ss.str();
  AddRegOperand(inst, kActionWrite, data.Q ? kRegX : kRegW, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rn);
  AddImmOperand(inst, data.imm5.uimm >> (size + 1));
  return true;
}

// UMOV  <Xd>, <Vn>.<Ts>[<index>]
bool TryDecodeUMOV_ASIMDINS_X_X(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeUMOV_ASIMDINS_W_W(data, inst);
}

// SMOV  <Wd>, <Vn>.<Ts>[<index>]
bool TryDecodeSMOV_ASIMDINS_W_W(const InstData &data, Instruction &inst) {
  uint64_t size = 0;
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (!LeastSignificantSetBit(data.imm5.uimm, &size) || size > 2) {
    return false;  // `if size > 3 then UnallocatedEncoding();`
  } else if (size == 2 && !data.Q) {
    return false;
  }
  std::stringstream ss;
  RegClass rclass;
  ss << inst.function;
  switch (size) {
    case 0:
      ss << "_B";
      rclass = kReg16B;
      break;
    case 1:
      ss << "_H";
      rclass = kReg8H;
      break;
    case 2:
      ss << "_S";
      rclass = kReg4S;
      break;
    default: return false;
  }
  inst.function = ss.str();
  AddRegOperand(inst, kActionWrite, data.Q ? kRegX : kRegW, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rn);
  AddImmOperand(inst, data.imm5.uimm >> (size + 1));
  return true;
}

// SMOV  <Xd>, <Vn>.<Ts>[<index>]
bool TryDecodeSMOV_ASIMDINS_X_X(const InstData &data, Instruction &inst) {
  return TryDecodeSMOV_ASIMDINS_W_W(data, inst);
}

// RBIT  <Wd>, <Wn>
bool TryDecodeRBIT_32_DP_1SRC(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeRdW_Rn(data, inst, kRegW);
}

// RBIT  <Xd>, <Xn>
bool TryDecodeRBIT_64_DP_1SRC(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeRdW_Rn(data, inst, kRegX);
}

// SDIV  <Wd>, <Wn>, <Wm>
bool TryDecodeSDIV_32_DP_2SRC(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeRdW_Rn_Rm(data, inst, kRegW);
}

// SDIV  <Xd>, <Xn>, <Xm>
bool TryDecodeSDIV_64_DP_2SRC(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeRdW_Rn_Rm(data, inst, kRegX);
}

static bool TryDecodeSCVTF_Sn_FLOAT2INT(const InstData &data, Instruction &inst,
                                        RegClass dest_class, RegClass src_class) {
  if (0x3 == data.type) {
    return false;  // `case type of ... when '10' UnallocatedEncoding();`
  }
  AddRegOperand(inst, kActionWrite, dest_class, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, src_class, kUseAsValue, data.Rn);
  return true;
}

// SCVTF  <Hd>, <Wn>
bool TryDecodeSCVTF_H32_FLOAT2INT(const InstData &data, Instruction &inst) {
  return TryDecodeSCVTF_Sn_FLOAT2INT(data, inst, kRegH, kRegW);
}

// SCVTF  <Sd>, <Wn>
bool TryDecodeSCVTF_S32_FLOAT2INT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeSCVTF_Sn_FLOAT2INT(data, inst, kRegS, kRegW);
}

// SCVTF  <Dd>, <Wn>
bool TryDecodeSCVTF_D32_FLOAT2INT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeSCVTF_Sn_FLOAT2INT(data, inst, kRegD, kRegW);
}

// SCVTF  <Hd>, <Xn>
bool TryDecodeSCVTF_H64_FLOAT2INT(const InstData &data, Instruction &inst) {
  return TryDecodeSCVTF_Sn_FLOAT2INT(data, inst, kRegH, kRegX);
}

// SCVTF  <Sd>, <Xn>
bool TryDecodeSCVTF_S64_FLOAT2INT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeSCVTF_Sn_FLOAT2INT(data, inst, kRegS, kRegX);
}

// SCVTF  <Dd>, <Xn>
bool TryDecodeSCVTF_D64_FLOAT2INT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeSCVTF_Sn_FLOAT2INT(data, inst, kRegD, kRegX);
}

// SCVTF  <V><d>, <V><n>
bool TryDecodeSCVTF_ASISDMISC_R(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  RegClass rclass;
  if (1 == data.sz) {
    inst.function += "_64";
    rclass = kReg2D;
  } else {
    inst.function += "_32";
    rclass = kReg4S;
  }
  return TryDecodeSCVTF_Sn_FLOAT2INT(data, inst, rclass, rclass);
}

// SCVTF  <Vd>.<T>, <Vn>.<T> (only 32bit or 64bit)
bool TryDecodeSCVTF_ASIMDMISC_R(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  uint64_t total_size, elem_size;
  total_size = data.Q ? 128 : 64;
  elem_size = data.sz ? 64 : 32;
  AddArrangementSpecifier(inst, total_size, elem_size);
  auto rclass = ArrangementRegClass(total_size, elem_size);
  AddRegOperand(inst, kActionWrite, rclass, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rn);
  return true;
}

// BIC  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeBIC_ASIMDSAME_ONLY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeORR_ASIMDSAME_ONLY(data, inst);
}

// EOR  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeEOR_ASIMDSAME_ONLY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeORR_ASIMDSAME_ONLY(data, inst);
}

// BIT  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeBIT_ASIMDSAME_ONLY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  AddQArrangementSpecifier(data, inst, "16B", "8B");
  auto rclass = data.Q ? kReg2D : kReg1D;

  AddRegOperand(inst, kActionReadWrite, rclass, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rn);
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rm);
  return true;
}

// BIF  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeBIF_ASIMDSAME_ONLY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeBIT_ASIMDSAME_ONLY(data, inst);
}

// BSL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
bool TryDecodeBSL_ASIMDSAME_ONLY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeBIT_ASIMDSAME_ONLY(data, inst);
}

// ADDV  <V><d>, <Vn>.<T>
bool TryDecodeADDV_ASIMDALL_ONLY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (data.size == 0x2 && !data.Q) {
    return false;  // `if size:Q == '100' then ReservedValue();`
  } else if (data.size == 0x3) {
    return false;  // `if size == '11' then ReservedValue();`.
  }
  const uint64_t elem_size = 8ULL << data.size;
  const uint64_t total_size = data.Q ? 128 : 64;
  AddArrangementSpecifier(inst, total_size, elem_size);
  auto rclass = ArrangementRegClass(total_size, elem_size);
  AddRegOperand(inst, kActionWrite, rclass, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rn);
  return true;
}

// UMINV  <V><d>, <Vn>.<T>
bool TryDecodeUMINV_ASIMDALL_ONLY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeADDV_ASIMDALL_ONLY(data, inst);
}

// UMAXV  <V><d>, <Vn>.<T>
bool TryDecodeUMAXV_ASIMDALL_ONLY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeADDV_ASIMDALL_ONLY(data, inst);
}

// SMAXV  <V><d>, <Vn>.<T>
bool TryDecodeSMAXV_ASIMDALL_ONLY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeADDV_ASIMDALL_ONLY(data, inst);
}

// SMINV  <V><d>, <Vn>.<T>
bool TryDecodeSMINV_ASIMDALL_ONLY(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeADDV_ASIMDALL_ONLY(data, inst);
}

// FMAXV  <V><d>, <Vn>.<T>
bool TryDecodeFMAXV_ASIMDALL_ONLY_H(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  AddQArrangementSpecifier(data, inst, "8H", "4H");
  auto rclass = data.Q ? kReg8H : kReg4H;
  AddRegOperand(inst, kActionWrite, rclass, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rn);
  return true;
}

// FMAXV  <V><d>, <Vn>.<T>
bool TryDecodeFMAXV_ASIMDALL_ONLY_SD(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (!(!data.sz && data.Q)) {
    return false;  // `if sz:Q != '01' then ReservedValue();`
  }
  inst.function += "_4S";
  AddRegOperand(inst, kActionWrite, kReg4S, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kReg4S, kUseAsValue, data.Rn);
  return true;
}

// FMINNMV  <V><d>, <Vn>.<T>
bool TryDecodeFMINNMV_ASIMDALL_ONLY_H(const InstData &data, Instruction &inst) {
  return TryDecodeFMAXV_ASIMDALL_ONLY_H(data, inst);
}

// FMINNMV  <V><d>, <Vn>.<T>
bool TryDecodeFMINNMV_ASIMDALL_ONLY_SD(const InstData &data, Instruction &inst) {
  return TryDecodeFMAXV_ASIMDALL_ONLY_SD(data, inst);
}

// FMAXNMV  <V><d>, <Vn>.<T>
bool TryDecodeFMAXNMV_ASIMDALL_ONLY_H(const InstData &data, Instruction &inst) {
  return TryDecodeFMAXV_ASIMDALL_ONLY_H(data, inst);
}

// FMAXNMV  <V><d>, <Vn>.<T>
bool TryDecodeFMAXNMV_ASIMDALL_ONLY_SD(const InstData &data, Instruction &inst) {
  return TryDecodeFMAXV_ASIMDALL_ONLY_SD(data, inst);
}

// FMINV  <V><d>, <Vn>.<T>
bool TryDecodeFMINV_ASIMDALL_ONLY_H(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeFMAXV_ASIMDALL_ONLY_H(data, inst);
}

// FMINV  <V><d>, <Vn>.<T>
bool TryDecodeFMINV_ASIMDALL_ONLY_SD(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return TryDecodeFMAXV_ASIMDALL_ONLY_SD(data, inst);
}

// UADDLV  <V><d>, <Vn>.<T>
bool TryDecodeUADDLV_ASIMDALL_ONLY(const InstData &, Instruction &) {
  return false;
}

// SADDLV  <V><d>, <Vn>.<T>
bool TryDecodeSADDLV_ASIMDALL_ONLY(const InstData &, Instruction &) {
  return false;
}

// DMB  <option>|#<imm>
bool TryDecodeDMB_BO_SYSTEM(const InstData &, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return true;
}

// INS  <Vd>.<Ts>[<index>], <R><n>
bool TryDecodeINS_ASIMDINS_IR_R(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  uint64_t size = 0;
  if (!LeastSignificantSetBit(data.imm5.uimm, &size) || size > 3) {
    return false;
  }
  RegClass rclass;
  std::stringstream ss;
  ss << inst.function;
  switch (size) {
    case 0:
      ss << "_B";
      rclass = kReg16B;
      break;
    case 1:
      ss << "_H";
      rclass = kReg8H;
      break;
    case 2:
      ss << "_S";
      rclass = kReg4S;
      break;
    case 3:
      ss << "_D";
      rclass = kReg2D;
      break;
    default: return false;
  }
  inst.function = ss.str();

  AddRegOperand(inst, kActionReadWrite, rclass, kUseAsValue, data.Rd);
  AddImmOperand(inst, data.imm5.uimm >> (size + 1));
  AddRegOperand(inst, kActionRead, (size == 3) ? kRegX : kRegW, kUseAsValue, data.Rn);
  return true;
}

// MOV  <Vd>.<Ts>[<index1>], <Vn>.<Ts>[<index2>]
bool TryDecodeMOV_INS_ASIMDINS_IV_V(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  uint64_t size = 0;
  if (!LeastSignificantSetBit(data.imm5.uimm, &size) || size > 3) {
    return false;
  }
  RegClass rclass;
  std::stringstream ss;
  ss << inst.function;
  switch (size) {
    case 0:
      ss << "_B";
      rclass = kReg16B;
      break;
    case 1:
      ss << "_H";
      rclass = kReg8H;
      break;
    case 2:
      ss << "_S";
      rclass = kReg4S;
      break;
    case 3:
      ss << "_D";
      rclass = kReg2D;
      break;
    default: return false;
  }
  inst.function = ss.str();

  AddRegOperand(inst, kActionReadWrite, rclass, kUseAsValue, data.Rd);
  AddImmOperand(inst, data.imm5.uimm >> (size + 1));
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rn);
  AddImmOperand(inst, data.imm4.uimm >> size);
  return true;
}

// LD1  { <Vt>.<T> }, [<Xn|SP>]
bool TryDecodeLD1_ASISDLSE_R1_1V(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  uint64_t num_bytes = 0;
  if (!TryDecodeLDn(data, inst, &num_bytes)) {
    return false;
  }
  AddBasePlusOffsetMemOp(inst, num_bytes * 8, data.Rn, 0);
  return true;
}

// LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]
bool TryDecodeLD2_ASISDLSE_R2(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  if (data.size == 0x3 && !data.Q) {
    return false;  // Reserved (arrangement specifier 1D).
  }
  return TryDecodeLD1_ASISDLSE_R1_1V(data, inst);
}

// LD3  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>]
bool TryDecodeLD3_ASISDLSE_R3(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLD2_ASISDLSE_R2(data, inst);
}

// LD4  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>]
bool TryDecodeLD4_ASISDLSE_R4(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLD2_ASISDLSE_R2(data, inst);
}

// LD1  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]
bool TryDecodeLD1_ASISDLSE_R2_2V(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLD1_ASISDLSE_R1_1V(data, inst);
}

// LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>]
bool TryDecodeLD1_ASISDLSE_R3_3V(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLD1_ASISDLSE_R1_1V(data, inst);
}

// LD1  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>]
bool TryDecodeLD1_ASISDLSE_R4_4V(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLD1_ASISDLSE_R1_1V(data, inst);
}

// LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>
bool TryDecodeLD2_ASISDLSEP_I2_I(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLD1_ASISDLSEP_I2_I2(data, inst);
}

// LD2  { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <Xm>
bool TryDecodeLD2_ASISDLSEP_R2_R(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  uint64_t offset = 0;
  if (!TryDecodeLDn(data, inst, &offset)) {
    return false;
  }
  AddPostIndexMemOp(inst, offset * 8, data.Rn, data.Rm);
  return true;
}

// LD1R  { <Vt>.<T> }, [<Xn|SP>]
bool TryDecodeLD1R_ASISDLSO_R1(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  auto elem_size = 8UL << data.size;
  auto total_size = data.Q ? 128 : 64;
  AddRegOperand(inst, kActionWrite, ArrangementRegClass(total_size, elem_size), kUseAsValue,
                data.Rt);
  AddArrangementSpecifier(inst, total_size, elem_size);
  AddBasePlusOffsetMemOp(inst, elem_size, data.Rn, 0);
  return true;
}

// LD4  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>], <imm>
bool TryDecodeLD4_ASISDLSEP_I4_I(const InstData &, Instruction &) {
  return false;
}

// LD4  { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>], <Xm>
bool TryDecodeLD4_ASISDLSEP_R4_R(const InstData &, Instruction &) {
  return false;
}

// NOT  <Vd>.<T>, <Vn>.<T>
bool TryDecodeNOT_ASIMDMISC_R(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  const uint64_t total_size = data.Q ? 128 : 64;
  AddArrangementSpecifier(inst, total_size, 8);
  auto rclass = ArrangementRegClass(total_size, 8);
  AddRegOperand(inst, kActionWrite, rclass, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rn);
  return true;
}

// LDAXR  <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeLDAXR_LR32_LDSTEXCL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDXR_LR32_LDSTEXCL(data, inst);
}

// LDAXR  <Xt>, [<Xn|SP>{,#0}]
bool TryDecodeLDAXR_LR64_LDSTEXCL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  return TryDecodeLDXR_LR64_LDSTEXCL(data, inst);
}

// LDXR  <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeLDXR_LR32_LDSTEXCL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  inst.is_atomic_read_modify_write = true;
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 32, data.Rn, 0);
  AddMonitorOperand(inst, kActionWrite);
  return true;
}

// LDXR  <Xt>, [<Xn|SP>{,#0}]
bool TryDecodeLDXR_LR64_LDSTEXCL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  inst.is_atomic_read_modify_write = true;
  AddRegOperand(inst, kActionWrite, kRegX, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 64, data.Rn, 0);
  AddMonitorOperand(inst, kActionWrite);
  return true;
}

// STLXR  <Ws>, <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeSTLXR_SR32_LDSTEXCL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  inst.is_atomic_read_modify_write = true;
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rs);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 32, data.Rn, 0);
  AddMonitorOperand(inst, kActionReadWrite);
  return true;
}

// STLXR  <Ws>, <Xt>, [<Xn|SP>{,#0}]
bool TryDecodeSTLXR_SR64_LDSTEXCL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  inst.is_atomic_read_modify_write = true;
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rs);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 64, data.Rn, 0);
  AddMonitorOperand(inst, kActionReadWrite);
  return true;
}

static uint64_t ConcatABCDEFGHToU8(const InstData &data) {
  uint64_t imm = data.a;
  imm = (imm << 1) | data.b;
  imm = (imm << 1) | data.c;
  imm = (imm << 1) | data.d;
  imm = (imm << 1) | data.e;
  imm = (imm << 1) | data.f;
  imm = (imm << 1) | data.g;
  imm = (imm << 1) | data.h;
  return imm;
}

static uint64_t ConcatAndReplicateABCDEFGHToU64(const InstData &data) {
  auto a = Replicate(data.a, 1, 8);
  auto b = Replicate(data.b, 1, 8);
  auto c = Replicate(data.c, 1, 8);
  auto d = Replicate(data.d, 1, 8);
  auto e = Replicate(data.e, 1, 8);
  auto f = Replicate(data.f, 1, 8);
  auto g = Replicate(data.g, 1, 8);
  auto h = Replicate(data.h, 1, 8);
  uint64_t imm = a;
  imm = (imm << 8) | b;
  imm = (imm << 8) | c;
  imm = (imm << 8) | d;
  imm = (imm << 8) | e;
  imm = (imm << 8) | f;
  imm = (imm << 8) | g;
  imm = (imm << 8) | h;
  return imm;
}

// MOVI  <Vd>.2D, #<imm>
bool TryDecodeMOVI_ASIMDIMM_D2_D(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  AddRegOperand(inst, kActionWrite, kReg2D, kUseAsValue, data.Rd);
  AddImmOperand(inst, ConcatAndReplicateABCDEFGHToU64(data));
  return true;
}

// MOVI  <Vd>.<T>, #<imm8>{, LSL #0}
bool TryDecodeMOVI_ASIMDIMM_N_B(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  AddQArrangementSpecifier(data, inst, "16B", "8B");
  AddRegOperand(inst, kActionWrite, data.Q ? kReg16B : kReg8B, kUseAsValue, data.Rd);
  AddImmOperand(inst, ConcatABCDEFGHToU8(data), kUnsigned, 8);
  return true;
}

// MOVI  <Vd>.<T>, #<imm8>{, LSL #<amount>}
bool TryDecodeMOVI_ASIMDIMM_L_HL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  AddQArrangementSpecifier(data, inst, "8H", "4H");
  AddRegOperand(inst, kActionWrite, data.Q ? kReg8H : kReg4H, kUseAsValue, data.Rd);
  uint64_t shift = (data.cmode & 2) ? 8 : 0;
  AddImmOperand(inst, ConcatABCDEFGHToU8(data) << shift, kUnsigned, 16);
  return true;
}

// MOVI  <Vd>.<T>, #<imm8>{, LSL #<amount>}
bool TryDecodeMOVI_ASIMDIMM_L_SL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  AddQArrangementSpecifier(data, inst, "4S", "2S");
  AddRegOperand(inst, kActionWrite, data.Q ? kReg4S : kReg2S, kUseAsValue, data.Rd);
  uint64_t shift = 8 * ((data.cmode >> 1) & 3);
  AddImmOperand(inst, ConcatABCDEFGHToU8(data) << shift, kUnsigned, 32);
  return true;
}

// BIC  <Vd>.<T>, #<imm8>{, LSL #<amount>}
bool TryDecodeBIC_ASIMDIMM_L_HL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  AddQArrangementSpecifier(data, inst, "8H", "4H");
  AddRegOperand(inst, kActionReadWrite, data.Q ? kReg8H : kReg4H, kUseAsValue, data.Rd);
  uint64_t shift = (data.cmode & 0b10) ? 8 : 0;
  AddImmOperand(inst, ConcatABCDEFGHToU8(data) << shift, kUnsigned, 16);
  return true;
}

// BIC  <Vd>.<T>, #<imm8>{, LSL #<amount>}
bool TryDecodeBIC_ASIMDIMM_L_SL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  AddQArrangementSpecifier(data, inst, "4S", "2S");
  AddRegOperand(inst, kActionReadWrite, data.Q ? kReg4S : kReg2S, kUseAsValue, data.Rd);
  uint64_t shift = 8 * ((data.cmode >> 1) & 0b11);
  AddImmOperand(inst, ConcatABCDEFGHToU8(data) << shift, kUnsigned, 32);
  return true;
}

// MOVI  <Vd>.<T>, #<imm8>, MSL #<amount>
bool TryDecodeMOVI_ASIMDIMM_M_SM(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  AddQArrangementSpecifier(data, inst, "4S", "2S");
  AddRegOperand(inst, kActionWrite, data.Q ? kReg4S : kReg2S, kUseAsValue, data.Rd);
  uint64_t shift = (data.cmode & 1) ? 16 : 8;
  uint64_t ones = ~((~0ULL) << shift);
  uint64_t imm = (ConcatABCDEFGHToU8(data) << shift) | ones;
  AddImmOperand(inst, imm, kUnsigned, 32);
  return true;
}

// MOVI  <Dd>, #<imm>
bool TryDecodeMOVI_ASIMDIMM_D_DS(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  AddRegOperand(inst, kActionWrite, kRegD, kUseAsValue, data.Rd);
  AddImmOperand(inst, ConcatAndReplicateABCDEFGHToU64(data));
  return true;
}

// MVNI  <Vd>.<T>, #<imm8>{, LSL #<amount>}
bool TryDecodeMVNI_ASIMDIMM_L_HL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (!TryDecodeMOVI_ASIMDIMM_L_HL(data, inst)) {
    return false;
  }
  auto &imm = inst.operands[inst.operands.size() - 1].imm.val;
  imm = (~imm) & 0xFFFFULL;
  return true;
}

// MVNI  <Vd>.<T>, #<imm8>{, LSL #<amount>}
bool TryDecodeMVNI_ASIMDIMM_L_SL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (!TryDecodeMOVI_ASIMDIMM_L_SL(data, inst)) {
    return false;
  }
  auto &imm = inst.operands[inst.operands.size() - 1].imm.val;
  imm = (~imm) & 0xFFFFFFFFULL;
  return true;
}

// MVNI  <Vd>.<T>, #<imm8>, MSL #<amount>
bool TryDecodeMVNI_ASIMDIMM_M_SM(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if (!TryDecodeMOVI_ASIMDIMM_M_SM(data, inst)) {
    return false;
  }
  auto &imm = inst.operands[inst.operands.size() - 1].imm.val;
  imm = (~imm) & 0xFFFFFFFFULL;
  return true;
}

// USHR  <V><d>, <V><n>, #<shift>
bool TryDecodeUSHR_ASISDSHF_R(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  if ((data.immh.uimm & 8) == 0) {
    return false;  // if immh<3> != '1' then ReservedValue();
  }
  uint64_t shift = 128 - ((data.immh.uimm << 3) + data.immb.uimm);
  AddRegOperand(inst, kActionWrite, kReg2D, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, kReg2D, kUseAsValue, data.Rn);
  AddImmOperand(inst, shift);
  return true;
}

// USHR  <Vd>.<T>, <Vn>.<T>, #<shift>
bool TryDecodeUSHR_ASIMDSHF_R(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return false;  // TODO remove this after adding semantics for vector version
  if (((data.immh.uimm & 8) != 0) && !data.Q) {
    return false;  // `if immh<3>:Q == '10' then ReservedValue();`
  }
  uint64_t esize = 0;
  MostSignificantSetBit(data.immh.uimm, &esize);
  esize = 8 << esize;

  const uint64_t datasize = data.Q ? 128 : 64;
  AddArrangementSpecifier(inst, datasize, esize);

  // AddArrangementSpecifier(inst, 128, 8UL << data.size);

  uint64_t shift = (esize * 2) - ((data.immh.uimm << 3) + data.immb.uimm);
  AddRegOperand(inst, kActionWrite, kReg2D, kUseAsValue, data.Rd);  // (FIXME) not used now
  AddRegOperand(inst, kActionRead, kReg2D, kUseAsValue, data.Rn);  // (FIXME) not used now
  AddImmOperand(inst, shift);
  return true;
}

// USHLL{2}  <Vd>.<Ta>, <Vn>.<Tb>, #<shift>
bool TryDecodeUSHLL_ASIMDSHF_L(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  uint64_t d_total_size, s_total_size, d_elem_size, s_elem_size, shift_val;
  d_total_size = 128;
  s_total_size = data.Q ? 128 : 64;
  if (data.immh.uimm & 0b0001) {
    s_elem_size = 8;
    shift_val = (data.immh.uimm << 3 | data.immb.uimm) - 0b1000;
  } else if (data.immh.uimm & 0b0010) {
    s_elem_size = 16;
    shift_val = (data.immh.uimm << 3 | data.immb.uimm) - 0b1'0000;
  } else if (data.immh.uimm & 0b0100) {
    s_elem_size = 32;
    shift_val = (data.immh.uimm << 3 | data.immb.uimm) - 0b10'0000;
  } else {
    LOG(FATAL) << "data.immh is invalid at USHLL instruction at 0x" << std::hex << inst.pc;
  }
  d_elem_size = s_elem_size << 1;
  AddArrangementSpecifierUSHLL(inst, d_total_size, d_elem_size, s_total_size, s_elem_size);
  auto d_rclass = ArrangementRegClass(d_total_size, d_elem_size);
  auto s_rclass = ArrangementRegClass(s_total_size, s_elem_size);
  AddRegOperand(inst, kActionWrite, d_rclass, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, s_rclass, kUseAsValue, data.Rn);
  AddImmOperand(inst, shift_val);
  return true;
}

// CAS  <Ws>, <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeCAS_C32_LDSTEXCL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionReadWrite, kRegW, kUseAsValue, data.Rs);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 8U << data.size, data.Rn, 0);
  return true;
}

// CAS  <Xs>, <Xt>, [<Xn|SP>{,#0}]
bool TryDecodeCAS_C64_LDSTEXCL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionReadWrite, kRegX, kUseAsValue, data.Rs);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 8U << data.size, data.Rn, 0);
  return true;
}

// CASA  <Ws>, <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeCASA_C32_LDSTEXCL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionReadWrite, kRegW, kUseAsValue, data.Rs);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 8U << data.size, data.Rn, 0);
  return true;
}

// CASA  <Xs>, <Xt>, [<Xn|SP>{,#0}]
bool TryDecodeCASA_C64_LDSTEXCL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionReadWrite, kRegX, kUseAsValue, data.Rs);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 8U << data.size, data.Rn, 0);
  return true;
}

// CASAL  <Ws>, <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeCASAL_C32_LDSTEXCL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionReadWrite, kRegW, kUseAsValue, data.Rs);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 8U << data.size, data.Rn, 0);
  return true;
}

// CASAL  <Xs>, <Xt>, [<Xn|SP>{,#0}]
bool TryDecodeCASAL_C64_LDSTEXCL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionReadWrite, kRegX, kUseAsValue, data.Rs);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 8U << data.size, data.Rn, 0);
  return true;
}

// CASL  <Ws>, <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeCASL_C32_LDSTEXCL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionReadWrite, kRegW, kUseAsValue, data.Rs);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 8U << data.size, data.Rn, 0);
  return true;
}

// CASL  <Xs>, <Xt>, [<Xn|SP>{,#0}]
bool TryDecodeCASL_C64_LDSTEXCL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  AddRegOperand(inst, kActionReadWrite, kRegX, kUseAsValue, data.Rs);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 8U << data.size, data.Rn, 0);
  return true;
}

// STXR  <Ws>, <Wt>, [<Xn|SP>{,#0}]
bool TryDecodeSTXR_SR32_LDSTEXCL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  inst.is_atomic_read_modify_write = true;
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rs);
  AddRegOperand(inst, kActionRead, kRegW, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 32, data.Rn, 0);
  AddMonitorOperand(inst, kActionReadWrite);
  return true;
}

// STXR  <Ws>, <Xt>, [<Xn|SP>{,#0}]
bool TryDecodeSTXR_SR64_LDSTEXCL(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Runtime;
  inst.is_atomic_read_modify_write = true;
  AddRegOperand(inst, kActionWrite, kRegW, kUseAsValue, data.Rs);
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rt);
  AddBasePlusOffsetMemOp(inst, 64, data.Rn, 0);
  AddMonitorOperand(inst, kActionReadWrite);
  return true;
}

// CNT  <Vd>.<T>, <Vn>.<T>
bool TryDecodeCNT_ASIMDMISC_R(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  AddArrangementSpecifier(inst, data.Q ? 128 : 64, 8);
  auto rclass = data.Q ? kReg16B : kReg8B;
  AddRegOperand(inst, kActionWrite, rclass, kUseAsValue, data.Rd);
  AddRegOperand(inst, kActionRead, rclass, kUseAsValue, data.Rn);
  return true;
}

// DC  <dc_op>, <Xt> /* FIXME */
bool TryDecodeDC_SYS_CR_SYSTEM(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::StateRuntime;
  AddRegOperand(inst, kActionRead, kRegX, kUseAsValue, data.Rt);
  return true;
}

// PRFM  (<prfop>|#<imm5>), [<Xn|SP>{, #<pimm>}] /* FIXME?? */
bool TryDecodePRFM_P_LDST_POS(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return true;
}

// CNTB <Xd>{, <pattern>{, MUL #<imm>}}
bool TryDecodeCNTB_X64_BITCOUNT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return true;
}

// CNTD <Xd>{, <pattern>{, MUL #<imm>}}
bool TryDecodeCNTD_X64_BITCOUNT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return true;
}

// CNTH <Xd>{, <pattern>{, MUL #<imm>}}
bool TryDecodeCNTH_X64_BITCOUNT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return true;
}

// CNTW <Xd>{, <pattern>{, MUL #<imm>}}
bool TryDecodeCNTW_X64_BITCOUNT(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return true;
}

// WHILELO <Pd>.<T>, <R><n>, <R><m>
bool TryDecodeWHILELO_PREDICATE(const InstData &data, Instruction &inst) {
  inst.sema_func_arg_type = SemaFuncArgType::Nothing;
  return true;
}

}  // namespace aarch64

auto Arch::GetAArch64(llvm::LLVMContext *context_, OSName os_name_, ArchName arch_name_)
    -> ArchPtr {
  return std::make_unique<AArch64Arch>(context_, os_name_, arch_name_);
}

}  // namespace remill
