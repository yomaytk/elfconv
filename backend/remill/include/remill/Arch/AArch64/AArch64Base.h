
#pragma once
#include <remill/Arch/Arch.h>
#include <remill/Arch/ArchBase.h>

// clang-format off
#define ADDRESS_SIZE 64
#include <remill/Arch/AArch64/Runtime/State.h>
// clang-format on

#include <charconv>
#include <glog/logging.h>
#include <string>

namespace remill {

enum RegAction { kActionRead, kActionWrite, kActionReadWrite };

class RegExp {
  enum class RegType;

 public:
  RegExp(RegType __ecv_r_type, uint32_t __reg_num)
      : _ecv_r_type(__ecv_r_type),
        reg_num(__reg_num) {}

  static RegExp str2RegExp(std::string_view reg_name) {
    RegType __ecv_r_type;
    uint32_t __reg_num;

    switch (reg_name[0]) {
      case 'X': __ecv_r_type = RegType::X; break;
      case 'W': __ecv_r_type = RegType::W; break;
      case 'B': __ecv_r_type = RegType::B; break;
      case 'H': __ecv_r_type = RegType::H; break;
      case 'S': __ecv_r_type = RegType::S; break;
      case 'D': __ecv_r_type = RegType::D; break;
      case 'Q': __ecv_r_type = RegType::Q; break;
      case 'V': __ecv_r_type = RegType::V; break;
      default: LOG(FATAL) << "Unexpected RegType at str2RegExp."; break;
    }
    auto conv_res =
        std::from_chars(reg_name.data() + 1, reg_name.data() + reg_name.size(), __reg_num);
    if (std::errc::invalid_argument == conv_res.ec) {
      LOG(FATAL) << "Cannot convert to reg_num at str2RegExp.";
    }
    return RegExp(__ecv_r_type, __reg_num);
  }

  enum class RegType { X, W, B, H, S, D, Q, V } _ecv_r_type;
  uint32_t reg_num;
};

class AArch64ArchBase : public virtual ArchBase {
 public:
  AArch64ArchBase(llvm::LLVMContext *context_, OSName os_name_, ArchName arch_name_)
      : ArchBase(context_, os_name_, arch_name_) {}

  virtual std::string_view StackPointerRegisterName(void) const override;

  std::string_view ProgramCounterRegisterName(void) const override;


  llvm::CallingConv::ID DefaultCallingConv(void) const override;

  llvm::DataLayout DataLayout(void) const override;

  llvm::Triple Triple(void) const override;


  // Align/Minimum/Maximum number of bytes in an instruction.
  uint64_t MinInstructionAlign(const DecodingContext &) const override;
  uint64_t MinInstructionSize(const DecodingContext &) const override;
  uint64_t MaxInstructionSize(const DecodingContext &, bool permit_fuse_idioms) const override;


  void PopulateRegisterTable(void) const override;
  // Populate a just-initialized lifted function function with architecture-
  // specific variables.
  void FinishLiftedFunctionInitialization(llvm::Module *module,
                                          llvm::Function *bb_func) const override;
  virtual ~AArch64ArchBase(void) = default;
};
}  // namespace remill