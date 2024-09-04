#include <glog/logging.h>
#include <remill/Arch/AArch64/AArch64Base.h>
#include <remill/Arch/Name.h>
#include <remill/BC/ABI.h>
#include <remill/BC/Util.h>

namespace remill {
// Returns the name of the stack pointer register.
std::string_view AArch64ArchBase::StackPointerRegisterName(void) const {
  return "SP";
}

// Returns the name of the program counter register.
std::string_view AArch64ArchBase::ProgramCounterRegisterName(void) const {
  return "PC";
}

uint64_t AArch64ArchBase::MinInstructionAlign(const DecodingContext &) const {
  return 4;
}

uint64_t AArch64ArchBase::MinInstructionSize(const DecodingContext &) const {
  return 4;
}

// Maximum number of bytes in an instruction for this particular architecture.
uint64_t AArch64ArchBase::MaxInstructionSize(const DecodingContext &, bool) const {
  return 4;
}


// Populate a just-initialized lifted function function with architecture-
// specific variables.
void AArch64ArchBase::FinishLiftedFunctionInitialization(llvm::Module *module,
                                                         llvm::Function *bb_func) const {

  auto &context = module->getContext();
  auto u64 = llvm::Type::getInt64Ty(context);

  const auto entry_block = &bb_func->getEntryBlock();
  llvm::IRBuilder<> ir(entry_block);

  const auto state_ptr_arg = NthArgument(bb_func, kStatePointerArgNum);

  ir.CreateAlloca(u64, nullptr, "SUPPRESS_WRITEBACK");

  (void) this->RegisterByName(kPCVariableName)->AddressOf(state_ptr_arg, ir);
}

llvm::Triple AArch64ArchBase::Triple(void) const {
  auto triple = BasicTriple();
  switch (arch_name) {
    case kArchAArch64LittleEndian_SLEIGH:
    case kArchAArch64LittleEndian: triple.setArch(llvm::Triple::aarch64); break;

    default:
      LOG(FATAL) << "Cannot get triple for non-AArch64 architecture " << GetArchName(arch_name);
      break;
  }
  return triple;
}

llvm::DataLayout AArch64ArchBase::DataLayout(void) const {
  std::string dl;
  switch (arch_name) {
    case kArchAArch64LittleEndian:
    case kArchAArch64LittleEndian_SLEIGH:
      dl = "e-m:e-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128";
      break;

    default:
      LOG(FATAL) << "Cannot get data layout for non-AArch64 architecture "
                 << GetArchName(arch_name);
      break;
  }
  return llvm::DataLayout(dl);
}

// Default calling convention for this architecture.
llvm::CallingConv::ID AArch64ArchBase::DefaultCallingConv(void) const {
  return llvm::CallingConv::C;
}

// Populate the table of register information.
void AArch64ArchBase::PopulateRegisterTable(void) const {

  reg_by_offset.resize(sizeof(AArch64State));

#define OFFSET_OF(type, access) \
  (reinterpret_cast<uintptr_t>( \
      &reinterpret_cast<const volatile char &>(static_cast<type *>(nullptr)->access)))

#define REG(name, access, type) AddRegister(#name, type, OFFSET_OF(AArch64State, access), nullptr)

#define SUB_REG(name, access, type, parent_reg_name) \
  AddRegister(#name, type, OFFSET_OF(AArch64State, access), #parent_reg_name)

  auto u8 = llvm::Type::getInt8Ty(*context);
  auto u16 = llvm::Type::getInt16Ty(*context);
  auto u32 = llvm::Type::getInt32Ty(*context);
  auto u64 = llvm::Type::getInt64Ty(*context);
  auto u128 = llvm::Type::getInt128Ty(*context);

  auto f32 = llvm::Type::getFloatTy(*context);
  auto f64 = llvm::Type::getDoubleTy(*context);

  auto u8v8 = llvm::VectorType::get(u8, 8, false);
  auto u8v16 = llvm::VectorType::get(u8, 16, false);
  auto u16v4 = llvm::VectorType::get(u16, 4, false);
  auto u16v8 = llvm::VectorType::get(u16, 8, false);
  auto u32v2 = llvm::VectorType::get(u32, 2, false);
  auto u32v4 = llvm::VectorType::get(u32, 4, false);
  auto u64v1 = llvm::VectorType::get(u64, 1, false);
  auto u64v2 = llvm::VectorType::get(u64, 2, false);
  auto f32v2 = llvm::VectorType::get(f32, 2, false);
  auto f32v4 = llvm::VectorType::get(f32, 4, false);
  auto f64v1 = llvm::VectorType::get(f64, 1, false);
  auto f64v2 = llvm::VectorType::get(f64, 2, false);
  auto u128v1 = llvm::VectorType::get(u128, 1, false);

  REG(X0, gpr.x0.qword, u64);
  REG(X1, gpr.x1.qword, u64);
  REG(X2, gpr.x2.qword, u64);
  REG(X3, gpr.x3.qword, u64);
  REG(X4, gpr.x4.qword, u64);
  REG(X5, gpr.x5.qword, u64);
  REG(X6, gpr.x6.qword, u64);
  REG(X7, gpr.x7.qword, u64);
  REG(X8, gpr.x8.qword, u64);
  REG(X9, gpr.x9.qword, u64);
  REG(X10, gpr.x10.qword, u64);
  REG(X11, gpr.x11.qword, u64);
  REG(X12, gpr.x12.qword, u64);
  REG(X13, gpr.x13.qword, u64);
  REG(X14, gpr.x14.qword, u64);
  REG(X15, gpr.x15.qword, u64);
  REG(X16, gpr.x16.qword, u64);
  REG(X17, gpr.x17.qword, u64);
  REG(X18, gpr.x18.qword, u64);
  REG(X19, gpr.x19.qword, u64);
  REG(X20, gpr.x20.qword, u64);
  REG(X21, gpr.x21.qword, u64);
  REG(X22, gpr.x22.qword, u64);
  REG(X23, gpr.x23.qword, u64);
  REG(X24, gpr.x24.qword, u64);
  REG(X25, gpr.x25.qword, u64);
  REG(X26, gpr.x26.qword, u64);
  REG(X27, gpr.x27.qword, u64);
  REG(X28, gpr.x28.qword, u64);
  REG(X29, gpr.x29.qword, u64);
  REG(X30, gpr.x30.qword, u64);

  SUB_REG(W0, gpr.x0.dword, u32, X0);
  SUB_REG(W1, gpr.x1.dword, u32, X1);
  SUB_REG(W2, gpr.x2.dword, u32, X2);
  SUB_REG(W3, gpr.x3.dword, u32, X3);
  SUB_REG(W4, gpr.x4.dword, u32, X4);
  SUB_REG(W5, gpr.x5.dword, u32, X5);
  SUB_REG(W6, gpr.x6.dword, u32, X6);
  SUB_REG(W7, gpr.x7.dword, u32, X7);
  SUB_REG(W8, gpr.x8.dword, u32, X8);
  SUB_REG(W9, gpr.x9.dword, u32, X9);
  SUB_REG(W10, gpr.x10.dword, u32, X10);
  SUB_REG(W11, gpr.x11.dword, u32, X11);
  SUB_REG(W12, gpr.x12.dword, u32, X12);
  SUB_REG(W13, gpr.x13.dword, u32, X13);
  SUB_REG(W14, gpr.x14.dword, u32, X14);
  SUB_REG(W15, gpr.x15.dword, u32, X15);
  SUB_REG(W16, gpr.x16.dword, u32, X16);
  SUB_REG(W17, gpr.x17.dword, u32, X17);
  SUB_REG(W18, gpr.x18.dword, u32, X18);
  SUB_REG(W19, gpr.x19.dword, u32, X19);
  SUB_REG(W20, gpr.x20.dword, u32, X20);
  SUB_REG(W21, gpr.x21.dword, u32, X21);
  SUB_REG(W22, gpr.x22.dword, u32, X22);
  SUB_REG(W23, gpr.x23.dword, u32, X23);
  SUB_REG(W24, gpr.x24.dword, u32, X24);
  SUB_REG(W25, gpr.x25.dword, u32, X25);
  SUB_REG(W26, gpr.x26.dword, u32, X26);
  SUB_REG(W27, gpr.x27.dword, u32, X27);
  SUB_REG(W28, gpr.x28.dword, u32, X28);
  SUB_REG(W29, gpr.x29.dword, u32, X29);
  SUB_REG(W30, gpr.x30.dword, u32, X30);

  REG(PC, gpr.pc.qword, u64);
  SUB_REG(WPC, gpr.pc.dword, u32, PC);

  REG(SP, gpr.sp.qword, u64);
  SUB_REG(WSP, gpr.sp.dword, u32, SP);

  SUB_REG(LP, gpr.x30.qword, u64, X30);
  SUB_REG(WLP, gpr.x30.dword, u32, LP);

  REG(V0, simd.v[0], u128v1);
  REG(V1, simd.v[1], u128v1);
  REG(V2, simd.v[2], u128v1);
  REG(V3, simd.v[3], u128v1);
  REG(V4, simd.v[4], u128v1);
  REG(V5, simd.v[5], u128v1);
  REG(V6, simd.v[6], u128v1);
  REG(V7, simd.v[7], u128v1);
  REG(V8, simd.v[8], u128v1);
  REG(V9, simd.v[9], u128v1);
  REG(V10, simd.v[10], u128v1);
  REG(V11, simd.v[11], u128v1);
  REG(V12, simd.v[12], u128v1);
  REG(V13, simd.v[13], u128v1);
  REG(V14, simd.v[14], u128v1);
  REG(V15, simd.v[15], u128v1);
  REG(V16, simd.v[16], u128v1);
  REG(V17, simd.v[17], u128v1);
  REG(V18, simd.v[18], u128v1);
  REG(V19, simd.v[19], u128v1);
  REG(V20, simd.v[20], u128v1);
  REG(V21, simd.v[21], u128v1);
  REG(V22, simd.v[22], u128v1);
  REG(V23, simd.v[23], u128v1);
  REG(V24, simd.v[24], u128v1);
  REG(V25, simd.v[25], u128v1);
  REG(V26, simd.v[26], u128v1);
  REG(V27, simd.v[27], u128v1);
  REG(V28, simd.v[28], u128v1);
  REG(V29, simd.v[29], u128v1);
  REG(V30, simd.v[30], u128v1);
  REG(V31, simd.v[31], u128v1);

  SUB_REG(B0, simd.v[0], u8, V0);
  SUB_REG(B1, simd.v[1], u8, V1);
  SUB_REG(B2, simd.v[2], u8, V2);
  SUB_REG(B3, simd.v[3], u8, V3);
  SUB_REG(B4, simd.v[4], u8, V4);
  SUB_REG(B5, simd.v[5], u8, V5);
  SUB_REG(B6, simd.v[6], u8, V6);
  SUB_REG(B7, simd.v[7], u8, V7);
  SUB_REG(B8, simd.v[8], u8, V8);
  SUB_REG(B9, simd.v[9], u8, V9);
  SUB_REG(B10, simd.v[10], u8, V10);
  SUB_REG(B11, simd.v[11], u8, V11);
  SUB_REG(B12, simd.v[12], u8, V12);
  SUB_REG(B13, simd.v[13], u8, V13);
  SUB_REG(B14, simd.v[14], u8, V14);
  SUB_REG(B15, simd.v[15], u8, V15);
  SUB_REG(B16, simd.v[16], u8, V16);
  SUB_REG(B17, simd.v[17], u8, V17);
  SUB_REG(B18, simd.v[18], u8, V18);
  SUB_REG(B19, simd.v[19], u8, V19);
  SUB_REG(B20, simd.v[20], u8, V20);
  SUB_REG(B21, simd.v[21], u8, V21);
  SUB_REG(B22, simd.v[22], u8, V22);
  SUB_REG(B23, simd.v[23], u8, V23);
  SUB_REG(B24, simd.v[24], u8, V24);
  SUB_REG(B25, simd.v[25], u8, V25);
  SUB_REG(B26, simd.v[26], u8, V26);
  SUB_REG(B27, simd.v[27], u8, V27);
  SUB_REG(B28, simd.v[28], u8, V28);
  SUB_REG(B29, simd.v[29], u8, V29);
  SUB_REG(B30, simd.v[30], u8, V30);
  SUB_REG(B31, simd.v[31], u8, V31);

  SUB_REG(H0, simd.v[0], u16, V0);
  SUB_REG(H1, simd.v[1], u16, V1);
  SUB_REG(H2, simd.v[2], u16, V2);
  SUB_REG(H3, simd.v[3], u16, V3);
  SUB_REG(H4, simd.v[4], u16, V4);
  SUB_REG(H5, simd.v[5], u16, V5);
  SUB_REG(H6, simd.v[6], u16, V6);
  SUB_REG(H7, simd.v[7], u16, V7);
  SUB_REG(H8, simd.v[8], u16, V8);
  SUB_REG(H9, simd.v[9], u16, V9);
  SUB_REG(H10, simd.v[10], u16, V10);
  SUB_REG(H11, simd.v[11], u16, V11);
  SUB_REG(H12, simd.v[12], u16, V12);
  SUB_REG(H13, simd.v[13], u16, V13);
  SUB_REG(H14, simd.v[14], u16, V14);
  SUB_REG(H15, simd.v[15], u16, V15);
  SUB_REG(H16, simd.v[16], u16, V16);
  SUB_REG(H17, simd.v[17], u16, V17);
  SUB_REG(H18, simd.v[18], u16, V18);
  SUB_REG(H19, simd.v[19], u16, V19);
  SUB_REG(H20, simd.v[20], u16, V20);
  SUB_REG(H21, simd.v[21], u16, V21);
  SUB_REG(H22, simd.v[22], u16, V22);
  SUB_REG(H23, simd.v[23], u16, V23);
  SUB_REG(H24, simd.v[24], u16, V24);
  SUB_REG(H25, simd.v[25], u16, V25);
  SUB_REG(H26, simd.v[26], u16, V26);
  SUB_REG(H27, simd.v[27], u16, V27);
  SUB_REG(H28, simd.v[28], u16, V28);
  SUB_REG(H29, simd.v[29], u16, V29);
  SUB_REG(H30, simd.v[30], u16, V30);
  SUB_REG(H31, simd.v[31], u16, V31);

  SUB_REG(S0, simd.v[0], f32, V0);
  SUB_REG(S1, simd.v[1], f32, V1);
  SUB_REG(S2, simd.v[2], f32, V2);
  SUB_REG(S3, simd.v[3], f32, V3);
  SUB_REG(S4, simd.v[4], f32, V4);
  SUB_REG(S5, simd.v[5], f32, V5);
  SUB_REG(S6, simd.v[6], f32, V6);
  SUB_REG(S7, simd.v[7], f32, V7);
  SUB_REG(S8, simd.v[8], f32, V8);
  SUB_REG(S9, simd.v[9], f32, V9);
  SUB_REG(S10, simd.v[10], f32, V10);
  SUB_REG(S11, simd.v[11], f32, V11);
  SUB_REG(S12, simd.v[12], f32, V12);
  SUB_REG(S13, simd.v[13], f32, V13);
  SUB_REG(S14, simd.v[14], f32, V14);
  SUB_REG(S15, simd.v[15], f32, V15);
  SUB_REG(S16, simd.v[16], f32, V16);
  SUB_REG(S17, simd.v[17], f32, V17);
  SUB_REG(S18, simd.v[18], f32, V18);
  SUB_REG(S19, simd.v[19], f32, V19);
  SUB_REG(S20, simd.v[20], f32, V20);
  SUB_REG(S21, simd.v[21], f32, V21);
  SUB_REG(S22, simd.v[22], f32, V22);
  SUB_REG(S23, simd.v[23], f32, V23);
  SUB_REG(S24, simd.v[24], f32, V24);
  SUB_REG(S25, simd.v[25], f32, V25);
  SUB_REG(S26, simd.v[26], f32, V26);
  SUB_REG(S27, simd.v[27], f32, V27);
  SUB_REG(S28, simd.v[28], f32, V28);
  SUB_REG(S29, simd.v[29], f32, V29);
  SUB_REG(S30, simd.v[30], f32, V30);
  SUB_REG(S31, simd.v[31], f32, V31);

  SUB_REG(D0, simd.v[0], f64, V0);
  SUB_REG(D1, simd.v[1], f64, V1);
  SUB_REG(D2, simd.v[2], f64, V2);
  SUB_REG(D3, simd.v[3], f64, V3);
  SUB_REG(D4, simd.v[4], f64, V4);
  SUB_REG(D5, simd.v[5], f64, V5);
  SUB_REG(D6, simd.v[6], f64, V6);
  SUB_REG(D7, simd.v[7], f64, V7);
  SUB_REG(D8, simd.v[8], f64, V8);
  SUB_REG(D9, simd.v[9], f64, V9);
  SUB_REG(D10, simd.v[10], f64, V10);
  SUB_REG(D11, simd.v[11], f64, V11);
  SUB_REG(D12, simd.v[12], f64, V12);
  SUB_REG(D13, simd.v[13], f64, V13);
  SUB_REG(D14, simd.v[14], f64, V14);
  SUB_REG(D15, simd.v[15], f64, V15);
  SUB_REG(D16, simd.v[16], f64, V16);
  SUB_REG(D17, simd.v[17], f64, V17);
  SUB_REG(D18, simd.v[18], f64, V18);
  SUB_REG(D19, simd.v[19], f64, V19);
  SUB_REG(D20, simd.v[20], f64, V20);
  SUB_REG(D21, simd.v[21], f64, V21);
  SUB_REG(D22, simd.v[22], f64, V22);
  SUB_REG(D23, simd.v[23], f64, V23);
  SUB_REG(D24, simd.v[24], f64, V24);
  SUB_REG(D25, simd.v[25], f64, V25);
  SUB_REG(D26, simd.v[26], f64, V26);
  SUB_REG(D27, simd.v[27], f64, V27);
  SUB_REG(D28, simd.v[28], f64, V28);
  SUB_REG(D29, simd.v[29], f64, V29);
  SUB_REG(D30, simd.v[30], f64, V30);
  SUB_REG(D31, simd.v[31], f64, V31);

  SUB_REG(Q0, simd.v[0], u128, V0);
  SUB_REG(Q1, simd.v[1], u128, V1);
  SUB_REG(Q2, simd.v[2], u128, V2);
  SUB_REG(Q3, simd.v[3], u128, V3);
  SUB_REG(Q4, simd.v[4], u128, V4);
  SUB_REG(Q5, simd.v[5], u128, V5);
  SUB_REG(Q6, simd.v[6], u128, V6);
  SUB_REG(Q7, simd.v[7], u128, V7);
  SUB_REG(Q8, simd.v[8], u128, V8);
  SUB_REG(Q9, simd.v[9], u128, V9);
  SUB_REG(Q10, simd.v[10], u128, V10);
  SUB_REG(Q11, simd.v[11], u128, V11);
  SUB_REG(Q12, simd.v[12], u128, V12);
  SUB_REG(Q13, simd.v[13], u128, V13);
  SUB_REG(Q14, simd.v[14], u128, V14);
  SUB_REG(Q15, simd.v[15], u128, V15);
  SUB_REG(Q16, simd.v[16], u128, V16);
  SUB_REG(Q17, simd.v[17], u128, V17);
  SUB_REG(Q18, simd.v[18], u128, V18);
  SUB_REG(Q19, simd.v[19], u128, V19);
  SUB_REG(Q20, simd.v[20], u128, V20);
  SUB_REG(Q21, simd.v[21], u128, V21);
  SUB_REG(Q22, simd.v[22], u128, V22);
  SUB_REG(Q23, simd.v[23], u128, V23);
  SUB_REG(Q24, simd.v[24], u128, V24);
  SUB_REG(Q25, simd.v[25], u128, V25);
  SUB_REG(Q26, simd.v[26], u128, V26);
  SUB_REG(Q27, simd.v[27], u128, V27);
  SUB_REG(Q28, simd.v[28], u128, V28);
  SUB_REG(Q29, simd.v[29], u128, V29);
  SUB_REG(Q30, simd.v[30], u128, V30);
  SUB_REG(Q31, simd.v[31], u128, V31);

  SUB_REG(8B0, simd.v[0], u8v8, V0);
  SUB_REG(8B1, simd.v[1], u8v8, V1);
  SUB_REG(8B2, simd.v[2], u8v8, V2);
  SUB_REG(8B3, simd.v[3], u8v8, V3);
  SUB_REG(8B4, simd.v[4], u8v8, V4);
  SUB_REG(8B5, simd.v[5], u8v8, V5);
  SUB_REG(8B6, simd.v[6], u8v8, V6);
  SUB_REG(8B7, simd.v[7], u8v8, V7);
  SUB_REG(8B8, simd.v[8], u8v8, V8);
  SUB_REG(8B9, simd.v[9], u8v8, V9);
  SUB_REG(8B10, simd.v[10], u8v8, V10);
  SUB_REG(8B11, simd.v[11], u8v8, V11);
  SUB_REG(8B12, simd.v[12], u8v8, V12);
  SUB_REG(8B13, simd.v[13], u8v8, V13);
  SUB_REG(8B14, simd.v[14], u8v8, V14);
  SUB_REG(8B15, simd.v[15], u8v8, V15);
  SUB_REG(8B16, simd.v[16], u8v8, V16);
  SUB_REG(8B17, simd.v[17], u8v8, V17);
  SUB_REG(8B18, simd.v[18], u8v8, V18);
  SUB_REG(8B19, simd.v[19], u8v8, V19);
  SUB_REG(8B20, simd.v[20], u8v8, V20);
  SUB_REG(8B21, simd.v[21], u8v8, V21);
  SUB_REG(8B22, simd.v[22], u8v8, V22);
  SUB_REG(8B23, simd.v[23], u8v8, V23);
  SUB_REG(8B24, simd.v[24], u8v8, V24);
  SUB_REG(8B25, simd.v[25], u8v8, V25);
  SUB_REG(8B26, simd.v[26], u8v8, V26);
  SUB_REG(8B27, simd.v[27], u8v8, V27);
  SUB_REG(8B28, simd.v[28], u8v8, V28);
  SUB_REG(8B29, simd.v[29], u8v8, V29);
  SUB_REG(8B30, simd.v[30], u8v8, V30);
  SUB_REG(8B31, simd.v[31], u8v8, V31);

  SUB_REG(8B0, simd.v[0], u8v8, V0);
  SUB_REG(8B1, simd.v[1], u8v8, V1);
  SUB_REG(8B2, simd.v[2], u8v8, V2);
  SUB_REG(8B3, simd.v[3], u8v8, V3);
  SUB_REG(8B4, simd.v[4], u8v8, V4);
  SUB_REG(8B5, simd.v[5], u8v8, V5);
  SUB_REG(8B6, simd.v[6], u8v8, V6);
  SUB_REG(8B7, simd.v[7], u8v8, V7);
  SUB_REG(8B8, simd.v[8], u8v8, V8);
  SUB_REG(8B9, simd.v[9], u8v8, V9);
  SUB_REG(8B10, simd.v[10], u8v8, V10);
  SUB_REG(8B11, simd.v[11], u8v8, V11);
  SUB_REG(8B12, simd.v[12], u8v8, V12);
  SUB_REG(8B13, simd.v[13], u8v8, V13);
  SUB_REG(8B14, simd.v[14], u8v8, V14);
  SUB_REG(8B15, simd.v[15], u8v8, V15);
  SUB_REG(8B16, simd.v[16], u8v8, V16);
  SUB_REG(8B17, simd.v[17], u8v8, V17);
  SUB_REG(8B18, simd.v[18], u8v8, V18);
  SUB_REG(8B19, simd.v[19], u8v8, V19);
  SUB_REG(8B20, simd.v[20], u8v8, V20);
  SUB_REG(8B21, simd.v[21], u8v8, V21);
  SUB_REG(8B22, simd.v[22], u8v8, V22);
  SUB_REG(8B23, simd.v[23], u8v8, V23);
  SUB_REG(8B24, simd.v[24], u8v8, V24);
  SUB_REG(8B25, simd.v[25], u8v8, V25);
  SUB_REG(8B26, simd.v[26], u8v8, V26);
  SUB_REG(8B27, simd.v[27], u8v8, V27);
  SUB_REG(8B28, simd.v[28], u8v8, V28);
  SUB_REG(8B29, simd.v[29], u8v8, V29);
  SUB_REG(8B30, simd.v[30], u8v8, V30);
  SUB_REG(8B31, simd.v[31], u8v8, V31);

  SUB_REG(16B0, simd.v[0], u8v16, V0);
  SUB_REG(16B1, simd.v[1], u8v16, V1);
  SUB_REG(16B2, simd.v[2], u8v16, V2);
  SUB_REG(16B3, simd.v[3], u8v16, V3);
  SUB_REG(16B4, simd.v[4], u8v16, V4);
  SUB_REG(16B5, simd.v[5], u8v16, V5);
  SUB_REG(16B6, simd.v[6], u8v16, V6);
  SUB_REG(16B7, simd.v[7], u8v16, V7);
  SUB_REG(16B8, simd.v[8], u8v16, V8);
  SUB_REG(16B9, simd.v[9], u8v16, V9);
  SUB_REG(16B10, simd.v[10], u8v16, V10);
  SUB_REG(16B11, simd.v[11], u8v16, V11);
  SUB_REG(16B12, simd.v[12], u8v16, V12);
  SUB_REG(16B13, simd.v[13], u8v16, V13);
  SUB_REG(16B14, simd.v[14], u8v16, V14);
  SUB_REG(16B15, simd.v[15], u8v16, V15);
  SUB_REG(16B16, simd.v[16], u8v16, V16);
  SUB_REG(16B17, simd.v[17], u8v16, V17);
  SUB_REG(16B18, simd.v[18], u8v16, V18);
  SUB_REG(16B19, simd.v[19], u8v16, V19);
  SUB_REG(16B20, simd.v[20], u8v16, V20);
  SUB_REG(16B21, simd.v[21], u8v16, V21);
  SUB_REG(16B22, simd.v[22], u8v16, V22);
  SUB_REG(16B23, simd.v[23], u8v16, V23);
  SUB_REG(16B24, simd.v[24], u8v16, V24);
  SUB_REG(16B25, simd.v[25], u8v16, V25);
  SUB_REG(16B26, simd.v[26], u8v16, V26);
  SUB_REG(16B27, simd.v[27], u8v16, V27);
  SUB_REG(16B28, simd.v[28], u8v16, V28);
  SUB_REG(16B29, simd.v[29], u8v16, V29);
  SUB_REG(16B30, simd.v[30], u8v16, V30);
  SUB_REG(16B31, simd.v[31], u8v16, V31);

  SUB_REG(4H0, simd.v[0], u16v4, V0);
  SUB_REG(4H1, simd.v[1], u16v4, V1);
  SUB_REG(4H2, simd.v[2], u16v4, V2);
  SUB_REG(4H3, simd.v[3], u16v4, V3);
  SUB_REG(4H4, simd.v[4], u16v4, V4);
  SUB_REG(4H5, simd.v[5], u16v4, V5);
  SUB_REG(4H6, simd.v[6], u16v4, V6);
  SUB_REG(4H7, simd.v[7], u16v4, V7);
  SUB_REG(4H8, simd.v[8], u16v4, V8);
  SUB_REG(4H9, simd.v[9], u16v4, V9);
  SUB_REG(4H10, simd.v[10], u16v4, V10);
  SUB_REG(4H11, simd.v[11], u16v4, V11);
  SUB_REG(4H12, simd.v[12], u16v4, V12);
  SUB_REG(4H13, simd.v[13], u16v4, V13);
  SUB_REG(4H14, simd.v[14], u16v4, V14);
  SUB_REG(4H15, simd.v[15], u16v4, V15);
  SUB_REG(4H16, simd.v[16], u16v4, V16);
  SUB_REG(4H17, simd.v[17], u16v4, V17);
  SUB_REG(4H18, simd.v[18], u16v4, V18);
  SUB_REG(4H19, simd.v[19], u16v4, V19);
  SUB_REG(4H20, simd.v[20], u16v4, V20);
  SUB_REG(4H21, simd.v[21], u16v4, V21);
  SUB_REG(4H22, simd.v[22], u16v4, V22);
  SUB_REG(4H23, simd.v[23], u16v4, V23);
  SUB_REG(4H24, simd.v[24], u16v4, V24);
  SUB_REG(4H25, simd.v[25], u16v4, V25);
  SUB_REG(4H26, simd.v[26], u16v4, V26);
  SUB_REG(4H27, simd.v[27], u16v4, V27);
  SUB_REG(4H28, simd.v[28], u16v4, V28);
  SUB_REG(4H29, simd.v[29], u16v4, V29);
  SUB_REG(4H30, simd.v[30], u16v4, V30);
  SUB_REG(4H31, simd.v[31], u16v4, V31);

  SUB_REG(8H0, simd.v[0], u16v8, V0);
  SUB_REG(8H1, simd.v[1], u16v8, V1);
  SUB_REG(8H2, simd.v[2], u16v8, V2);
  SUB_REG(8H3, simd.v[3], u16v8, V3);
  SUB_REG(8H4, simd.v[4], u16v8, V4);
  SUB_REG(8H5, simd.v[5], u16v8, V5);
  SUB_REG(8H6, simd.v[6], u16v8, V6);
  SUB_REG(8H7, simd.v[7], u16v8, V7);
  SUB_REG(8H8, simd.v[8], u16v8, V8);
  SUB_REG(8H9, simd.v[9], u16v8, V9);
  SUB_REG(8H10, simd.v[10], u16v8, V10);
  SUB_REG(8H11, simd.v[11], u16v8, V11);
  SUB_REG(8H12, simd.v[12], u16v8, V12);
  SUB_REG(8H13, simd.v[13], u16v8, V13);
  SUB_REG(8H14, simd.v[14], u16v8, V14);
  SUB_REG(8H15, simd.v[15], u16v8, V15);
  SUB_REG(8H16, simd.v[16], u16v8, V16);
  SUB_REG(8H17, simd.v[17], u16v8, V17);
  SUB_REG(8H18, simd.v[18], u16v8, V18);
  SUB_REG(8H19, simd.v[19], u16v8, V19);
  SUB_REG(8H20, simd.v[20], u16v8, V20);
  SUB_REG(8H21, simd.v[21], u16v8, V21);
  SUB_REG(8H22, simd.v[22], u16v8, V22);
  SUB_REG(8H23, simd.v[23], u16v8, V23);
  SUB_REG(8H24, simd.v[24], u16v8, V24);
  SUB_REG(8H25, simd.v[25], u16v8, V25);
  SUB_REG(8H26, simd.v[26], u16v8, V26);
  SUB_REG(8H27, simd.v[27], u16v8, V27);
  SUB_REG(8H28, simd.v[28], u16v8, V28);
  SUB_REG(8H29, simd.v[29], u16v8, V29);
  SUB_REG(8H30, simd.v[30], u16v8, V30);
  SUB_REG(8H31, simd.v[31], u16v8, V31);

  SUB_REG(2S0, simd.v[0], u32v2, V0);
  SUB_REG(2S1, simd.v[1], u32v2, V1);
  SUB_REG(2S2, simd.v[2], u32v2, V2);
  SUB_REG(2S3, simd.v[3], u32v2, V3);
  SUB_REG(2S4, simd.v[4], u32v2, V4);
  SUB_REG(2S5, simd.v[5], u32v2, V5);
  SUB_REG(2S6, simd.v[6], u32v2, V6);
  SUB_REG(2S7, simd.v[7], u32v2, V7);
  SUB_REG(2S8, simd.v[8], u32v2, V8);
  SUB_REG(2S9, simd.v[9], u32v2, V9);
  SUB_REG(2S10, simd.v[10], u32v2, V10);
  SUB_REG(2S11, simd.v[11], u32v2, V11);
  SUB_REG(2S12, simd.v[12], u32v2, V12);
  SUB_REG(2S13, simd.v[13], u32v2, V13);
  SUB_REG(2S14, simd.v[14], u32v2, V14);
  SUB_REG(2S15, simd.v[15], u32v2, V15);
  SUB_REG(2S16, simd.v[16], u32v2, V16);
  SUB_REG(2S17, simd.v[17], u32v2, V17);
  SUB_REG(2S18, simd.v[18], u32v2, V18);
  SUB_REG(2S19, simd.v[19], u32v2, V19);
  SUB_REG(2S20, simd.v[20], u32v2, V20);
  SUB_REG(2S21, simd.v[21], u32v2, V21);
  SUB_REG(2S22, simd.v[22], u32v2, V22);
  SUB_REG(2S23, simd.v[23], u32v2, V23);
  SUB_REG(2S24, simd.v[24], u32v2, V24);
  SUB_REG(2S25, simd.v[25], u32v2, V25);
  SUB_REG(2S26, simd.v[26], u32v2, V26);
  SUB_REG(2S27, simd.v[27], u32v2, V27);
  SUB_REG(2S28, simd.v[28], u32v2, V28);
  SUB_REG(2S29, simd.v[29], u32v2, V29);
  SUB_REG(2S30, simd.v[30], u32v2, V30);
  SUB_REG(2S31, simd.v[31], u32v2, V31);

  SUB_REG(2SF0, simd.v[0], f32v2, V0);
  SUB_REG(2SF1, simd.v[1], f32v2, V1);
  SUB_REG(2SF2, simd.v[2], f32v2, V2);
  SUB_REG(2SF3, simd.v[3], f32v2, V3);
  SUB_REG(2SF4, simd.v[4], f32v2, V4);
  SUB_REG(2SF5, simd.v[5], f32v2, V5);
  SUB_REG(2SF6, simd.v[6], f32v2, V6);
  SUB_REG(2SF7, simd.v[7], f32v2, V7);
  SUB_REG(2SF8, simd.v[8], f32v2, V8);
  SUB_REG(2SF9, simd.v[9], f32v2, V9);
  SUB_REG(2SF10, simd.v[10], f32v2, V10);
  SUB_REG(2SF11, simd.v[11], f32v2, V11);
  SUB_REG(2SF12, simd.v[12], f32v2, V12);
  SUB_REG(2SF13, simd.v[13], f32v2, V13);
  SUB_REG(2SF14, simd.v[14], f32v2, V14);
  SUB_REG(2SF15, simd.v[15], f32v2, V15);
  SUB_REG(2SF16, simd.v[16], f32v2, V16);
  SUB_REG(2SF17, simd.v[17], f32v2, V17);
  SUB_REG(2SF18, simd.v[18], f32v2, V18);
  SUB_REG(2SF19, simd.v[19], f32v2, V19);
  SUB_REG(2SF20, simd.v[20], f32v2, V20);
  SUB_REG(2SF21, simd.v[21], f32v2, V21);
  SUB_REG(2SF22, simd.v[22], f32v2, V22);
  SUB_REG(2SF23, simd.v[23], f32v2, V23);
  SUB_REG(2SF24, simd.v[24], f32v2, V24);
  SUB_REG(2SF25, simd.v[25], f32v2, V25);
  SUB_REG(2SF26, simd.v[26], f32v2, V26);
  SUB_REG(2SF27, simd.v[27], f32v2, V27);
  SUB_REG(2SF28, simd.v[28], f32v2, V28);
  SUB_REG(2SF29, simd.v[29], f32v2, V29);
  SUB_REG(2SF30, simd.v[30], f32v2, V30);
  SUB_REG(2SF31, simd.v[31], f32v2, V31);

  SUB_REG(4S0, simd.v[0], u32v4, V0);
  SUB_REG(4S1, simd.v[1], u32v4, V1);
  SUB_REG(4S2, simd.v[2], u32v4, V2);
  SUB_REG(4S3, simd.v[3], u32v4, V3);
  SUB_REG(4S4, simd.v[4], u32v4, V4);
  SUB_REG(4S5, simd.v[5], u32v4, V5);
  SUB_REG(4S6, simd.v[6], u32v4, V6);
  SUB_REG(4S7, simd.v[7], u32v4, V7);
  SUB_REG(4S8, simd.v[8], u32v4, V8);
  SUB_REG(4S9, simd.v[9], u32v4, V9);
  SUB_REG(4S10, simd.v[10], u32v4, V10);
  SUB_REG(4S11, simd.v[11], u32v4, V11);
  SUB_REG(4S12, simd.v[12], u32v4, V12);
  SUB_REG(4S13, simd.v[13], u32v4, V13);
  SUB_REG(4S14, simd.v[14], u32v4, V14);
  SUB_REG(4S15, simd.v[15], u32v4, V15);
  SUB_REG(4S16, simd.v[16], u32v4, V16);
  SUB_REG(4S17, simd.v[17], u32v4, V17);
  SUB_REG(4S18, simd.v[18], u32v4, V18);
  SUB_REG(4S19, simd.v[19], u32v4, V19);
  SUB_REG(4S20, simd.v[20], u32v4, V20);
  SUB_REG(4S21, simd.v[21], u32v4, V21);
  SUB_REG(4S22, simd.v[22], u32v4, V22);
  SUB_REG(4S23, simd.v[23], u32v4, V23);
  SUB_REG(4S24, simd.v[24], u32v4, V24);
  SUB_REG(4S25, simd.v[25], u32v4, V25);
  SUB_REG(4S26, simd.v[26], u32v4, V26);
  SUB_REG(4S27, simd.v[27], u32v4, V27);
  SUB_REG(4S28, simd.v[28], u32v4, V28);
  SUB_REG(4S29, simd.v[29], u32v4, V29);
  SUB_REG(4S30, simd.v[30], u32v4, V30);
  SUB_REG(4S31, simd.v[31], u32v4, V31);

  SUB_REG(4SF0, simd.v[0], f32v4, V0);
  SUB_REG(4SF1, simd.v[1], f32v4, V1);
  SUB_REG(4SF2, simd.v[2], f32v4, V2);
  SUB_REG(4SF3, simd.v[3], f32v4, V3);
  SUB_REG(4SF4, simd.v[4], f32v4, V4);
  SUB_REG(4SF5, simd.v[5], f32v4, V5);
  SUB_REG(4SF6, simd.v[6], f32v4, V6);
  SUB_REG(4SF7, simd.v[7], f32v4, V7);
  SUB_REG(4SF8, simd.v[8], f32v4, V8);
  SUB_REG(4SF9, simd.v[9], f32v4, V9);
  SUB_REG(4SF10, simd.v[10], f32v4, V10);
  SUB_REG(4SF11, simd.v[11], f32v4, V11);
  SUB_REG(4SF12, simd.v[12], f32v4, V12);
  SUB_REG(4SF13, simd.v[13], f32v4, V13);
  SUB_REG(4SF14, simd.v[14], f32v4, V14);
  SUB_REG(4SF15, simd.v[15], f32v4, V15);
  SUB_REG(4SF16, simd.v[16], f32v4, V16);
  SUB_REG(4SF17, simd.v[17], f32v4, V17);
  SUB_REG(4SF18, simd.v[18], f32v4, V18);
  SUB_REG(4SF19, simd.v[19], f32v4, V19);
  SUB_REG(4SF20, simd.v[20], f32v4, V20);
  SUB_REG(4SF21, simd.v[21], f32v4, V21);
  SUB_REG(4SF22, simd.v[22], f32v4, V22);
  SUB_REG(4SF23, simd.v[23], f32v4, V23);
  SUB_REG(4SF24, simd.v[24], f32v4, V24);
  SUB_REG(4SF25, simd.v[25], f32v4, V25);
  SUB_REG(4SF26, simd.v[26], f32v4, V26);
  SUB_REG(4SF27, simd.v[27], f32v4, V27);
  SUB_REG(4SF28, simd.v[28], f32v4, V28);
  SUB_REG(4SF29, simd.v[29], f32v4, V29);
  SUB_REG(4SF30, simd.v[30], f32v4, V30);
  SUB_REG(4SF31, simd.v[31], f32v4, V31);

  SUB_REG(1D0, simd.v[0], u64v1, V0);
  SUB_REG(1D1, simd.v[1], u64v1, V1);
  SUB_REG(1D2, simd.v[2], u64v1, V2);
  SUB_REG(1D3, simd.v[3], u64v1, V3);
  SUB_REG(1D4, simd.v[4], u64v1, V4);
  SUB_REG(1D5, simd.v[5], u64v1, V5);
  SUB_REG(1D6, simd.v[6], u64v1, V6);
  SUB_REG(1D7, simd.v[7], u64v1, V7);
  SUB_REG(1D8, simd.v[8], u64v1, V8);
  SUB_REG(1D9, simd.v[9], u64v1, V9);
  SUB_REG(1D10, simd.v[10], u64v1, V10);
  SUB_REG(1D11, simd.v[11], u64v1, V11);
  SUB_REG(1D12, simd.v[12], u64v1, V12);
  SUB_REG(1D13, simd.v[13], u64v1, V13);
  SUB_REG(1D14, simd.v[14], u64v1, V14);
  SUB_REG(1D15, simd.v[15], u64v1, V15);
  SUB_REG(1D16, simd.v[16], u64v1, V16);
  SUB_REG(1D17, simd.v[17], u64v1, V17);
  SUB_REG(1D18, simd.v[18], u64v1, V18);
  SUB_REG(1D19, simd.v[19], u64v1, V19);
  SUB_REG(1D20, simd.v[20], u64v1, V20);
  SUB_REG(1D21, simd.v[21], u64v1, V21);
  SUB_REG(1D22, simd.v[22], u64v1, V22);
  SUB_REG(1D23, simd.v[23], u64v1, V23);
  SUB_REG(1D24, simd.v[24], u64v1, V24);
  SUB_REG(1D25, simd.v[25], u64v1, V25);
  SUB_REG(1D26, simd.v[26], u64v1, V26);
  SUB_REG(1D27, simd.v[27], u64v1, V27);
  SUB_REG(1D28, simd.v[28], u64v1, V28);
  SUB_REG(1D29, simd.v[29], u64v1, V29);
  SUB_REG(1D30, simd.v[30], u64v1, V30);
  SUB_REG(1D31, simd.v[31], u64v1, V31);

  SUB_REG(1DF0, simd.v[0], f64v1, V0);
  SUB_REG(1DF1, simd.v[1], f64v1, V1);
  SUB_REG(1DF2, simd.v[2], f64v1, V2);
  SUB_REG(1DF3, simd.v[3], f64v1, V3);
  SUB_REG(1DF4, simd.v[4], f64v1, V4);
  SUB_REG(1DF5, simd.v[5], f64v1, V5);
  SUB_REG(1DF6, simd.v[6], f64v1, V6);
  SUB_REG(1DF7, simd.v[7], f64v1, V7);
  SUB_REG(1DF8, simd.v[8], f64v1, V8);
  SUB_REG(1DF9, simd.v[9], f64v1, V9);
  SUB_REG(1DF10, simd.v[10], f64v1, V10);
  SUB_REG(1DF11, simd.v[11], f64v1, V11);
  SUB_REG(1DF12, simd.v[12], f64v1, V12);
  SUB_REG(1DF13, simd.v[13], f64v1, V13);
  SUB_REG(1DF14, simd.v[14], f64v1, V14);
  SUB_REG(1DF15, simd.v[15], f64v1, V15);
  SUB_REG(1DF16, simd.v[16], f64v1, V16);
  SUB_REG(1DF17, simd.v[17], f64v1, V17);
  SUB_REG(1DF18, simd.v[18], f64v1, V18);
  SUB_REG(1DF19, simd.v[19], f64v1, V19);
  SUB_REG(1DF20, simd.v[20], f64v1, V20);
  SUB_REG(1DF21, simd.v[21], f64v1, V21);
  SUB_REG(1DF22, simd.v[22], f64v1, V22);
  SUB_REG(1DF23, simd.v[23], f64v1, V23);
  SUB_REG(1DF24, simd.v[24], f64v1, V24);
  SUB_REG(1DF25, simd.v[25], f64v1, V25);
  SUB_REG(1DF26, simd.v[26], f64v1, V26);
  SUB_REG(1DF27, simd.v[27], f64v1, V27);
  SUB_REG(1DF28, simd.v[28], f64v1, V28);
  SUB_REG(1DF29, simd.v[29], f64v1, V29);
  SUB_REG(1DF30, simd.v[30], f64v1, V30);
  SUB_REG(1DF31, simd.v[31], f64v1, V31);

  SUB_REG(2D0, simd.v[0], u64v2, V0);
  SUB_REG(2D1, simd.v[1], u64v2, V1);
  SUB_REG(2D2, simd.v[2], u64v2, V2);
  SUB_REG(2D3, simd.v[3], u64v2, V3);
  SUB_REG(2D4, simd.v[4], u64v2, V4);
  SUB_REG(2D5, simd.v[5], u64v2, V5);
  SUB_REG(2D6, simd.v[6], u64v2, V6);
  SUB_REG(2D7, simd.v[7], u64v2, V7);
  SUB_REG(2D8, simd.v[8], u64v2, V8);
  SUB_REG(2D9, simd.v[9], u64v2, V9);
  SUB_REG(2D10, simd.v[10], u64v2, V10);
  SUB_REG(2D11, simd.v[11], u64v2, V11);
  SUB_REG(2D12, simd.v[12], u64v2, V12);
  SUB_REG(2D13, simd.v[13], u64v2, V13);
  SUB_REG(2D14, simd.v[14], u64v2, V14);
  SUB_REG(2D15, simd.v[15], u64v2, V15);
  SUB_REG(2D16, simd.v[16], u64v2, V16);
  SUB_REG(2D17, simd.v[17], u64v2, V17);
  SUB_REG(2D18, simd.v[18], u64v2, V18);
  SUB_REG(2D19, simd.v[19], u64v2, V19);
  SUB_REG(2D20, simd.v[20], u64v2, V20);
  SUB_REG(2D21, simd.v[21], u64v2, V21);
  SUB_REG(2D22, simd.v[22], u64v2, V22);
  SUB_REG(2D23, simd.v[23], u64v2, V23);
  SUB_REG(2D24, simd.v[24], u64v2, V24);
  SUB_REG(2D25, simd.v[25], u64v2, V25);
  SUB_REG(2D26, simd.v[26], u64v2, V26);
  SUB_REG(2D27, simd.v[27], u64v2, V27);
  SUB_REG(2D28, simd.v[28], u64v2, V28);
  SUB_REG(2D29, simd.v[29], u64v2, V29);
  SUB_REG(2D30, simd.v[30], u64v2, V30);
  SUB_REG(2D31, simd.v[31], u64v2, V31);

  SUB_REG(2DF0, simd.v[0], f64v2, V0);
  SUB_REG(2DF1, simd.v[1], f64v2, V1);
  SUB_REG(2DF2, simd.v[2], f64v2, V2);
  SUB_REG(2DF3, simd.v[3], f64v2, V3);
  SUB_REG(2DF4, simd.v[4], f64v2, V4);
  SUB_REG(2DF5, simd.v[5], f64v2, V5);
  SUB_REG(2DF6, simd.v[6], f64v2, V6);
  SUB_REG(2DF7, simd.v[7], f64v2, V7);
  SUB_REG(2DF8, simd.v[8], f64v2, V8);
  SUB_REG(2DF9, simd.v[9], f64v2, V9);
  SUB_REG(2DF10, simd.v[10], f64v2, V10);
  SUB_REG(2DF11, simd.v[11], f64v2, V11);
  SUB_REG(2DF12, simd.v[12], f64v2, V12);
  SUB_REG(2DF13, simd.v[13], f64v2, V13);
  SUB_REG(2DF14, simd.v[14], f64v2, V14);
  SUB_REG(2DF15, simd.v[15], f64v2, V15);
  SUB_REG(2DF16, simd.v[16], f64v2, V16);
  SUB_REG(2DF17, simd.v[17], f64v2, V17);
  SUB_REG(2DF18, simd.v[18], f64v2, V18);
  SUB_REG(2DF19, simd.v[19], f64v2, V19);
  SUB_REG(2DF20, simd.v[20], f64v2, V20);
  SUB_REG(2DF21, simd.v[21], f64v2, V21);
  SUB_REG(2DF22, simd.v[22], f64v2, V22);
  SUB_REG(2DF23, simd.v[23], f64v2, V23);
  SUB_REG(2DF24, simd.v[24], f64v2, V24);
  SUB_REG(2DF25, simd.v[25], f64v2, V25);
  SUB_REG(2DF26, simd.v[26], f64v2, V26);
  SUB_REG(2DF27, simd.v[27], f64v2, V27);
  SUB_REG(2DF28, simd.v[28], f64v2, V28);
  SUB_REG(2DF29, simd.v[29], f64v2, V29);
  SUB_REG(2DF30, simd.v[30], f64v2, V30);
  SUB_REG(2DF31, simd.v[31], f64v2, V31);

  REG(TPIDR_EL0, sr.tpidr_el0.qword, u64);
  REG(TPIDRRO_EL0, sr.tpidrro_el0.qword, u64);
  REG(CTR_EL0, sr.ctr_el0.qword, u64);
  REG(DCZID_EL0, sr.dczid_el0.qword, u64);
  REG(MIDR_EL0, sr.midr_el1.qword, u64);
  REG(ECV_NZCV, ecv_nzcv, u64);
}
}  // namespace remill