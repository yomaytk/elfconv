#pragma once
#include "TestState.h"
#include "lifter/Lift.h"
#include "lifter/MainLifter.h"
#include "lifter/TraceManager.h"
#include "runtime/Memory.h"

#include <cstddef>
#include <cstdint>

class DisassembleCmd {
 public:
  static void ExecRasm2(const std::string &nemonic, uint8_t insn_bytes[4]);
};

class TestAArch64TraceManager final : public AArch64TraceManager {
 public:
  TestAArch64TraceManager(std::string __target_elf_file_name)
      : AArch64TraceManager(__target_elf_file_name){};
  std::unordered_map<uint64_t, TestInstructionState *> test_inst_state_map;
};
