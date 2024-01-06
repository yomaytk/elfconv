#pragma once

#include <string>
#include <unordered_map>

static const uintptr_t g_test_disasm_func_vma = 0x00400000;

class TestInstructionState {
 public:
  std::string mnemonic;
  std::unordered_map<std::string, uint64_t> ini_state;
  std::unordered_map<std::string, uint64_t> required_state;

  TestInstructionState(std::string __mnemonic,
                       std::unordered_map<std::string, uint64_t> __ini_state,
                       std::unordered_map<std::string, uint64_t> __required_state)
      : mnemonic(__mnemonic),
        ini_state(__ini_state),
        required_state(__required_state) {}
  TestInstructionState() {}
};
