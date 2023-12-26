#include "TestLift.h"

#include <map>

uint64_t vma = g_test_disasm_func_vma;

std::map<uint64_t, TestInstructionState> g_disasm_funcs = {
    {vma++, TestInstructionState("mov x0, #42", {}, {{"x0", 42}})}};