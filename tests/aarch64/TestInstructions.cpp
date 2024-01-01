#include "TestLift.h"

#include <map>

uint64_t vma = g_test_disasm_func_vma;

#define NEXT_VMA() (vma += 4, vma)

std::map<uint64_t, TestInstructionState> g_disasm_funcs = {
    {vma, TestInstructionState("mov x0, #42", {}, {{"X0", 42}})},
    {NEXT_VMA(), TestInstructionState("mov x1, #52", {}, {{"X1", 52}})},
    {NEXT_VMA(), TestInstructionState("mov x2, #62", {}, {{"X2", 62}})},
    {NEXT_VMA(), TestInstructionState("ret", {}, {})}};