#include "TestState.h"

#include <map>

uint64_t g_inst_vma = g_test_disasm_func_vma;

#define NEXT_VMA() (g_inst_vma += 4, g_inst_vma)

std::map<uint64_t, TestInstructionState> g_disasm_funcs = {
    {g_inst_vma, TestInstructionState("mov x0, #42", {}, {{"X0", 42}})},
    {NEXT_VMA(), TestInstructionState("mov x1, #52", {}, {{"X1", 52}})},
    {NEXT_VMA(), TestInstructionState("mov x2, #62", {}, {{"X2", 62}})},
    {NEXT_VMA(), TestInstructionState("add x1, x2, x3", {{"X2", 12}, {"X3", 21}}, {{"X1", 33}})},
    /* must be inserted at end */ {NEXT_VMA(), TestInstructionState("ret", {}, {})}};
