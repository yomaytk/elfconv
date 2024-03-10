#pragma once

#include <iostream>
#include <remill/BC/HelperMacro.h>
#if defined(LIFT_DEBUG) && defined(__linux__)
#  include <signal.h>
#endif

/* debug function */
extern "C" void debug_state_machine();
extern "C" void debug_state_machine_vectors();
extern "C" void debug_memory_value_change();
extern "C" void debug_insn();
#if defined(LIFT_DEBUG) && defined(__linux__)
extern "C" void segv_debug_state_machine(int sig, siginfo_t *info, void *ctx);
#endif