#pragma once

#include <iostream>
#include <remill/BC/HelperMacro.h>
#if defined(LIFT_DEBUG)
#  include <signal.h>
#endif

/* debug function */
extern "C" void debug_state_machine();
extern "C" void debug_state_machine_vectors();
extern "C" void debug_insn();
#if defined(LIFT_DEBUG)
extern "C" void segv_debug_state_machine(int sig, siginfo_t *info, void *ctx);
#endif