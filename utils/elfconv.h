#pragma once

#include <iostream>
#include <remill/BC/HelperMacro.h>
#if defined(RUNTIME_SIGSEGV_DEBUG) && defined(__linux__)
#  include <signal.h>
#endif

/* debug function */
extern "C" void debug_state_machine();
extern "C" void debug_state_machine_vectors();
extern "C" void debug_insn();
