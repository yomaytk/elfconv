#include "Runtime.h"

#include "utils/Util.h"

#if defined(__FORK_PTHREAD__)

// Entry point of the pthread for fork emulation.
// This function must be called as pthread.
void *ManageNewForkPthread(void *arg) {

  auto ecv_pthread_arg = (struct EcvPthreadArg *) arg;
  auto ecv_pr = ecv_pthread_arg->ecv_pr;
  auto rt_m = ecv_pthread_arg->rt_m;
  auto t_func = ecv_pthread_arg->t_func;
  auto next_pc = ecv_pthread_arg->next_pc;

  auto new_ecv_pid = rt_m->GetNewEcvPID();

  // set global (actually, thread_local) state data.
  CPUState = ecv_pr->cpu_state;
  CurEcvPid = new_ecv_pid;

  // call the target function (must be the function which issue fork syscall).
  t_func(ecv_pr->memory_arena->bytes, CPUState, next_pc, rt_m);

  // execution loop for `parent_call_history`.
  for (;;) {

    if (CPUState->func_depth == 0) {
      LiftedFunc tn_func;

      if (ecv_pr->parent_call_history.empty()) {
        elfconv_runtime_error("parent_call_history must not be empty.\n");
      }

      auto [tn_func_addr, tn_func_next_pc] = ecv_pr->parent_call_history.top();
      ecv_pr->parent_call_history.pop();

      auto tn_func_it = std::lower_bound(
          rt_m->addr_funptr_srt_list.begin(), rt_m->addr_funptr_srt_list.end(), tn_func_addr,
          [](auto const &lhs, addr_t value) { return lhs.first < value; });
      tn_func = tn_func_it->second;

      CPUState->gpr.pc.qword = tn_func_next_pc;
      CPUState->func_depth = 1;
      ecv_pr->call_history.pop();

      // jmp to the function the top of history.
      tn_func(ecv_pr->memory_arena->bytes, CPUState, tn_func_next_pc, rt_m);
    } else {
      elfconv_runtime_error(
          "function depth must be 0 after the normal function call finishing. function_depth: %ld\n",
          CPUState->func_depth);
    }
  }
}

#endif