#include "Memory.h"
#include "Runtime.h"
#include "remill/Arch/Runtime/Types.h"

#include <algorithm>
#include <cassert>
#include <cstdarg>
#include <iomanip>
#include <iostream>
#include <remill/Arch/Runtime/Intrinsics.h>
#include <remill/BC/HelperMacro.h>
#include <sstream>
#include <unordered_map>
#include <utils/Util.h>
#include <utils/elfconv.h>

#if defined(ELF_IS_AARCH64)
#  include <remill/Arch/AArch64/Runtime/State.h>
#  define PCREG CPUState.gpr.pc.qword
#elif defined(ELF_IS_AMD64)
#  include <remill/Arch/X86/Runtime/State.h>
#  define PCREG CPUState.gpr.rip.qword
#else
#  define PCREG CPUState.gpr.pc.qword
#endif

#define UNDEFINED_INTRINSICS(intrinsics) \
  printf("[ERROR] undefined intrinsics: %s\n", intrinsics); \
  debug_state_machine(); \
  fflush(stdout); \
  abort();

// __remill_(read | write)_memory_* functions are not used for the optimization.

uint8_t __remill_read_memory_8(RuntimeManager *runtime_manager, addr_t addr) {
  elfconv_runtime_error("__remill_read_memory_8 function must not be called!");
}

uint16_t __remill_read_memory_16(RuntimeManager *runtime_manager, addr_t addr) {
  elfconv_runtime_error("__remill_read_memory_16 function must not be called!");
}

uint32_t __remill_read_memory_32(RuntimeManager *runtime_manager, addr_t addr) {
  elfconv_runtime_error("__remill_read_memory_32 function must not be called!");
}

uint64_t __remill_read_memory_64(RuntimeManager *runtime_manager, addr_t addr) {
  elfconv_runtime_error("__remill_read_memory_64 function must not be called!");
}

uint128_t __remill_read_memory_128(RuntimeManager *runtime_manager, addr_t addr) {
  elfconv_runtime_error("__remill_read_memory_128 function must not be called!");
}

float32_t __remill_read_memory_f32(RuntimeManager *runtime_manager, addr_t addr) {
  elfconv_runtime_error("__remill_read_memory_f32 function must not be called!");
}

float64_t __remill_read_memory_f64(RuntimeManager *runtime_manager, addr_t addr) {
  elfconv_runtime_error("__remill_read_memory_f64 function must not be called!");
}

void __remill_write_memory_8(RuntimeManager *runtime_manager, addr_t addr, uint8_t src) {
  elfconv_runtime_error("__remill_write_memory_8 function must not be called!");
}

void __remill_write_memory_16(RuntimeManager *runtime_manager, addr_t addr, uint16_t src) {
  elfconv_runtime_error("__remill_write_memory_16 function must not be called!");
}

void __remill_write_memory_32(RuntimeManager *runtime_manager, addr_t addr, uint32_t src) {
  elfconv_runtime_error("__remill_write_memory_32 function must not be called!");
}

void __remill_write_memory_64(RuntimeManager *runtime_manager, addr_t addr, uint64_t src) {
  elfconv_runtime_error("__remill_write_memory_64 function must not be called!");
}

void __remill_write_memory_128(RuntimeManager *runtime_manager, addr_t addr, uint128_t src) {
  elfconv_runtime_error("__remill_write_memory_128 function must not be called!");
}

void __remill_write_memory_f32(RuntimeManager *runtime_manager, addr_t addr, float32_t src) {
  elfconv_runtime_error("__remill_write_memory_f32 function must not be called!");
}

void __remill_write_memory_f64(RuntimeManager *runtime_manager, addr_t addr, float64_t src) {
  elfconv_runtime_error("__remill_write_memory_f64 function must not be called!");
}

void __remill_write_memory_f128(RuntimeManager *, addr_t, float128_t) {}

/*
  tranpoline call for emulating syscall of original ELF binary.
*/
void __remill_syscall_tranpoline_call(State &state, RuntimeManager *runtime_manager) {
  /* TODO: We should select one syscall emulate process (own implementation, WASI, LKL, etc...) */
#if defined(TARGET_IS_WASI)
  runtime_manager->SVCWasiCall();
#elif defined(TARGET_IS_BROWSER)
  runtime_manager->SVCBrowserCall();
#else
  runtime_manager->SVCNativeCall();
#endif
}

/*
  Marks `mem` as being used. This is used for making sure certain symbols are
  kept around through optimization, and makes sure that optimization doesn't
  perform dead-argument elimination on any of the intrinsics.
*/
extern "C" void __remill_mark_as_used(void *mem) {
  asm("" ::"m"(mem));
}

void __remill_function_return(State &state, addr_t fn_ret_vma, RuntimeManager *runtime_manager) {}

void __remill_missing_block(State &, addr_t, RuntimeManager *runtime_manager) {
  std::cout << std::hex << std::setw(16) << std::setfill('0')
            << "[WARNING] reached \"__remill_missing_block\", PC: 0x" << PCREG << std::endl;
}

void __remill_async_hyper_call(State &, addr_t ret_addr, RuntimeManager *runtime_manager) {}

void __remill_error(State &, addr_t addr, RuntimeManager *) {
  printf("[ERROR] Reached __remill_error.\n");
  debug_state_machine();
  fflush(stdout);
  abort();
}

/*
  BLR instuction
  The remill semantic sets X30 link register, so this only jumps to target function.
*/

void __remill_function_call(State &state, addr_t t_vma, RuntimeManager *runtime_manager) {
  // jump to the optimized function.
  if (auto jmp_fn = runtime_manager->addr_optfn_vma_map[t_vma]; jmp_fn) {
    jmp_fn(&state, t_vma, runtime_manager);
  }
  // jump to the noopt function.
  else if (auto it = std::lower_bound(runtime_manager->noopt_fun_entrys.begin(),
                                      runtime_manager->noopt_fun_entrys.end(), t_vma);
           it != runtime_manager->noopt_fun_entrys.end()) {
    PCREG = t_vma;
    auto noopt_t_fun = runtime_manager->addr_nooptfn_vma_map.at(*it);
    noopt_t_fun(&state, *it, runtime_manager);
  } else {
    elfconv_runtime_error(
        "[ERROR] vma 0x%016llx is not included in the lifted function pointer table (BLR). PC: "
        "0x%08x\n",
        t_vma, PCREG);
  }
}

/* BR instruction */
void __remill_jump(State &state, addr_t t_vma, RuntimeManager *runtime_manager) {
  // jump to the optimized function.
  if (auto jmp_fn = runtime_manager->addr_optfn_vma_map[t_vma]; jmp_fn) {
    jmp_fn(&state, t_vma, runtime_manager);
  }
  // jump to the noopt function.
  else if (auto it = std::lower_bound(runtime_manager->noopt_fun_entrys.begin(),
                                      runtime_manager->noopt_fun_entrys.end(), t_vma);
           it != runtime_manager->noopt_fun_entrys.end()) {
    PCREG = t_vma;
    auto noopt_t_fun = runtime_manager->addr_nooptfn_vma_map.at(*it);
    noopt_t_fun(&state, *it, runtime_manager);
  } else {
    elfconv_runtime_error(
        "[ERROR] vma 0x%016llx is not included in the lifted function pointer table (BR). PC: "
        "0x%08x\n",
        t_vma, PCREG);
  }
}

// get the target basic block label pointer for indirectbr instruction
extern "C" uint64_t *__g_get_indirectbr_block_address(RuntimeManager *runtime_manager,
                                                      uint64_t fun_vma, uint64_t bb_vma) {
  if (runtime_manager->addr_block_addrs_map.count(fun_vma) == 1) {
    auto &vma_bb_map = runtime_manager->addr_block_addrs_map[fun_vma];
    if (vma_bb_map.count(bb_vma) == 1) {
      return vma_bb_map[bb_vma];
    } else {
      if (runtime_manager->addr_optfn_vma_map.count(fun_vma) == 1 ||
          runtime_manager->addr_nooptfn_vma_map.count(fun_vma) == 1) {
        return vma_bb_map[UINT64_MAX];
      } else {
        elfconv_runtime_error(
            "[ERROR] 0x%llx is neither the block address vma or lifted function vma of '%s'.\n",
            bb_vma, __func__);
      }
    }
  } else {
    elfconv_runtime_error(
        "[ERROR] 0x%llx is not the entry address of any lifted function. (at %s)\n", fun_vma,
        __func__);
  }
}

// get the target basic block label pointer on the noopt indirectbr instruction.
extern "C" uint64_t *_ecv_noopt_get_bb(RuntimeManager *runtime_manager, addr_t t_vma) {
  auto it = std::lower_bound(runtime_manager->noopt_inst_vmas.begin(),
                             runtime_manager->noopt_inst_vmas.end(), t_vma);
  if (t_vma != *it) {
    elfconv_runtime_error("address 0x%lx cannot be found on the basic block list.", t_vma);
  }
  return runtime_manager->noopt_bb_ptrs[it - runtime_manager->noopt_inst_vmas.begin()];
}

// push the callee symbol to the call stack for debug
extern "C" void debug_call_stack_push(RuntimeManager *runtime_manager, uint64_t fn_vma) {
  if (auto func_name = runtime_manager->addr_fn_symbol_map[fn_vma]; func_name) {
    if (strncmp(func_name, "fn_plt", 6) == 0) {
      return;
    }
    runtime_manager->call_stacks.push_back(fn_vma);
    std::string tab_space;
    for (size_t i = 0; i < runtime_manager->call_stacks.size(); i++) {
      if (i & 0b1)
        tab_space += "\033[34m";
      else
        tab_space += "\033[31m";
      tab_space += "|";
    }
    tab_space += "\033[0m";
    char entry_func_log[100];
    snprintf(entry_func_log, 100, "start : %s\n", func_name);
    printf("%s", tab_space.c_str());
    printf("%s", entry_func_log);
  } else {
    elfconv_runtime_error("[ERROR] unknown entry func vma: 0x%08llx\n", fn_vma);
  }
}

// pop the callee symbol from the call stack for debug
extern "C" void debug_call_stack_pop(RuntimeManager *runtime_manager, uint64_t fn_vma) {
  if (runtime_manager->call_stacks.empty()) {
    elfconv_runtime_error("invalid debug call stack empty. PC: 0x%016llx\n", PCREG);
  } else {
    auto last_call_vma = runtime_manager->call_stacks.back();
    auto func_name = runtime_manager->addr_fn_symbol_map[last_call_vma];
    if (strncmp(func_name, "fn_plt", 6) != 0) {
      if (fn_vma != last_call_vma)
        elfconv_runtime_error("fn_vma: %lu(%s) must be equal to last_call_vma(%s): %lu\n", fn_vma,
                              last_call_vma, runtime_manager->addr_fn_symbol_map[fn_vma],
                              runtime_manager->addr_fn_symbol_map[last_call_vma]);
      runtime_manager->call_stacks.pop_back();
      return;
      std::string tab_space;
      for (int i = 0; i < runtime_manager->call_stacks.size(); i++) {
        if (i & 0b1)
          tab_space += "\033[34m";
        else
          tab_space += "\033[31m";
        tab_space += "|";
      }
      tab_space += "\033[0m";
      char return_func_log[100];
      snprintf(return_func_log, 100, "end   : %s\n", func_name);
      printf("%s", tab_space.c_str());
      printf("%s", return_func_log);
    }
  }
}

// observe the value change of runtime memory
extern "C" void debug_memory_value_change(RuntimeManager *runtime_manager) {
  // step 1. set target vma
  static uint64_t target_vma = 0x491030;
  if (0 == target_vma)
    return;
  static uint64_t old_value = 0;
  // step 2. get the current value on the address (uint64_t -> __remill_read_memory_64)
  auto cur_value = __remill_read_memory_64(runtime_manager, target_vma);
  if (old_value != cur_value) {
    std::cout << std::hex << "target_vma: 0x" << target_vma << "\told value: 0x" << old_value
              << "\tcurrent value: 0x" << cur_value << std::endl;
    old_value = cur_value;
  }
}

// observe the value of runtime memory
extern "C" void debug_memory_value(RuntimeManager *runtime_manager) {
  // step 1. set target vma
  std::vector<uint64_t> target_vmas = {0xfffff00000ffb98};
  // step 2. set the data type of target values
  std::cout << "[Memory Debug]" << std::endl;
  for (auto &target_vma : target_vmas) {
    auto target_pma = (double *) runtime_manager->TranslateVMA(target_vma);
    std::cout << "*target_pma: " << *target_pma << std::endl;
  }
}

extern "C" void debug_string(const char *str) {
  std::cout << str << std::endl;
}


extern "C" void debug_vma_and_registers(uint64_t pc, uint64_t args_num, ...) {

  static std::string reg_space = " 0x                 ";
  static std::string org_debug_str =
      "PC:" + reg_space + "X0:" + reg_space + "X1:" + reg_space + "X2:" + reg_space +
      "X3:" + reg_space + "X4:" + reg_space + "X5:" + reg_space + "X6:" + reg_space +
      "X7:" + reg_space + "X8:" + reg_space + "X9:" + reg_space + "PC:" + reg_space +
      "X10:" + reg_space + "X11:" + reg_space + "X12:" + reg_space + "X13:" + reg_space +
      "X14:" + reg_space + "X15:" + reg_space + "X16:" + reg_space + "X17:" + reg_space +
      "X18:" + reg_space + "X19:" + reg_space + "PC:" + reg_space + "X20:" + reg_space +
      "X21:" + reg_space + "X22:" + reg_space + "X23:" + reg_space + "X24:" + reg_space +
      "X25:" + reg_space + "X26:" + reg_space + "X27:" + reg_space + "X28:" + reg_space +
      "X29:" + reg_space + "X30:" + reg_space + "SP:" + reg_space + "ECV_NZCV" + reg_space;

#define __SP_INDEX 31
#define __ECV_NZCV_INDEX 32

  static uint64_t general_regs_offsets[] = {
      /* 0 */ 3 * 2 + reg_space.length() + 3,
      /* 1 */ 3 * 3 + reg_space.length() * 2 + 3,
      /* 2 */ 3 * 4 + reg_space.length() * 3 + 3,
      /* 3 */ 3 * 5 + reg_space.length() * 4 + 3,
      /* 4 */ 3 * 6 + reg_space.length() * 5 + 3,
      /* 5 */ 3 * 7 + reg_space.length() * 6 + 3,
      /* 6 */ 3 * 8 + reg_space.length() * 7 + 3,
      /* 7 */ 3 * 9 + reg_space.length() * 8 + 3,
      /* 8 */ 3 * 10 + reg_space.length() * 9 + 3,
      /* 9 */ 3 * 11 + reg_space.length() * 10 + 3,
      /* 10 (skip 1 PC) */ 3 * 12 + 4 * 1 + reg_space.length() * 12 + 3,
      /* 11 */ 3 * 12 + 4 * 2 + reg_space.length() * 13 + 3,
      /* 12 */ 3 * 12 + 4 * 3 + reg_space.length() * 14 + 3,
      /* 13 */ 3 * 12 + 4 * 4 + reg_space.length() * 15 + 3,
      /* 14 */ 3 * 12 + 4 * 5 + reg_space.length() * 16 + 3,
      /* 15 */ 3 * 12 + 4 * 6 + reg_space.length() * 17 + 3,
      /* 16 */ 3 * 12 + 4 * 7 + reg_space.length() * 18 + 3,
      /* 17 */ 3 * 12 + 4 * 8 + reg_space.length() * 19 + 3,
      /* 18 */ 3 * 12 + 4 * 9 + reg_space.length() * 20 + 3,
      /* 19 */ 3 * 12 + 4 * 10 + reg_space.length() * 21 + 3,
      /* 20 (skip 2 PC) */ 3 * 13 + 4 * 11 + reg_space.length() * 23 + 3,
      /* 21 */ 3 * 13 + 4 * 12 + reg_space.length() * 24 + 3,
      /* 22 */ 3 * 13 + 4 * 13 + reg_space.length() * 25 + 3,
      /* 23 */ 3 * 13 + 4 * 14 + reg_space.length() * 26 + 3,
      /* 24 */ 3 * 13 + 4 * 15 + reg_space.length() * 27 + 3,
      /* 25 */ 3 * 13 + 4 * 16 + reg_space.length() * 28 + 3,
      /* 26 */ 3 * 13 + 4 * 17 + reg_space.length() * 29 + 3,
      /* 27 */ 3 * 13 + 4 * 18 + reg_space.length() * 30 + 3,
      /* 28 */ 3 * 13 + 4 * 19 + reg_space.length() * 31 + 3,
      /* 29 */ 3 * 13 + 4 * 20 + reg_space.length() * 32 + 3,
      /* 30 */ 3 * 13 + 4 * 21 + reg_space.length() * 33 + 3,
      /* SP */ 3 * 13 + 4 * 22 + reg_space.length() * 34 + 3,
      /* ECV_NZCV */ 3 * 13 + 4 * 22 + 8 + reg_space.length() * 35 + 3,
  };

  va_list args;
  va_start(args, args_num);

  if (args_num & 0b1) {
    elfconv_runtime_error("args_num must be even number at debug_vma_and_registers. args_num: %ld",
                          args_num);
  }

  std::string general_regs_str = org_debug_str;
  std::stringstream vector_regs_str("");
  std::stringstream tmp_str("");

  // PC
  tmp_str << std::hex << pc;
  auto pc_str_len = tmp_str.str().length();

  general_regs_str.replace(3 + 3 + (16 - pc_str_len), pc_str_len,
                           tmp_str.str());  // 1 PC
  general_regs_str.replace(general_regs_offsets[9] + reg_space.length() + 3 + (16 - pc_str_len),
                           pc_str_len,
                           tmp_str.str());  // 2 PC
  general_regs_str.replace(general_regs_offsets[19] + reg_space.length() + 3 + (16 - pc_str_len),
                           pc_str_len,
                           tmp_str.str());  // 3 PC

  tmp_str.str("");
  tmp_str.clear(std::stringstream::goodbit);

  // All regs
  for (size_t i = 0; i < args_num; i += 2) {
    char *reg_name = va_arg(args, char *);
    // Vector
    if ('V' == reg_name[0]) {
      uint128_t reg_val = va_arg(args, uint128_t);
      uint64_t high = static_cast<uint64_t>(reg_val >> 64);
      uint64_t low = static_cast<uint64_t>(reg_val & 0xffff'ffff'ffff'ffff);
      vector_regs_str << reg_name << ": 0x" << std::hex << std::setw(16) << std::setfill('0')
                      << high << std::setw(16) << std::setfill('0') << low << " ";
    }
    // General or Special
    else {
      uint64_t reg_val = va_arg(args, uint64_t);
      tmp_str.str("");
      tmp_str.clear(std::stringstream::goodbit);
      tmp_str << std::hex << reg_val;
      auto tmp_str_len = tmp_str.str().length();
      size_t reg_index;
      if (reg_name[0] == 'X') {
        reg_index = std::atoi(reg_name + 1);
      } else if (strncmp(reg_name, "ECV_NZCV", 8) == 0) {
        reg_index = __ECV_NZCV_INDEX;
      } else if (strncmp(reg_name, "SP", 2) == 0) {
        reg_index = __SP_INDEX;
      } else {
        if (strncmp(reg_name, "PC", 2) != 0) {
          elfconv_runtime_error("invalid reg_name on the debug_vma_and_registers. reg_name: %s\n",
                                reg_name);
        }
      }
      general_regs_str.replace(general_regs_offsets[reg_index] + (16 - tmp_str_len), tmp_str_len,
                               tmp_str.str());
    }
  }

  std::cout << general_regs_str << " " << vector_regs_str.str() << std::endl;

  va_end(args);
}

// temp patch for correct stdout behavior
extern "C" void temp_patch_f_flags(RuntimeManager *runtime_manager, uint64_t f_flags_vma) {
  uint64_t *pma = (uint64_t *) runtime_manager->TranslateVMA(f_flags_vma);
  *pma = 0xfbad2a84;
  return;
}

inline bool __remill_flag_computation_sign(bool result, ...) {
  return result;
}
inline bool __remill_flag_computation_zero(bool result, ...) {
  return result;
}
inline bool __remill_flag_computation_overflow(bool result, ...) {
  return result;
}
inline bool __remill_flag_computation_carry(bool result, ...) {
  return result;
}

inline bool __remill_compare_sle(bool result) {
  return result;
}
inline bool __remill_compare_slt(bool result) {
  return result;
}
inline bool __remill_compare_sge(bool result) {
  return result;
}
inline bool __remill_compare_sgt(bool result) {
  return result;
}
inline bool __remill_compare_ule(bool result) {
  return result;
}
inline bool __remill_compare_ult(bool result) {
  return result;
}
inline bool __remill_compare_ugt(bool result) {
  return result;
}
inline bool __remill_compare_uge(bool result) {
  return result;
}
inline bool __remill_compare_eq(bool result) {
  return result;
}
inline bool __remill_compare_neq(bool result) {
  return result;
}

/* Data Memory Barrier instruction (FIXME) */
void __remill_barrier_load_load(RuntimeManager *runtime_manager) {}
void __remill_barrier_load_store(RuntimeManager *runtime_manager) {}
void __remill_barrier_store_load(RuntimeManager *runtime_manager) {}
void __remill_barrier_store_store(RuntimeManager *runtime_manager) {}

/* atomic */
void __remill_atomic_begin(RuntimeManager *runtime_manager) {}
void __remill_atomic_end(RuntimeManager *runtime_manager) {}

/* FIXME */
void __remill_aarch64_emulate_instruction(RuntimeManager *runtime_manager) {}

int __remill_fpu_exception_test_and_clear(int read_mask, int clear_mask) {
  return clear_mask;
}

// Memory *__remill_read_memory_f80(Memory *, addr_t, native_float80_t &) {
//   UNDEFINED_INTRINSICS("__remill_read_memory_f80");
//   return nullptr;
// }
// Memory *__remill_write_memory_f80(Memory *, addr_t, const native_float80_t &) {
//   UNDEFINED_INTRINSICS("__remill_") return nullptr;
// }

float128_t __remill_read_memory_f128(RuntimeManager *runtime_manager, addr_t addr) {
  UNDEFINED_INTRINSICS("__remill_read_memory_f128");
}

uint8_t __remill_undefined_8(void) {
  return 0;
}
uint16_t __remill_undefined_16(void) {
  UNDEFINED_INTRINSICS("__remill_undefined_16");
  return 0;
}
uint32_t __remill_undefined_32(void) {
  UNDEFINED_INTRINSICS("__remill_undefined_32");
  return 0;
}
uint64_t __remill_undefined_64(void) {
  UNDEFINED_INTRINSICS("__remill_undefied_64");
  return 0;
}
float32_t __remill_undefined_f32(void) {
  UNDEFINED_INTRINSICS("__remill_undefined_f32");
  return 0;
}
float64_t __remill_undefined_f64(void) {
  UNDEFINED_INTRINSICS("__remill_undefined_f64");
  return 0;
}
// float80_t __remill_undefined_f80(void) {
//   UNDEFINED_INTRINSICS("__remill_undefined_f80");
//   return 0;
// }
float128_t __remill_undefined_f128(void) {
  UNDEFINED_INTRINSICS("__remill_undefined_f128");
  return 0;
}

Memory *__remill_delay_slot_begin(Memory *) {
  UNDEFINED_INTRINSICS("__remill_delay_slot_begin");
  return 0;
}
Memory *__remill_delay_slot_end(Memory *) {
  UNDEFINED_INTRINSICS("__remill_delay_slot_end");
  return 0;
}
Memory *__remill_compare_exchange_memory_8(Memory *, addr_t addr, uint8_t &expected,
                                           uint8_t desired) {
  UNDEFINED_INTRINSICS("__remill_compare_exchange_memory_8");
  return 0;
}
Memory *__remill_compare_exchange_memory_16(Memory *, addr_t addr, uint16_t &expected,
                                            uint16_t desired) {
  UNDEFINED_INTRINSICS("__remill_compare_exchange_memory_16");
  return 0;
}
Memory *__remill_compare_exchange_memory_32(Memory *, addr_t addr, uint32_t &expected,
                                            uint32_t desired) {
  UNDEFINED_INTRINSICS("__remill_compare_exchange_memory_32");
  return 0;
}
Memory *__remill_compare_exchange_memory_64(Memory *, addr_t addr, uint64_t &expected,
                                            uint64_t desired) {
  UNDEFINED_INTRINSICS("__remill_compare_exchange_memory_64");
  return 0;
}
#if !defined(REMILL_DISABLE_INT128)
Memory *__remill_compare_exchange_memory_128(Memory *, addr_t addr, uint128_t &expected,
                                             uint128_t &desired) {
  UNDEFINED_INTRINSICS("__remill_compare_exchange_memory_128");
  return 0;
}
#endif
Memory *__remill_fetch_and_add_8(Memory *, addr_t addr, uint8_t &value) {
  UNDEFINED_INTRINSICS("__remill_fetch_and_add_8");
  return 0;
}
Memory *__remill_fetch_and_add_16(Memory *, addr_t addr, uint16_t &value) {
  UNDEFINED_INTRINSICS("__remill_fetch_and_add_16");
  return 0;
}
Memory *__remill_fetch_and_add_32(Memory *, addr_t addr, uint32_t &value) {
  UNDEFINED_INTRINSICS("__remill_fetch_and_add_32");
  return 0;
}
Memory *__remill_fetch_and_add_64(Memory *, addr_t addr, uint64_t &value) {
  UNDEFINED_INTRINSICS("__remill_fetch_and_add_64");
  return 0;
}
Memory *__remill_fetch_and_sub_8(Memory *, addr_t addr, uint8_t &value) {
  UNDEFINED_INTRINSICS("__remill_fetch_and_sub_8");
  return 0;
}
Memory *__remill_fetch_and_sub_16(Memory *, addr_t addr, uint16_t &value) {
  UNDEFINED_INTRINSICS("__remill_fetch_and_sub_16");
  return 0;
}
Memory *__remill_fetch_and_sub_32(Memory *, addr_t addr, uint32_t &value) {
  UNDEFINED_INTRINSICS("__remill_fetch_and_sub_32");
  return 0;
}
Memory *__remill_fetch_and_sub_64(Memory *, addr_t addr, uint64_t &value) {
  UNDEFINED_INTRINSICS("__remill_fetch_and_sub_64");
  return 0;
}
Memory *__remill_fetch_and_and_8(Memory *, addr_t addr, uint8_t &value) {
  UNDEFINED_INTRINSICS("__remill_fetch_and_and_8");
  return 0;
}
Memory *__remill_fetch_and_and_16(Memory *, addr_t addr, uint16_t &value) {
  UNDEFINED_INTRINSICS("__remill_fetch_and_and_16");
  return 0;
}
Memory *__remill_fetch_and_and_32(Memory *, addr_t addr, uint32_t &value) {
  UNDEFINED_INTRINSICS("__remill_fetch_and_and_32");
  return 0;
}
Memory *__remill_fetch_and_and_64(Memory *, addr_t addr, uint64_t &value) {
  UNDEFINED_INTRINSICS("__remill_fetch_and_and_64");
  return 0;
}
Memory *__remill_fetch_and_or_8(Memory *, addr_t addr, uint8_t &value) {
  UNDEFINED_INTRINSICS("__remill_fetch_and_or_8");
  return 0;
}
Memory *__remill_fetch_and_or_16(Memory *, addr_t addr, uint16_t &value) {
  UNDEFINED_INTRINSICS("__remill_fetch_and_or_16");
  return 0;
}
Memory *__remill_fetch_and_or_32(Memory *, addr_t addr, uint32_t &value) {
  UNDEFINED_INTRINSICS("__remill_fetch_and_or_32");
  return 0;
}
Memory *__remill_fetch_and_or_64(Memory *, addr_t addr, uint64_t &value) {
  UNDEFINED_INTRINSICS("__remill_fetch_and_or_64");
  return 0;
}
Memory *__remill_fetch_and_xor_8(Memory *, addr_t addr, uint8_t &value) {
  UNDEFINED_INTRINSICS("__remill_fetch_and_xor_8");
  return 0;
}
Memory *__remill_fetch_and_xor_16(Memory *, addr_t addr, uint16_t &value) {
  UNDEFINED_INTRINSICS("__remill_fetch_and_xor_16");
  return 0;
}
Memory *__remill_fetch_and_xor_32(Memory *, addr_t addr, uint32_t &value) {
  UNDEFINED_INTRINSICS("__remill_fetch_and_xor_32");
  return 0;
}
Memory *__remill_fetch_and_xor_64(Memory *, addr_t addr, uint64_t &value) {
  UNDEFINED_INTRINSICS("__remill_fetch_and_xor_64");
  return 0;
}
Memory *__remill_fetch_and_nand_8(Memory *, addr_t addr, uint8_t &value) {
  UNDEFINED_INTRINSICS("__remill_fetch_and_nand_8");
  return 0;
}
Memory *__remill_fetch_and_nand_16(Memory *, addr_t addr, uint16_t &value) {
  UNDEFINED_INTRINSICS("__remill_fetch_and_nand_16");
  return 0;
}
Memory *__remill_fetch_and_nand_32(Memory *, addr_t addr, uint32_t &value) {
  UNDEFINED_INTRINSICS("__remill_fetch_and_nand_32");
  return 0;
}
Memory *__remill_fetch_and_nand_64(Memory *, addr_t addr, uint64_t &value) {
  UNDEFINED_INTRINSICS("__remill_fetch_and_nand_64");
  return 0;
}

uint8_t __remill_read_io_port_8(Memory *, addr_t) {
  UNDEFINED_INTRINSICS("__remill_read_io_port_8");
  return 0;
}
uint16_t __remill_read_io_port_16(Memory *, addr_t) {
  UNDEFINED_INTRINSICS("__remill_read_io_port_16");
  return 0;
}
uint32_t __remill_read_io_port_32(Memory *, addr_t) {
  UNDEFINED_INTRINSICS("__remill_read_io_port_32");
  return 0;
}
Memory *__remill_write_io_port_8(Memory *, addr_t, uint8_t) {
  UNDEFINED_INTRINSICS("__remill_write_io_port_8");
  return 0;
}
Memory *__remill_write_io_port_16(Memory *, addr_t, uint16_t) {
  UNDEFINED_INTRINSICS("__remill_write_io_port_16");
  return 0;
}
Memory *__remill_write_io_port_32(Memory *, addr_t, uint32_t) {
  UNDEFINED_INTRINSICS("__remill_write_io_port_32");
  return 0;
}
Memory *__remill_x86_set_segment_es(Memory *) {
  UNDEFINED_INTRINSICS("__remill_x86_set_segment_es");
  return 0;
}
Memory *__remill_x86_set_segment_ss(Memory *) {
  UNDEFINED_INTRINSICS("__remill_x86_set_segment_ss");
  return 0;
}
Memory *__remill_x86_set_segment_ds(Memory *) {
  UNDEFINED_INTRINSICS("__remill_x86_set_segment_ds");
  return 0;
}
Memory *__remill_x86_set_segment_fs(Memory *) {
  UNDEFINED_INTRINSICS("__remill_x86_set_segment_fs");
  return 0;
}
Memory *__remill_x86_set_segment_gs(Memory *) {
  UNDEFINED_INTRINSICS("__remill_x86_set_segment_gs");
  return 0;
}
Memory *__remill_x86_set_debug_reg(Memory *) {
  UNDEFINED_INTRINSICS("__remill_x86_set_debug_reg");
  return 0;
}
Memory *__remill_x86_set_control_reg_0(Memory *) {
  UNDEFINED_INTRINSICS("__remill_x86_set_control_reg_0");
  return 0;
}
Memory *__remill_x86_set_control_reg_1(Memory *) {
  UNDEFINED_INTRINSICS("__remill_x86_set_control_reg_1");
  return 0;
}
Memory *__remill_x86_set_control_reg_2(Memory *) {
  UNDEFINED_INTRINSICS("__remill_x86_set_control_reg_2");
  return 0;
}
Memory *__remill_x86_set_control_reg_3(Memory *) {
  UNDEFINED_INTRINSICS("__remill_x86_set_control_reg_3");
  return 0;
}
Memory *__remill_x86_set_control_reg_4(Memory *) {
  UNDEFINED_INTRINSICS("__remill_x86_set_control_reg_4");
  return 0;
}
Memory *__remill_amd64_set_debug_reg(Memory *) {
  UNDEFINED_INTRINSICS("__remill_amd64_set_debug_reg");
  return 0;
}
Memory *__remill_amd64_set_control_reg_0(Memory *) {
  UNDEFINED_INTRINSICS("__remill_amd64_set_control_reg_0");
  return 0;
}
Memory *__remill_amd64_set_control_reg_1(Memory *) {
  UNDEFINED_INTRINSICS("__remill_amd64_set_control_reg_1");
  return 0;
}
Memory *__remill_amd64_set_control_reg_2(Memory *) {
  UNDEFINED_INTRINSICS("__remill_amd64_set_control_reg_2");
  return 0;
}
Memory *__remill_amd64_set_control_reg_3(Memory *) {
  UNDEFINED_INTRINSICS("__remill_amd64_set_control_reg_3");
  return 0;
}
Memory *__remill_amd64_set_control_reg_4(Memory *) {
  UNDEFINED_INTRINSICS("__remill_amd64_set_control_reg_4");
  return 0;
}
Memory *__remill_amd64_set_control_reg_8(Memory *) {
  UNDEFINED_INTRINSICS("__remill_amd64_set_control_reg_8");
  return 0;
}

Memory *__remill_aarch32_emulate_instruction(Memory *) {
  UNDEFINED_INTRINSICS("__remill_aarch32_emulate_instruction");
  return 0;
}
Memory *__remill_aarch32_check_not_el2(Memory *) {
  UNDEFINED_INTRINSICS("__remill_aarch32_check_not_el2");
  return 0;
}
Memory *__remill_sparc_set_asi_register(Memory *) {
  UNDEFINED_INTRINSICS("__remill_sparc_set_asi_register");
  return 0;
}
Memory *__remill_sparc_unimplemented_instruction(Memory *) {
  UNDEFINED_INTRINSICS("__remill_sparc_unimplemented_instruction");
  return 0;
}
Memory *__remill_sparc_unhandled_dcti(Memory *) {
  UNDEFINED_INTRINSICS("__remill_sparc_unhandled_dcti");
  return 0;
}
Memory *__remill_sparc_window_underflow(Memory *) {
  UNDEFINED_INTRINSICS("__remill_sparc_window_underflow");
  return 0;
}
Memory *__remill_sparc_trap_cond_a(Memory *) {
  UNDEFINED_INTRINSICS("__remill_sparc_trap_cond_a");
  return 0;
}
Memory *__remill_sparc_trap_cond_n(Memory *) {
  UNDEFINED_INTRINSICS("__remill_sparc_trap_cond_n");
  return 0;
}
Memory *__remill_sparc_trap_cond_ne(Memory *) {
  UNDEFINED_INTRINSICS("__remill_sparc_trap_cond_ne");
  return 0;
}
Memory *__remill_sparc_trap_cond_e(Memory *) {
  UNDEFINED_INTRINSICS("__remill_sparc_trap_cond_e");
  return 0;
}
Memory *__remill_sparc_trap_cond_g(Memory *) {
  UNDEFINED_INTRINSICS("__remill_sparc_trap_cond_g");
  return 0;
}
Memory *__remill_sparc_trap_cond_le(Memory *) {
  UNDEFINED_INTRINSICS("__remill_sparc_trap_cond_le");
  return 0;
}
Memory *__remill_sparc_trap_cond_ge(Memory *) {
  UNDEFINED_INTRINSICS("__remill_sparc_trap_cond_ge");
  return 0;
}
Memory *__remill_sparc_trap_cond_l(Memory *) {
  UNDEFINED_INTRINSICS("__remill_sparc_trap_cond_l");
  return 0;
}
Memory *__remill_sparc_trap_cond_gu(Memory *) {
  UNDEFINED_INTRINSICS("__remill_sparc_trap_cond_gu");
  return 0;
}
Memory *__remill_sparc_trap_cond_leu(Memory *) {
  UNDEFINED_INTRINSICS("__remill_sparc_trap_cond_leu");
  return 0;
}
Memory *__remill_sparc_trap_cond_cc(Memory *) {
  UNDEFINED_INTRINSICS("__remill_sparc_trap_cond_cc");
  return 0;
}
Memory *__remill_sparc_trap_cond_cs(Memory *) {
  UNDEFINED_INTRINSICS("__remill_sparc_trap_cond_cs");
  return 0;
}
Memory *__remill_sparc_trap_cond_pos(Memory *) {
  UNDEFINED_INTRINSICS("__remill_sparc_trap_cond_pos");
  return 0;
}
Memory *__remill_sparc_trap_cond_neg(Memory *) {
  UNDEFINED_INTRINSICS("__remill_sparc_trap_cond_neg");
  return 0;
}
Memory *__remill_sparc_trap_cond_vc(Memory *) {
  UNDEFINED_INTRINSICS("__remill_sparc_trap_cond_vc");
  return 0;
}
Memory *__remill_sparc_trap_cond_vs(Memory *) {
  UNDEFINED_INTRINSICS("__remill_sparc_trap_cond_vs");
  return 0;
}
Memory *__remill_sparc32_emulate_instruction(Memory *) {
  UNDEFINED_INTRINSICS("__remill_sparc32_emulate_instruction");
  return 0;
}
Memory *__remill_sparc64_emulate_instruction(Memory *) {
  UNDEFINED_INTRINSICS("__remill_sparc64_emulate_instruction");
  return 0;
}
Memory *__remill_ppc_emulate_instruction(Memory *) {
  UNDEFINED_INTRINSICS("__remill_ppc_emulate_instruction");
  return 0;
}
Memory *__remill_ppc_syscall(Memory *) {
  UNDEFINED_INTRINSICS("__remill_ppc_syscall");
  return 0;
}
