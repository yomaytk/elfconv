#include "Runtime.h"

#include <cstdarg>
#include <iomanip>
#include <iostream>
#include <remill/Arch/AArch64/Runtime/State.h>
#include <remill/Arch/Runtime/Intrinsics.h>
#include <remill/BC/HelperMacro.h>
#include <utils/Util.h>
#include <utils/elfconv.h>

#define UNDEFINED_INTRINSICS(intrinsics) \
  printf("[ERROR] undefined intrinsics: %s\n", intrinsics); \
  debug_state_machine(); \
  fflush(stdout); \
  abort();

uint8_t __remill_read_memory_8(RuntimeManager *runtime_manager, addr_t addr) {
  return *(uint8_t *) runtime_manager->TranslateVMA(addr);
}

uint16_t __remill_read_memory_16(RuntimeManager *runtime_manager, addr_t addr) {
  return *(uint16_t *) runtime_manager->TranslateVMA(addr);
}

uint32_t __remill_read_memory_32(RuntimeManager *runtime_manager, addr_t addr) {
  return *(uint32_t *) runtime_manager->TranslateVMA(addr);
}

uint64_t __remill_read_memory_64(RuntimeManager *runtime_manager, addr_t addr) {
  return *(uint64_t *) runtime_manager->TranslateVMA(addr);
}

float32_t __remill_read_memory_f32(RuntimeManager *runtime_manager, addr_t addr) {
  return *(float32_t *) runtime_manager->TranslateVMA(addr);
}

float64_t __remill_read_memory_f64(RuntimeManager *runtime_manager, addr_t addr) {
  return *(float64_t *) runtime_manager->TranslateVMA(addr);
}

float128_t __remill_read_memory_f128(RuntimeManager *runtime_manager, addr_t addr) {
  return *(float128_t *) runtime_manager->TranslateVMA(addr);
}

void __remill_write_memory_8(RuntimeManager *runtime_manager, addr_t addr, uint8_t src) {
  auto dst = (uint8_t *) runtime_manager->TranslateVMA(addr);
  *dst = src;
}

void __remill_write_memory_16(RuntimeManager *runtime_manager, addr_t addr, uint16_t src) {
  auto dst = (uint16_t *) runtime_manager->TranslateVMA(addr);
  *dst = src;
}

void __remill_write_memory_32(RuntimeManager *runtime_manager, addr_t addr, uint32_t src) {
  auto dst = (uint32_t *) runtime_manager->TranslateVMA(addr);
  *dst = src;
}

void __remill_write_memory_64(RuntimeManager *runtime_manager, addr_t addr, uint64_t src) {
  auto dst = (uint64_t *) runtime_manager->TranslateVMA(addr);
  *dst = src;
}

void __remill_write_memory_f32(RuntimeManager *runtime_manager, addr_t addr, float32_t src) {
  auto dst = (float32_t *) runtime_manager->TranslateVMA(addr);
  *dst = src;
}

void __remill_write_memory_f64(RuntimeManager *runtime_manager, addr_t addr, float64_t src) {
  auto dst = (float64_t *) runtime_manager->TranslateVMA(addr);
  *dst = src;
}

void __remill_write_memory_f128(RuntimeManager *, addr_t, float128_t) {}

/*
  tranpoline call for emulating syscall of original ELF binary.
*/
void __remill_syscall_tranpoline_call(State &state, RuntimeManager *runtime_manager) {
  /* TODO: We should select one syscall emulate process (own implementation, WASI, LKL, etc...) */
#if defined(ELFC_WASI_ENV)
  runtime_manager->SVCWasiCall();
#elif defined(ELFC_BROWSER_ENV)
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
            << "[WARNING] reached \"__remill_missing_block\", PC: 0x" << g_state.gpr.pc.qword
            << std::endl;
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
void __remill_function_call(State &state, addr_t fn_vma, RuntimeManager *runtime_manager) {
  if (auto jmp_fn = runtime_manager->addr_fn_map[fn_vma]; jmp_fn) {
    // std::cout << "indirect: " << runtime_manager->addr_fn_symbol_map[fn_vma] << std::endl;
    jmp_fn(&state, fn_vma, runtime_manager);
  } else {
    elfconv_runtime_error(
        "[ERROR] vma 0x%016llx is not included in the lifted function pointer table (BLR). PC: "
        "0x%08x\n",
        fn_vma, state.gpr.pc.dword);
  }
}

/* BR instruction */
void __remill_jump(State &state, addr_t fn_vma, RuntimeManager *runtime_manager) {
  if (auto jmp_fn = runtime_manager->addr_fn_map[fn_vma]; jmp_fn) {
    jmp_fn(&state, fn_vma, runtime_manager);
  } else {
    elfconv_runtime_error(
        "[ERROR] vma 0x%016llx is not included in the lifted function pointer table (BR). PC: "
        "0x%08x\n",
        fn_vma, state.gpr.pc.dword);
  }
}

// get the target basic block lable pointer for indirectbr instruction
extern "C" uint64_t *__g_get_indirectbr_block_address(RuntimeManager *runtime_manager,
                                                      uint64_t fun_vma, uint64_t bb_vma) {
  if (runtime_manager->addr_block_addrs_map.count(fun_vma) == 1) {
    auto vma_bb_map = runtime_manager->addr_block_addrs_map[fun_vma];
    if (vma_bb_map.count(bb_vma) == 1) {
      return vma_bb_map[bb_vma];
    } else {
      if (runtime_manager->addr_fn_map.count(fun_vma) == 1)
        return vma_bb_map[UINT64_MAX];
      else
        elfconv_runtime_error("[ERROR] 0x%llx is not the vma of the block address of '%s'.\n",
                              bb_vma, __func__);
    }
  } else {
    elfconv_runtime_error(
        "[ERROR] 0x%llx is not the entry address of any lifted function. (at %s)\n", fun_vma,
        __func__);
  }
}

// push the callee symbole to the call stack for debug
extern "C" void debug_call_stack_push(RuntimeManager *runtime_manager, uint64_t fn_vma) {
  if (auto func_name = runtime_manager->addr_fn_symbol_map[fn_vma]; func_name) {
    if (strncmp(func_name, "fn_plt", 6) == 0) {
      return;
    }
    runtime_manager->call_stacks.push_back(fn_vma);
    std::string tab_space;
    for (int i = 0; i < runtime_manager->call_stacks.size(); i++) {
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
    elfconv_runtime_error("invalid debug call stack empty. PC: 0x%016llx\n", g_state.gpr.pc.qword);
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
  static uint64_t target_vma = 0x499f98;
  if (0 == target_vma)
    return;
  static uint64_t old_value = 0;
  // step 2. set the data type of target value
  auto target_pma = (uint64_t *) runtime_manager->TranslateVMA(target_vma);
  auto new_value = *target_pma;
  if (old_value != new_value) {
    std::cout << std::hex << "target_vma: 0x" << target_vma << " target_pma: 0x" << target_pma
              << std::endl
              << "\told value: 0x" << old_value << std::endl
              << "\tnew value: 0x" << new_value << std::endl;
    old_value = new_value;
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

uint8_t __remill_undefined_8(void) {
  UNDEFINED_INTRINSICS("__remill_undefined_8");
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
