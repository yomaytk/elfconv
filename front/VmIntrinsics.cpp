#include <iostream>
#include <cstdarg>
#include "remill/Arch/Runtime/Intrinsics.h"
#include "remill/Arch/AArch64/Runtime/State.h"
#include "memory.h"

#define UNDEFINED_INTRINSICS(intrinsics) printf("[ERROR] undefined intrinsics: %s\n", intrinsics); \
                                          debug_state_machine(); \
                                          fflush(stdout); \
                                          abort();

uint8_t __remill_read_memory_8(Memory *, addr_t addr){
  return *getMemoryAddr<uint8_t>(addr);
}

uint16_t __remill_read_memory_16(Memory *, addr_t addr){
  return *getMemoryAddr<uint16_t>(addr);
}

uint32_t __remill_read_memory_32(Memory *, addr_t addr) {
  return *getMemoryAddr<uint32_t>(addr);
}

uint64_t __remill_read_memory_64(Memory *, addr_t addr) {
  return *getMemoryAddr<uint64_t>(addr);
}

float32_t __remill_read_memory_f32(Memory *, addr_t addr){
  return *getMemoryAddr<float32_t>(addr);
}

float64_t __remill_read_memory_f64(Memory *, addr_t addr){
  return *getMemoryAddr<float64_t>(addr);
}

float128_t __remill_read_memory_f128(Memory *, addr_t addr){
  return *getMemoryAddr<float128_t>(addr);
}

Memory * __remill_write_memory_8(Memory *memory, addr_t addr, uint8_t src){
  auto dst = getMemoryAddr<uint8_t>(addr);
  *dst = src;
  return memory;
}

Memory * __remill_write_memory_16(Memory *memory, addr_t addr, uint16_t src){
  auto dst = getMemoryAddr<uint16_t>(addr);
  *dst = src;
  return memory;
}

Memory *__remill_write_memory_32(Memory *memory, addr_t addr, uint32_t src) {
  auto dst = getMemoryAddr<uint32_t>(addr);
  *dst = src;
  return memory;
}

Memory *__remill_write_memory_64(Memory *memory, addr_t addr, uint64_t src) {
  auto dst = getMemoryAddr<uint64_t>(addr);
  *dst = src;
  return memory;
}

Memory * __remill_write_memory_f32(Memory *memory, addr_t addr, float32_t src){
  auto dst = getMemoryAddr<float32_t>(addr);
  *dst = src;
  return memory;
}

Memory * __remill_write_memory_f64(Memory *memory, addr_t addr, float64_t src){
  auto dst = getMemoryAddr<float64_t>(addr);
  *dst = src;
  return memory;
}

Memory *__remill_write_memory_f128(Memory *, addr_t, float128_t){ return nullptr; }

/*
  tranpoline call for emulating syscall of original ELF binary.
*/
Memory *__remill_syscall_tranpoline_call(State &state, Memory *memory) {
  /* TODO: We should select one syscall emulate process (own implementation, WASI, LKL, etc...) */
  __svc_call();
  return memory;
}

/* 
  Marks `mem` as being used. This is used for making sure certain symbols are
  kept around through optimization, and makes sure that optimization doesn't
  perform dead-argument elimination on any of the intrinsics. 
*/
extern "C" void __remill_mark_as_used(void *mem) {
  asm("" ::"m"(mem));
}

Memory *__remill_function_return(State &, addr_t, Memory *memory) {
  return memory;
}

Memory *__remill_missing_block(State &, addr_t, Memory *memory) {
  printf("[WARNING] reached \"__remill_missing_block\", PC: 0x%016llx\n", g_state.gpr.pc.qword);
  return memory;
}

Memory *__remill_async_hyper_call(State &, addr_t ret_addr, Memory *memory){ 
  return memory; 
}

/* panic function for jumping to .plt section (FIXME) */
Memory *__remill_panic_plt_jmp(State &, addr_t, Memory *) {
  printf("[ERROR] detect jumping to .plt section\n");
  fflush(stdout);
  abort();
}

Memory * __remill_error(State &, addr_t addr, Memory *){
  printf("[WARNING] Reached __remill_error.\n");
  debug_state_machine();
  fflush(stdout);
  abort();
}

/*
  BLR instuction
  The remill semantic sets X30 link register, so this only jumps to target function.
*/
Memory * __remill_function_call(State &state, addr_t fn_vma, Memory *memory){ 
  if (auto jmp_fn = g_run_mgr->addr_fn_map[fn_vma]; jmp_fn) {
    jmp_fn(&state, fn_vma, memory);
  } else {
    printf("[ERROR] vma 0x%016llx is not included in the lifted function pointer table.\n", fn_vma);
    abort();
  }
  return memory;
}

/* BL instruction */
Memory * __remill_jump(State &state, addr_t fn_vma, Memory *memory){
  if (auto jmp_fn = g_run_mgr->addr_fn_map[fn_vma]; jmp_fn) {
    jmp_fn(&state, fn_vma, memory);
  } else {
    printf("[ERROR] vma 0x%016llx is not included in the lifted function pointer table.\n", fn_vma);
    abort();
  }
  return memory;
}

bool __remill_flag_computation_sign(bool result, ...){ return result; }
bool __remill_flag_computation_zero(bool result, ...){ return result; }
bool __remill_flag_computation_overflow(bool result, ...){ return result; }
bool __remill_flag_computation_carry(bool result, ...){ return result; }

bool __remill_compare_sle(bool result){ return result; }
bool __remill_compare_slt(bool result){ return result; }
bool __remill_compare_sge(bool result){ return result; }
bool __remill_compare_sgt(bool result){ return result; }
bool __remill_compare_ule(bool result){ return result; }
bool __remill_compare_ult(bool result){ return result; }
bool __remill_compare_ugt(bool result){ return result; }
bool __remill_compare_uge(bool result){ return result; }
bool __remill_compare_eq(bool result){ return result; }
bool __remill_compare_neq(bool result){ return result; }

/* Data Memory Barrier instruction (FIXME) */
Memory * __remill_barrier_load_load(Memory *memory){ return memory; }
Memory * __remill_barrier_load_store(Memory *memory){ return memory; }
Memory * __remill_barrier_store_load(Memory *memory){ return memory; }
Memory * __remill_barrier_store_store(Memory *memory){ return memory; }

/* atomic */
Memory * __remill_atomic_begin(Memory *memory) { return memory; }
Memory *__remill_atomic_end(Memory *memory){ return memory; }

/* FIXME */
Memory *__remill_aarch64_emulate_instruction(Memory *memory){ return memory; }

Memory *__remill_read_memory_f80(Memory *, addr_t, native_float80_t &){ UNDEFINED_INTRINSICS("__remill_read_memory_f80"); return nullptr; }
Memory * __remill_write_memory_f80(Memory *, addr_t, const native_float80_t &){ UNDEFINED_INTRINSICS("__remill_") return nullptr; }

uint8_t __remill_undefined_8(void){ UNDEFINED_INTRINSICS("__remill_undefined_8"); return 0; }
uint16_t __remill_undefined_16(void){ UNDEFINED_INTRINSICS("__remill_undefined_16"); return 0; }
uint32_t __remill_undefined_32(void){ UNDEFINED_INTRINSICS("__remill_undefined_32"); return 0; }
uint64_t __remill_undefined_64(void){ UNDEFINED_INTRINSICS("__remill_undefied_64"); return 0; }
float32_t __remill_undefined_f32(void){ UNDEFINED_INTRINSICS("__remill_undefined_f32"); return 0; }
float64_t __remill_undefined_f64(void){ UNDEFINED_INTRINSICS("__remill_undefined_f64"); return 0; }
float80_t __remill_undefined_f80(void){ UNDEFINED_INTRINSICS("__remill_undefined_f80"); return 0; }
float128_t __remill_undefined_f128(void){ UNDEFINED_INTRINSICS("__remill_undefined_f128"); return 0; }

Memory *__remill_delay_slot_begin(Memory *){ UNDEFINED_INTRINSICS("__remill_delay_slot_begin"); return 0; }
Memory *__remill_delay_slot_end(Memory *){ UNDEFINED_INTRINSICS("__remill_delay_slot_end"); return 0; }
Memory *__remill_compare_exchange_memory_8(Memory *, addr_t addr, uint8_t &expected, uint8_t desired){ UNDEFINED_INTRINSICS("__remill_compare_exchange_memory_8"); return 0; }
Memory *__remill_compare_exchange_memory_16(Memory *, addr_t addr, uint16_t &expected, uint16_t desired){ UNDEFINED_INTRINSICS("__remill_compare_exchange_memory_16"); return 0; }
Memory *__remill_compare_exchange_memory_32(Memory *, addr_t addr, uint32_t &expected, uint32_t desired){ UNDEFINED_INTRINSICS("__remill_compare_exchange_memory_32"); return 0; }
Memory *__remill_compare_exchange_memory_64(Memory *, addr_t addr, uint64_t &expected,uint64_t desired){ UNDEFINED_INTRINSICS("__remill_compare_exchange_memory_64"); return 0; }
#if !defined(REMILL_DISABLE_INT128)
Memory *__remill_compare_exchange_memory_128(Memory *, addr_t addr, uint128_t &expected, uint128_t &desired){ UNDEFINED_INTRINSICS("__remill_compare_exchange_memory_128"); return 0; }
#endif
Memory *__remill_fetch_and_add_8(Memory *, addr_t addr, uint8_t &value){ UNDEFINED_INTRINSICS("__remill_fetch_and_add_8"); return 0; }
Memory *__remill_fetch_and_add_16(Memory *, addr_t addr, uint16_t &value){ UNDEFINED_INTRINSICS("__remill_fetch_and_add_16"); return 0; }
Memory *__remill_fetch_and_add_32(Memory *, addr_t addr, uint32_t &value){ UNDEFINED_INTRINSICS("__remill_fetch_and_add_32"); return 0; }
Memory *__remill_fetch_and_add_64(Memory *, addr_t addr, uint64_t &value){ UNDEFINED_INTRINSICS("__remill_fetch_and_add_64"); return 0; }
Memory *__remill_fetch_and_sub_8(Memory *, addr_t addr, uint8_t &value){ UNDEFINED_INTRINSICS("__remill_fetch_and_sub_8"); return 0; }
Memory *__remill_fetch_and_sub_16(Memory *, addr_t addr, uint16_t &value){ UNDEFINED_INTRINSICS("__remill_fetch_and_sub_16"); return 0; }
Memory *__remill_fetch_and_sub_32(Memory *, addr_t addr, uint32_t &value){ UNDEFINED_INTRINSICS("__remill_fetch_and_sub_32"); return 0; }
Memory *__remill_fetch_and_sub_64(Memory *, addr_t addr, uint64_t &value){ UNDEFINED_INTRINSICS("__remill_fetch_and_sub_64"); return 0; }
Memory *__remill_fetch_and_and_8(Memory *, addr_t addr, uint8_t &value){ UNDEFINED_INTRINSICS("__remill_fetch_and_and_8"); return 0; }
Memory *__remill_fetch_and_and_16(Memory *, addr_t addr, uint16_t &value){ UNDEFINED_INTRINSICS("__remill_fetch_and_and_16"); return 0; }
Memory *__remill_fetch_and_and_32(Memory *, addr_t addr, uint32_t &value){ UNDEFINED_INTRINSICS("__remill_fetch_and_and_32"); return 0; }
Memory *__remill_fetch_and_and_64(Memory *, addr_t addr, uint64_t &value){ UNDEFINED_INTRINSICS("__remill_fetch_and_and_64"); return 0; }
Memory *__remill_fetch_and_or_8(Memory *, addr_t addr, uint8_t &value){ UNDEFINED_INTRINSICS("__remill_fetch_and_or_8"); return 0; }
Memory *__remill_fetch_and_or_16(Memory *, addr_t addr, uint16_t &value){ UNDEFINED_INTRINSICS("__remill_fetch_and_or_16"); return 0; }
Memory *__remill_fetch_and_or_32(Memory *, addr_t addr, uint32_t &value){ UNDEFINED_INTRINSICS("__remill_fetch_and_or_32"); return 0; }
Memory *__remill_fetch_and_or_64(Memory *, addr_t addr, uint64_t &value){ UNDEFINED_INTRINSICS("__remill_fetch_and_or_64"); return 0; }
Memory *__remill_fetch_and_xor_8(Memory *, addr_t addr, uint8_t &value){ UNDEFINED_INTRINSICS("__remill_fetch_and_xor_8"); return 0; }
Memory *__remill_fetch_and_xor_16(Memory *, addr_t addr, uint16_t &value){ UNDEFINED_INTRINSICS("__remill_fetch_and_xor_16"); return 0; }
Memory *__remill_fetch_and_xor_32(Memory *, addr_t addr, uint32_t &value){ UNDEFINED_INTRINSICS("__remill_fetch_and_xor_32"); return 0; }
Memory *__remill_fetch_and_xor_64(Memory *, addr_t addr, uint64_t &value){ UNDEFINED_INTRINSICS("__remill_fetch_and_xor_64"); return 0; }
Memory *__remill_fetch_and_nand_8(Memory *, addr_t addr, uint8_t &value){ UNDEFINED_INTRINSICS("__remill_fetch_and_nand_8"); return 0; }
Memory *__remill_fetch_and_nand_16(Memory *, addr_t addr, uint16_t &value){ UNDEFINED_INTRINSICS("__remill_fetch_and_nand_16"); return 0; }
Memory *__remill_fetch_and_nand_32(Memory *, addr_t addr, uint32_t &value){ UNDEFINED_INTRINSICS("__remill_fetch_and_nand_32"); return 0; }
Memory *__remill_fetch_and_nand_64(Memory *, addr_t addr, uint64_t &value){ UNDEFINED_INTRINSICS("__remill_fetch_and_nand_64"); return 0; }
int __remill_fpu_exception_test_and_clear(int read_mask, int clear_mask){ UNDEFINED_INTRINSICS("__remill_fpu_exception_test_and_clear"); return 0; }
uint8_t __remill_read_io_port_8(Memory *, addr_t){ UNDEFINED_INTRINSICS("__remill_read_io_port_8"); return 0; }
uint16_t __remill_read_io_port_16(Memory *, addr_t){ UNDEFINED_INTRINSICS("__remill_read_io_port_16"); return 0; }
uint32_t __remill_read_io_port_32(Memory *, addr_t){ UNDEFINED_INTRINSICS("__remill_read_io_port_32"); return 0; }
Memory *__remill_write_io_port_8(Memory *, addr_t, uint8_t){ UNDEFINED_INTRINSICS("__remill_write_io_port_8"); return 0; }
Memory *__remill_write_io_port_16(Memory *, addr_t, uint16_t){ UNDEFINED_INTRINSICS("__remill_write_io_port_16"); return 0; }
Memory *__remill_write_io_port_32(Memory *, addr_t, uint32_t){ UNDEFINED_INTRINSICS("__remill_write_io_port_32"); return 0; }
Memory *__remill_x86_set_segment_es(Memory *){ UNDEFINED_INTRINSICS("__remill_x86_set_segment_es"); return 0; }
Memory *__remill_x86_set_segment_ss(Memory *){ UNDEFINED_INTRINSICS("__remill_x86_set_segment_ss"); return 0; }
Memory *__remill_x86_set_segment_ds(Memory *){ UNDEFINED_INTRINSICS("__remill_x86_set_segment_ds"); return 0; }
Memory *__remill_x86_set_segment_fs(Memory *){ UNDEFINED_INTRINSICS("__remill_x86_set_segment_fs"); return 0; }
Memory *__remill_x86_set_segment_gs(Memory *){ UNDEFINED_INTRINSICS("__remill_x86_set_segment_gs"); return 0; }
Memory *__remill_x86_set_debug_reg(Memory *){ UNDEFINED_INTRINSICS("__remill_x86_set_debug_reg"); return 0; }
Memory *__remill_x86_set_control_reg_0(Memory *){ UNDEFINED_INTRINSICS("__remill_x86_set_control_reg_0"); return 0; }
Memory *__remill_x86_set_control_reg_1(Memory *){ UNDEFINED_INTRINSICS("__remill_x86_set_control_reg_1"); return 0; }
Memory *__remill_x86_set_control_reg_2(Memory *){ UNDEFINED_INTRINSICS("__remill_x86_set_control_reg_2"); return 0; }
Memory *__remill_x86_set_control_reg_3(Memory *){ UNDEFINED_INTRINSICS("__remill_x86_set_control_reg_3"); return 0; }
Memory *__remill_x86_set_control_reg_4(Memory *){ UNDEFINED_INTRINSICS("__remill_x86_set_control_reg_4"); return 0; }
Memory *__remill_amd64_set_debug_reg(Memory *){ UNDEFINED_INTRINSICS("__remill_amd64_set_debug_reg"); return 0; }
Memory *__remill_amd64_set_control_reg_0(Memory *){ UNDEFINED_INTRINSICS("__remill_amd64_set_control_reg_0"); return 0; }
Memory *__remill_amd64_set_control_reg_1(Memory *){ UNDEFINED_INTRINSICS("__remill_amd64_set_control_reg_1"); return 0; }
Memory *__remill_amd64_set_control_reg_2(Memory *){ UNDEFINED_INTRINSICS("__remill_amd64_set_control_reg_2"); return 0; }
Memory *__remill_amd64_set_control_reg_3(Memory *){ UNDEFINED_INTRINSICS("__remill_amd64_set_control_reg_3"); return 0; }
Memory *__remill_amd64_set_control_reg_4(Memory *){ UNDEFINED_INTRINSICS("__remill_amd64_set_control_reg_4"); return 0; }
Memory *__remill_amd64_set_control_reg_8(Memory *){ UNDEFINED_INTRINSICS("__remill_amd64_set_control_reg_8"); return 0; }

Memory *__remill_aarch32_emulate_instruction(Memory *){UNDEFINED_INTRINSICS("__remill_aarch32_emulate_instruction");  return 0; }
Memory *__remill_aarch32_check_not_el2(Memory *){ UNDEFINED_INTRINSICS("__remill_aarch32_check_not_el2"); return 0; }
Memory *__remill_sparc_set_asi_register(Memory *){ UNDEFINED_INTRINSICS("__remill_sparc_set_asi_register"); return 0; }
Memory *__remill_sparc_unimplemented_instruction(Memory *){ UNDEFINED_INTRINSICS("__remill_sparc_unimplemented_instruction"); return 0; }
Memory *__remill_sparc_unhandled_dcti(Memory *){ UNDEFINED_INTRINSICS("__remill_sparc_unhandled_dcti"); return 0; }
Memory *__remill_sparc_window_underflow(Memory *){ UNDEFINED_INTRINSICS("__remill_sparc_window_underflow"); return 0; }
Memory *__remill_sparc_trap_cond_a(Memory *){ UNDEFINED_INTRINSICS("__remill_sparc_trap_cond_a"); return 0; }
Memory *__remill_sparc_trap_cond_n(Memory *){ UNDEFINED_INTRINSICS("__remill_sparc_trap_cond_n"); return 0; }
Memory *__remill_sparc_trap_cond_ne(Memory *){ UNDEFINED_INTRINSICS("__remill_sparc_trap_cond_ne"); return 0; }
Memory *__remill_sparc_trap_cond_e(Memory *){ UNDEFINED_INTRINSICS("__remill_sparc_trap_cond_e"); return 0; }
Memory *__remill_sparc_trap_cond_g(Memory *){ UNDEFINED_INTRINSICS("__remill_sparc_trap_cond_g"); return 0; }
Memory *__remill_sparc_trap_cond_le(Memory *){ UNDEFINED_INTRINSICS("__remill_sparc_trap_cond_le"); return 0; }
Memory *__remill_sparc_trap_cond_ge(Memory *){ UNDEFINED_INTRINSICS("__remill_sparc_trap_cond_ge"); return 0; }
Memory *__remill_sparc_trap_cond_l(Memory *){ UNDEFINED_INTRINSICS("__remill_sparc_trap_cond_l"); return 0; }
Memory *__remill_sparc_trap_cond_gu(Memory *){ UNDEFINED_INTRINSICS("__remill_sparc_trap_cond_gu"); return 0; }
Memory *__remill_sparc_trap_cond_leu(Memory *){ UNDEFINED_INTRINSICS("__remill_sparc_trap_cond_leu"); return 0; }
Memory *__remill_sparc_trap_cond_cc(Memory *){ UNDEFINED_INTRINSICS("__remill_sparc_trap_cond_cc"); return 0; }
Memory *__remill_sparc_trap_cond_cs(Memory *){ UNDEFINED_INTRINSICS("__remill_sparc_trap_cond_cs"); return 0; }
Memory *__remill_sparc_trap_cond_pos(Memory *){ UNDEFINED_INTRINSICS("__remill_sparc_trap_cond_pos"); return 0; }
Memory *__remill_sparc_trap_cond_neg(Memory *){ UNDEFINED_INTRINSICS("__remill_sparc_trap_cond_neg"); return 0; }
Memory *__remill_sparc_trap_cond_vc(Memory *){ UNDEFINED_INTRINSICS("__remill_sparc_trap_cond_vc"); return 0; }
Memory *__remill_sparc_trap_cond_vs(Memory *){ UNDEFINED_INTRINSICS("__remill_sparc_trap_cond_vs"); return 0; }
Memory *__remill_sparc32_emulate_instruction(Memory *){ UNDEFINED_INTRINSICS("__remill_sparc32_emulate_instruction"); return 0; }
Memory *__remill_sparc64_emulate_instruction(Memory *){ UNDEFINED_INTRINSICS("__remill_sparc64_emulate_instruction"); return 0; }
Memory *__remill_ppc_emulate_instruction(Memory *){ UNDEFINED_INTRINSICS("__remill_ppc_emulate_instruction"); return 0; }
Memory *__remill_ppc_syscall(Memory *){ UNDEFINED_INTRINSICS("__remill_ppc_syscall"); return 0; }
