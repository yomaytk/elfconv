#include "aarch64_ttype.h"

#include <arm_neon.h>

// ST1  { <Vt>.D }[<index>], [<Xn|SP>]
void st1_simd_d_index(uint64x2_t qt1, double *res_ptr) {
  asm __volatile__("ST1 {%[q1].d}[1], [%[ptr]]" ::[q1] "w"(qt1), [ptr] "r"(res_ptr) : "memory");
}
// ST1  { <Vt>.D }[<index>], [<Xn|SP>], #8
void st1_simd_d_index_postimm(uint64x2_t qt1, double **res_ptr) {
  asm __volatile__("ST1 {%[q1].d}[1], [%[ptr]], #8"
                   : [ptr] "+r"(*res_ptr)
                   : [q1] "w"(qt1)
                   : "memory");
}
// ST1  { <Vt>.D }[<index>], [<Xn|SP>], <Xm>
void st1_simd_d_index_postreg(uint64x2_t qt1, double **res_ptr, uint64_t reg1) {
  asm __volatile__("ST1 {%[q1].d}[1], [%[ptr]], %[r1]"
                   : [ptr] "+r"(*res_ptr)
                   : [q1] "w"(qt1), [r1] "r"(reg1)
                   : "memory");
}
// STR <Bt>, [<Xn|SP>], #<simm>
void str_simd_b_simmpost(uint8x8_t bt, uint8_t **res_ptr) {
  asm __volatile__("STR %b1, [%0], #1" : "+r"(*res_ptr) : "w"(bt) : "memory");
}
// STR <Ht>, [<Xn|SP>], #<simm>
void str_simd_h_simmpost(uint16x4_t ht, uint16_t **res_ptr) {
  asm __volatile__("STR %h1, [%0], #2" : "+r"(*res_ptr) : "w"(ht) : "memory");
}
// STR <St>, [<Xn|SP>], #<simm>
void str_simd_s_simmpost(float val, float **res_ptr) {
  asm __volatile__("STR %s1, [%0], #4" : "+r"(*res_ptr) : "w"(val) : "memory");
}
// STR <Dt>, [<Xn|SP>], #<simm>
void str_simd_d_simmpost(float val, float **res_ptr) {
  asm __volatile__("STR %d1, [%0], #4" : "+r"(*res_ptr) : "w"(val) : "memory");
}
// STR <Qt>, [<Xn|SP>], #<simm>
void str_simd_q_simmpost(uint64x2_t qt, double **res_ptr) {
  asm __volatile__("STR %q1, [%0], #8" : "+r"(*res_ptr) : "w"(qt) : "memory");
}
// STR <Bt>, [<Xn|SP>, #<simm>]!
void str_simd_b_simmpre(uint8x8_t bt, uint8_t **res_ptr) {
  asm __volatile__("STR %b1, [%0, #1]!" : "+r"(*res_ptr) : "w"(bt) : "memory");
}
// STR <Ht>, [<Xn|SP>, #<simm>]!
void str_simd_h_simmpre(uint16x4_t ht, uint16_t **res_ptr) {
  asm __volatile__("STR %h1, [%0, #2]!" : "+r"(*res_ptr) : "w"(ht) : "memory");
}
// STR <St>, [<Xn|SP>, #<simm>]!
void str_simd_s_simmpre(float val, float **res_ptr) {
  asm __volatile__("STR %d1, [%0, #4]!" : "+r"(*res_ptr) : "w"(val) : "memory");
}
// STR <Dt>, [<Xn|SP>, #<simm>]!
void str_simd_d_simmpre(double val, double **res_ptr) {
  asm __volatile__("STR %d1, [%0, #8]!" : "+r"(*res_ptr) : "w"(val) : "memory");
}
// STR <St>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
// no option
void str_simd_s_regoff(float val, float *mem_ptr, uint64_t offset) {
  asm __volatile__("STR %s0, [%1, %2]" ::"w"(val), "r"(mem_ptr), "r"(offset) : "memory");
}
// lsl
void str_simd_s_regoff_lsl(float val, float *mem_ptr, uint64_t offset) {
  asm __volatile__("STR %s0, [%1, %2, LSL #2]" ::"w"(val), "r"(mem_ptr), "r"(offset) : "memory");
}
// sxtx
void str_simd_s_regoff_sxtx(float val, float *mem_ptr, uint64_t offset) {
  asm __volatile__("STR %s0, [%1, %2, sxtx #2]" ::"w"(val), "r"(mem_ptr), "r"(offset) : "memory");
}
// STR <Dt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
// no option
void str_simd_d_regoff(double val, double *mem_ptr, uint64_t offset) {
  asm __volatile__("STR %d0, [%1, %2]" ::"w"(val), "r"(mem_ptr), "r"(offset) : "memory");
}
// lsl
void str_simd_d_regoff_lsl(double val, double *mem_ptr, uint64_t offset) {
  asm __volatile__("STR %d0, [%1, %2, LSL #3]" ::"w"(val), "r"(mem_ptr), "r"(offset) : "memory");
}
// sxtx
void str_simd_d_regoff_sxtx(double val, double *mem_ptr, uint64_t offset) {
  asm __volatile__("STR %d0, [%1, %2, sxtx #3]" ::"w"(val), "r"(mem_ptr), "r"(offset) : "memory");
}
// STLR <Xt>, [<Xn|SP>{,#0}]
void stlr_x(uint64_t val, uint64_t *mem_ptr) {
  asm __volatile__("STLR %x0, [%1]" ::"r"(val), "r"(mem_ptr) : "memory");
}
// STP  <St1>, <St2>, [<Xn|SP>, #<imm>]!
void stp_s_immpre(float st1, float st2, float **mem_ptr) {
  asm __volatile__("STP %s[s1], %s[s2], [%[ptr], #8]!"
                   : [ptr] "+r"(*mem_ptr)
                   : [s1] "w"(st1), [s2] "w"(st2)
                   : "memory");
}
// STP  <Dt1>, <Dt2>, [<Xn|SP>, #<imm>]!
void stp_d_immpre(double dt1, double dt2, double **mem_ptr) {
  asm __volatile__("STP %d[d1], %d[d2], [%[ptr], #16]!"
                   : [ptr] "+r"(*mem_ptr)
                   : [d1] "w"(dt1), [d2] "w"(dt2)
                   : "memory");
}
// STP <Qt1>, <Qt2>, [<Xn|SP>, #<imm>]!
void stp_q_immpre(uint64x2_t qt1, uint64x2_t qt2, double **mem_ptr) {
  asm __volatile__("STP %q[q1], %q[q2], [%[ptr], #16]!"
                   : [ptr] "+r"(*mem_ptr)
                   : [q1] "w"(qt1), [q2] "w"(qt2)
                   : "memory");
}
// STP  <St1>, <St2>, [<Xn|SP>], #<imm>
void stp_s_imm_post(float st1, float st2, float **mem_ptr) {
  asm __volatile__("STP %s[s1], %s[s2], [%[ptr]], #8"
                   : [ptr] "+r"(*mem_ptr)
                   : [s1] "w"(st1), [s2] "w"(st2)
                   : "memory");
}
// STP  <Dt1>, <Dt2>, [<Xn|SP>], #<imm>
void stp_d_imm_post(double dt1, double dt2, double **mem_ptr) {
  asm __volatile__("STP %s[d1], %s[d2], [%[ptr]], #16"
                   : [ptr] "+r"(*mem_ptr)
                   : [d1] "w"(dt1), [d2] "w"(dt2)
                   : "memory");
}
// STP <Qt1>, <Qt2>, [<Xn|SP>], #<imm>
void stp_q_imm_post(uint64x2_t qt1, uint64x2_t qt2, double **mem_ptr) {
  asm __volatile__("STP %q[q1], %q[q2], [%[ptr]], #16"
                   : [ptr] "+r"(*mem_ptr)
                   : [q1] "w"(qt1), [q2] "w"(qt2)
                   : "memory");
}
// MOV  <Vd>.<Ts>[<index1>], <Vn>.<Ts>[<index2>]
void mov_ins_v_v(uint64x2_t *qt1, uint64x2_t qt2) {
  asm __volatile__("MOV %[q1].d[1], %[q2].d[0]" : [q1] "+w"(*qt1) : [q2] "w"(qt2));
}
// SWP <Ws>, <Wt>, [<Xn|SP>]
void swp_word(uint32_t *ws, uint32_t wt, uint32_t *mem_ptr) {
  asm __volatile__("SWP %w0, %w1, [%2]" : "=r"(*ws) : "r"(wt), "r"(mem_ptr) : "memory");
}
// SWP <Xs>, <Xt>, [<Xn|SP>]
void swp_doubleword(uint64_t *xs, uint64_t xt, uint64_t *mem_ptr) {
  asm __volatile__("SWP %x0, %x1, [%2]" : "=r"(*xs) : "r"(xt), "r"(mem_ptr) : "memory");
}
// SWPA <Ws>, <Wt>, [<Xn|SP>]
void swpa_word(uint32_t *ws, uint32_t wt, uint32_t *mem_ptr) {
  asm __volatile__("SWPA %w0, %w1, [%2]" : "=r"(*ws) : "r"(wt), "r"(mem_ptr) : "memory");
}
// SWPA <Xs>, <Xt>, [<Xn|SP>]
void swpa_doubleword(uint64_t *xs, uint64_t xt, uint64_t *mem_ptr) {
  asm __volatile__("SWPA %x0, %x1, [%2]" : "=r"(*xs) : "r"(xt), "r"(mem_ptr) : "memory");
}
// SWPL <Ws>, <Wt>, [<Xn|SP>]
void swpl_word(uint32_t *ws, uint32_t wt, uint32_t *mem_ptr) {
  asm __volatile__("SWP %w0, %w1, [%2]" : "=r"(*ws) : "r"(wt), "r"(mem_ptr) : "memory");
}
// SWPL <Xs>, <Xt>, [<Xn|SP>]
void swpl_doubleword(uint64_t *xs, uint64_t xt, uint64_t *mem_ptr) {
  asm __volatile__("SWP %x0, %x1, [%2]" : "=r"(*xs) : "r"(xt), "r"(mem_ptr) : "memory");
}
// LDR <Bt>, [<Xn|SP>, (<Wm>|<Xm>), <extend> {<amount>}]
void ldr_byte(uint8x8_t *bt, uint8x8_t *mem_xn, uint64_t xm_off) {
  asm __volatile__("LDR %b0, [%1, %2]" : "=w"(*bt) : "r"(mem_xn), "r"(xm_off) : "memory");
}
// LDADD  <Ws>, <Wt>, [<Xn|SP>]
void ldadd_word(uint32_t *ws, uint32_t wt, uint32_t *mem_ptr) {
  asm __volatile__("LDADD %w0, %w1, [%2]" : "=r"(*ws) : "r"(wt), "r"(mem_ptr) : "memory");
}
// LDADD <Xs>, <Xt>, [<Xn|SP>]
void ldadd_doubleword(uint64_t *xs, uint64_t xt, uint64_t *mem_ptr) {
  asm __volatile__("LDADD %x0, %x1, [%2]" : "=r"(*xs) : "r"(xt), "r"(mem_ptr) : "memory");
}
// LDADDA <Ws>, <Wt>, [<Xn|SP>]
void ldadda_word(uint32_t *ws, uint32_t wt, uint32_t *mem_ptr) {
  asm __volatile__("LDADDA %w0, %w1, [%2]" : "=r"(*ws) : "r"(wt), "r"(mem_ptr) : "memory");
}
// LDADDA <Xs>, <Xt>, [<Xn|SP>]
void ldadda_doubleword(uint64_t *xs, uint64_t xt, uint64_t *mem_ptr) {
  asm __volatile__("LDADDA %x0, %x1, [%2]" : "=r"(*xs) : "r"(xt), "r"(mem_ptr) : "memory");
}
// LDADDL <Ws>, <Wt>, [<Xn|SP>]
void ldaddl_word(uint32_t *ws, uint32_t wt, uint32_t *mem_ptr) {
  asm __volatile__("LDADD %w0, %w1, [%2]" : "=r"(*ws) : "r"(wt), "r"(mem_ptr) : "memory");
}
// LDADDL <Xs>, <Xt>, [<Xn|SP>]
void ldaddl_doubleword(uint64_t *xs, uint64_t xt, uint64_t *mem_ptr) {
  asm __volatile__("LDADD %x0, %x1, [%2]" : "=r"(*xs) : "r"(xt), "r"(mem_ptr) : "memory");
}
// LDADDAL <Ws>, <Wt>, [<Xn|SP>]
void ldaddal_word(uint32_t *ws, uint32_t wt, uint32_t *mem_ptr) {
  asm __volatile__("LDADD %w0, %w1, [%2]" : "=r"(*ws) : "r"(wt), "r"(mem_ptr) : "memory");
}
// LDADDAL <Xs>, <Xt>, [<Xn|SP>]
void ldaddal_doubleword(uint64_t *xs, uint64_t xt, uint64_t *mem_ptr) {
  asm __volatile__("LDADD %x0, %x1, [%2]" : "=r"(*xs) : "r"(xt), "r"(mem_ptr) : "memory");
}
// LDSET <Ws>, <Wt>, [<Xn|SP>]
void ldset_word(uint32_t *ws, uint32_t wt, uint32_t *mem_ptr) {
  asm __volatile__("LDSET %w0, %w1, [%2]" : "=r"(*ws) : "r"(wt), "r"(mem_ptr) : "memory");
}
// LDSET <Xs>, <Xt>, [<Xn|SP>]
void ldset_doubleword(uint64_t *xs, uint64_t xt, uint64_t *mem_ptr) {
  asm __volatile__("LDSET %x0, %x1, [%2]" : "=r"(*xs) : "r"(xt), "r"(mem_ptr) : "memory");
}
// LDSETA <Ws>, <Wt>, [<Xn|SP>]
void ldseta_word(uint32_t *ws, uint32_t wt, uint32_t *mem_ptr) {
  asm __volatile__("LDSETA %w0, %w1, [%2]" : "=r"(*ws) : "r"(wt), "r"(mem_ptr) : "memory");
}
// LDSETA <Xs>, <Xt>, [<Xn|SP>]
void ldseta_doubleword(uint64_t *xs, uint64_t xt, uint64_t *mem_ptr) {
  asm __volatile__("LDSET %x0, %x1, [%2]" : "=r"(*xs) : "r"(xt), "r"(mem_ptr) : "memory");
}
// LDSETL <Ws>, <Wt>, [<Xn|SP>]
void ldsetl_word(uint32_t *ws, uint32_t wt, uint32_t *mem_ptr) {
  asm __volatile__("LDSETL %w0, %w1, [%2]" : "=r"(*ws) : "r"(wt), "r"(mem_ptr) : "memory");
}
// LDSETL <Xs>, <Xt>, [<Xn|SP>]
void ldsetl_doubleword(uint64_t *xs, uint64_t xt, uint64_t *mem_ptr) {
  asm __volatile__("LDSET %x0, %x1, [%2]" : "=r"(*xs) : "r"(xt), "r"(mem_ptr) : "memory");
}
// LDSETAL <Ws>, <Wt>, [<Xn|SP>]
void ldsetal_word(uint32_t *ws, uint32_t wt, uint32_t *mem_ptr) {
  asm __volatile__("LDSET %w0, %w1, [%2]" : "=r"(*ws) : "r"(wt), "r"(mem_ptr) : "memory");
}
// LDSETAL <Xs>, <Xt>, [<Xn|SP>]
void ldsetal_doubleword(uint64_t *xs, uint64_t xt, uint64_t *mem_ptr) {
  asm __volatile__("LDSET %x0, %x1, [%2]" : "=r"(*xs) : "r"(xt), "r"(mem_ptr) : "memory");
}
// LDURSH <Xt>, [<Xn|SP>{, #<simm>}]
void ldursh_doubleword_preimm(uint64_t *xt, uint64_t *mem_ptr) {
  asm __volatile__("LDURSH %x0, [%x1, 8]" : "=r"(*xt) : "r"(mem_ptr) : "memory");
}
// BIC <Vd>.<T>, #<imm8>{, LSL #<amount>}
void bic_asimd_imm(uint16x4_t *qt1) {
  asm __volatile__("BIC %0.4h, 12, lsl 8" : "+w"(*qt1));
}
// CAS <Ws>, <Wt>, [<Xn|SP>{,#0}]
void cas_word(uint32_t *ws, uint32_t wt, uint32_t *mem_ptr) {
  asm __volatile__("CAS %w0, %w1, [%2]" : "+r"(*ws) : "r"(wt), "r"(mem_ptr) : "memory");
}
// CAS <Xs>, <Xt>, [<Xn|SP>{,#0}]
void cas_doubleword(uint64_t *xs, uint64_t xt, uint64_t *mem_ptr) {
  asm __volatile__("CAS %x0, %x1, [%2]" : "+r"(*xs) : "r"(xt), "r"(mem_ptr) : "memory");
}
// CASA <Ws>, <Wt>, [<Xn|SP>{,#0}]
void casa_word(uint32_t *ws, uint32_t wt, uint32_t *mem_ptr) {
  asm __volatile__("CASA %w0, %w1, [%2]" : "+r"(*ws) : "r"(wt), "r"(mem_ptr) : "memory");
}
// CASA <Xs>, <Xt>, [<Xn|SP>{,#0}]
void casa_doubleword(uint64_t *xs, uint64_t xt, uint64_t *mem_ptr) {
  asm __volatile__("CASA %x0, %x1, [%2]" : "+r"(*xs) : "r"(xt), "r"(mem_ptr) : "memory");
}
// CASAL <Ws>, <Wt>, [<Xn|SP>{,#0}]
void casal_word(uint32_t *ws, uint32_t wt, uint32_t *mem_ptr) {
  asm __volatile__("CASAL %w0, %w1, [%2]" : "+r"(*ws) : "r"(wt), "r"(mem_ptr) : "memory");
}
// CASAL <Xs>, <Xt>, [<Xn|SP>{,#0}]
void casal_doubleword(uint64_t *xs, uint64_t xt, uint64_t *mem_ptr) {
  asm __volatile__("CASAL %x0, %x1, [%2]" : "+r"(*xs) : "r"(xt), "r"(mem_ptr) : "memory");
}
// CASL <Ws>, <Wt>, [<Xn|SP>{,#0}]
void casl_word(uint32_t *ws, uint32_t wt, uint32_t *mem_ptr) {
  asm __volatile__("CASL %w0, %w1, [%2]" : "+r"(*ws) : "r"(wt), "r"(mem_ptr) : "memory");
}
// CASL <Xs>, <Xt>, [<Xn|SP>{,#0}]
void casl_doubleword(uint64_t *xs, uint64_t xt, uint64_t *mem_ptr) {
  asm __volatile__("CASL %x0, %x1, [%2]" : "+r"(*xs) : "r"(xt), "r"(mem_ptr) : "memory");
}
// LD1R { <Vt>.<T> }, [<Xn|SP>] (T = 4H)
void ld1r_4h(uint16x4_t *qt1, uint16_t *mem_ptr) {
  asm __volatile__("LD1R {%0.4h}, [%1]" : "+w"(*qt1) : "r"(mem_ptr) : "memory");
}
// LD1R { <Vt>.<T> }, [<Xn|SP>] (T = 4S)
void ld1r_4s(uint32x4_t *qt1, uint32_t *mem_ptr) {
  asm __volatile__("LD1R {%0.4s}, [%1]" : "+w"(*qt1) : "r"(mem_ptr) : "memory");
}
// STXR <Ws>, <Wt>, [<Xn|SP>{,#0}]
void stxr_word(uint32_t *ws1, uint32_t *w_status, uint32_t wt, uint32_t *mem_ptr) {
  asm __volatile__("LDXR %w0, [%[mem]] \n\t"
                   "STXR %w1, %w2, [%[mem]]"
                   : "+r"(*ws1), "+r"(*w_status)
                   : "r"(wt), [mem] "r"(mem_ptr)
                   : "memory");  // LDXR for exclusive access
}
// STXR <Ws>, <Xt>, [<Xn|SP>{,#0}]
void stxr_doubleword(uint64_t *xs1, uint32_t *ws2, uint64_t xt, uint64_t *mem_ptr) {
  asm __volatile__("LDXR %x0, [%[mem]] \n\t"
                   "STXR %w1, %w2, [%[mem]]"
                   : "+r"(*xs1), "+r"(*ws2)
                   : "r"(xt), [mem] "r"(mem_ptr)
                   : "memory");  // LDXR for exclusive access
}
// DC <dc_op>, <Xt> (dc_op = zva)
void dc_zva(uint64_t *mem_ptr) {
  asm __volatile__("DC zva, %0" ::"r"(mem_ptr));
}
// CNT  <Vd>.<T>, <Vn>.<T> (T = 8B)
void cnt_vector_8b(uint8x8_t *qt1, uint8x8_t qt2) {
  asm __volatile__("CNT %0.8B, %1.8B" : "=w"(*qt1) : "w"(qt2));
}
// CNT  <Vd>.<T>, <Vn>.<T> (T = 16B)
void cnt_vector_16b(uint8x16_t *qt1, uint8x16_t qt2) {
  asm __volatile__("CNT %0.16B, %1.16B" : "=w"(*qt1) : "w"(qt2));
}
