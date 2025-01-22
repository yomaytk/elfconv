#include "BINARY.c"
#include "COND.c"
#include "CONVERT.c"
#include "DATAXFER.c"
#include "MISC.c"
#include "SIMD.c"
#include "aarch64_ttype.h"

#include <arm_neon.h>
#include <assert.h>
#include <stdio.h>

void test_cond() {}

/*
  BINARY.c
*/
// FMSUB  <Sd>, <Sn>, <Sm>, <Sa> (Note. have a mergin of error compared to normal compilation)
void test_fmsub_float() {
  float sd = 0;
  float sn = 3;
  float sm = 12.25;
  float sa = 5.25;
  fmsub_float(&sd, sn, sm, sa);
  assert(-31.5 == sd);
  printf("ok FMSUB  <Sd>, <Sn>, <Sm>, <Sa>\n");
}
// FMSUB  <Dd>, <Dn>, <Dm>, <Da> (Note. have a mergin of error compared to normal compilation)
void test_fmsub_double() {
  double dd = 0;
  double dn = 3;
  double dm = 12.25;
  double da = 5.25;
  fmsub_double(&dd, dn, dm, da);
  assert(-31.5 == dd);
  printf("ok FMSUB  <Dd>, <Dn>, <Dm>, <Da>\n");
}
// ADC  <Wd>, <Wn>, <Wm>
void test_adc_word() {
  // overflow
  {
    uint32_t _r1 = 1 << 31;
    uint32_t _r2 = 1 << 31;
    uint32_t wd = 0;
    uint32_t wn = 12;
    uint32_t wm = 123;
    adc_word(_r1, _r2, &wd, wn, wm);
    assert(136 == wd);
  }
  // not overflow
  {
    uint32_t _r1 = 1 << 30;
    uint32_t _r2 = 1 << 31;
    uint32_t wd = 0;
    uint32_t wn = 12;
    uint32_t wm = 123;
    adc_word(_r1, _r2, &wd, wn, wm);
    assert(135 == wd);
  }
  printf("ok ADC  <Wd>, <Wn>, <Wm>\n");
}
// ADC  <Xd>, <Xn>, <Xm>
void test_adc_doubleword() {
  // overflow
  {
    uint64_t _r1 = 1ULL << 63;
    uint64_t _r2 = 1LL << 63;
    uint64_t xd = 0;
    uint64_t xn = 12;
    uint64_t xm = 123;
    adc_doubleword(_r1, _r2, &xd, xn, xm);
    assert(136 == xd);
  }
  // not overflow
  {
    uint64_t _r1 = 1ULL << 62;
    uint64_t _r2 = 1ULL << 63;
    uint64_t xd = 0;
    uint64_t xn = 12;
    uint64_t xm = 123;
    adc_doubleword(_r1, _r2, &xd, xn, xm);
    assert(135 == xd);
  }
  printf("ok ADC  <Xd>, <Xn>, <Xm>\n");
}
// UMSUBL <Xd>, <Wn>, <Wm>, <Xa>
void test_umsubl() {
  uint64_t xd = 0;
  uint32_t wn = 12;
  uint32_t wm = 13;
  uint64_t xa = 200;
  umsubl(&xd, wn, wm, xa);
  assert(44 == xd);
  printf("ok UMSUBL <Xd>, <Wn>, <Wm>, <Xa>\n");
}
// FSUB <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
void test_fsub_vector() {
  float32x4_t qtd = vcombine_f32(vcreate_f32(0), vcreate_f32(0));
  float32x4_t qtn = vcombine_f32(vcreate_f32(0), vcreate_f32(0));
  qtn = vsetq_lane_f32(1.25, qtn, 0);
  qtn = vsetq_lane_f32(2.5, qtn, 1);
  qtn = vsetq_lane_f32(4.5, qtn, 2);
  qtn = vsetq_lane_f32(1.5, qtn, 3);
  float32x4_t qtm = vcombine_f32(vcreate_f32(0), vcreate_f32(0));
  qtm = vsetq_lane_f32(1, qtm, 0);
  qtm = vsetq_lane_f32(2, qtm, 1);
  qtm = vsetq_lane_f32(3, qtm, 2);
  qtm = vsetq_lane_f32(4, qtm, 3);
  fsub_vector(&qtd, qtn, qtm);
  assert(0.25 == vgetq_lane_f32(qtd, 0));
  assert(0.5 == vgetq_lane_f32(qtd, 1));
  assert(1.5 == vgetq_lane_f32(qtd, 2));
  assert(-2.5 == vgetq_lane_f32(qtd, 3));
  printf("ok FSUB <Vd>.<T>, <Vn>.<T>, <Vm>.<T>\n");
}
// FDIV  <Vd>.<T>, <Vn>.<T>, <Vm>.<T> (only 32bit or 64bit)
void test_fdiv_vector() {
  float32x4_t qtd = vcombine_f32(vcreate_f32(0), vcreate_f32(0));
  float32x4_t qtn = vcombine_f32(vcreate_f32(0), vcreate_f32(0));
  qtn = vsetq_lane_f32(2.4, qtn, 0);
  qtn = vsetq_lane_f32(2, qtn, 1);
  qtn = vsetq_lane_f32(17.5, qtn, 2);
  qtn = vsetq_lane_f32(-4, qtn, 3);
  float32x4_t qtm = vcombine_f32(vcreate_f32(0), vcreate_f32(0));
  qtm = vsetq_lane_f32(1.2, qtm, 0);
  qtm = vsetq_lane_f32(0.5, qtm, 1);
  qtm = vsetq_lane_f32(3.5, qtm, 2);
  qtm = vsetq_lane_f32(8, qtm, 3);
  fdiv_vector(&qtd, qtn, qtm);
  assert(2 == vgetq_lane_f32(qtd, 0));
  assert(4 == vgetq_lane_f32(qtd, 1));
  assert(5 == vgetq_lane_f32(qtd, 2));
  assert(-0.5 == vgetq_lane_f32(qtd, 3));
  printf("ok FDIV <Vd>.<T>, <Vn>.<T>, <Vm>.<T> (only 32bit or 64bit)\n");
}
/*
  CONVVERT.c
*/
// UCVTF  <V><d>, <V><n> (<V> = S)
void test_ucvtf_float() {
  float sd = 0;
  uint32_t n32 = 43;
  ucvtf_float(&sd, n32);
  assert(43 == sd);
  printf("ok UCVTF  <V><d>, <V><n> (<V> = S)\n");
}
// UCVTF  <V><d>, <V><n> (<V> = D)
void test_ucvtf_double() {
  double dd = 0;
  uint64_t n64 = 43;
  ucvtf_double(&dd, n64);
  assert(43 == dd);
  printf("ok UCVTF  <V><d>, <V><n> (<V> = D)\n");
}
// SCVTF  <V><d>, <V><n> (<V> = S)
void test_scvtf_float() {
  float sd = 0;
  int n32 = -43;
  scvtf_float(&sd, n32);
  assert(-43 == sd);
  printf("ok SCVTF  <V><d>, <V><n> (<V> = S)\n");
}
// SCVTF  <V><d>, <V><n> (<V> = D)
void test_scvtf_double() {
  double dd = 0;
  long n64 = -43;
  scvtf_double(&dd, n64);
  assert(-43 == dd);
  printf("ok SCVTF  <V><d>, <V><n> (<V> = D)\n");
}
// FRINTA  <Dd>, <Dn>
void test_frinta_doubleword() {
  double dn = 43.3;
  double dd = 0;
  frinta_doubleword(dn, &dd);
  assert(43 == dd);
  printf("ok FRINTA  <Dd>, <Dn>\n");
}
// FCVTAS  <Xd>, <Dn>
void test_fcvtas_doubleword() {
  double dn = 43.3;
  long xd = 0;
  fcvtas_doubleword(dn, &xd);
  assert(43 == xd);
  printf("ok FCVTAS  <Xd>, <Dn>\n");
}

/*
  DATAXFER.c
*/
// ST1  { <Vt>.D }[<index>], [<Xn|SP>]
void test_st1_simd_d_index() {
  double res_f64 = 0;
  double a1 = 1.2f;
  double a2 = 12.3f;
  uint64x2_t qt1 = vcombine_u64(vcreate_u64(*((uint64_t *) &a1)), vcreate_u64(*((uint64_t *) &a2)));
  st1_simd_d_index(qt1, &res_f64);
  assert(12.3f == res_f64);
  printf("ok ST1  { <Vt>.D }[<index>], [<Xn|SP>]\n");
}
// ST1  { <Vt>.D }[<index>], [<Xn|SP>], #8
void test_st1_simd_d_index_postimm() {
  double res_f64 = 0;
  double a1 = 1.2f;
  double a2 = 12.3f;
  uint64x2_t qt1 = vcombine_u64(vcreate_u64(*((uint64_t *) &a1)), vcreate_u64(*((uint64_t *) &a2)));
  double *mem_ptr_reg = &res_f64;
  st1_simd_d_index_postimm(qt1, &mem_ptr_reg);
  assert(12.3f == res_f64);
  assert(&res_f64 + 1 == mem_ptr_reg);
  printf("ok ST1  { <Vt>.D }[<index>], [<Xn|SP>], #8\n");
}
// ST1  { <Vt>.D }[<index>], [<Xn|SP>], <Xm>
void test_st1_simd_d_index_postreg() {
  double res_f64 = 0;
  double a1 = 1.2f;
  double a2 = 12.3f;
  uint64x2_t qt1 = vcombine_u64(vcreate_u64(*((uint64_t *) &a1)), vcreate_u64(*((uint64_t *) &a2)));
  double *mem_ptr_reg = &res_f64;
  st1_simd_d_index_postreg(qt1, &mem_ptr_reg, 16);
  assert(12.3f == res_f64);
  assert(&res_f64 + 2 == mem_ptr_reg);
  printf("ok ST1  { <Vt>.D }[<index>], [<Xn|SP>], <Xm>\n");
}
// STR <Bt>, [<Xn|SP>], #<simm>
void test_str_simd_b_simmpost() {
  uint8x8_t bt = vcreate_u8(42);
  uint8_t res_u8[10] = {0};
  uint8_t *res_ptr = res_u8;
  str_simd_b_simmpost(bt, &res_ptr);
  assert(42 == res_u8[0]);
  assert(res_u8 + 1 == res_ptr);
  printf("ok STR <Bt>, [<Xn|SP>], #<simm>\n");
}
// STR <Ht>, [<Xn|SP>], #<simm>
void test_str_simd_h_simmpost() {
  uint16x4_t ht = vcreate_u16(42);
  uint16_t res_u16[10] = {0};
  uint16_t *res_ptr = res_u16;
  str_simd_h_simmpost(ht, &res_ptr);
  assert(42 == res_u16[0]);
  assert(res_u16 + 1 == res_ptr);
  printf("ok STR <Ht>, [<Xn|SP>], #<simm>\n");
}
// STR <St>, [<Xn|SP>], #<simm>
void test_str_simd_s_simmpost() {
  float res_f32[1024] = {0};
  double res_f64[1024] = {0};
  {
    float *res = res_f32;
    str_simd_s_simmpost(43.3f, &res);
    assert(43.3f == res_f32[0]);
    assert(res_f32 + 1 == res);
  }
  {
    float *res = res_f32;
    str_simd_s_simmpost(-43.3f, &res);
    assert(-43.3f == res_f32[0]);
  }
  {
    float *res = res_f32;
    str_simd_s_simmpost(43, &res);
    assert(43 == res_f32[0]);
  }
  printf("ok STR <St>, [<Xn|SP>], #<simm>\n");
}
// STR <Dt>, [<Xn|SP>], #<simm>
void test_str_simd_d_simmpost() {
  float res_f32[1024] = {0};
  double res_f64[1024] = {0};
  {
    float *res = res_f32;
    str_simd_d_simmpost(43.3f, &res);
    assert(43.3f == res_f32[0]);
    assert(res_f32 + 1 == res);
  }
  {
    float *res = res_f32;
    str_simd_d_simmpost(-43.3f, &res);
    assert(-43.3f == res_f32[0]);
  }
  {
    float *res = res_f32;
    str_simd_d_simmpost(43, &res);
    assert(43 == res_f32[0]);
  }
  printf("ok STR <Dt>, [<Xn|SP>], #<simm>\n");
}
// STR <Qt>, [<Xn|SP>], #<simm>
void test_str_simd_q_simmpost() {
  double res_f64[100] = {0};
  double a1 = 1.2f;
  double a2 = 12.3f;
  uint64x2_t qt1 = vcombine_u64(vcreate_u64(*((uint64_t *) &a1)), vcreate_u64(*((uint64_t *) &a2)));
  double *mem_ptr_reg = res_f64;
  str_simd_q_simmpost(qt1, &mem_ptr_reg);
  assert(1.2f == res_f64[0]);
  assert(12.3f == res_f64[1]);
  assert(res_f64 + 1 == mem_ptr_reg);
  printf("ok STR <Qt>, [<Xn|SP>], #<simm>\n");
}
// STR <Bt>, [<Xn|SP>, #<simm>]!
void test_str_simd_b_simmpre() {
  uint8x8_t bt = vcreate_u8(42);
  uint8_t res_u8[10] = {0};
  uint8_t *res_ptr = res_u8;
  str_simd_b_simmpre(bt, &res_ptr);
  assert(42 == res_u8[1]);
  assert(res_u8 + 1 == res_ptr);
  printf("ok STR <Bt>, [<Xn|SP>, #<simm>]!\n");
}
// STR <Ht>, [<Xn|SP>, #<simm>]!
void test_str_simd_h_simmpre() {
  uint16x4_t ht = vcreate_u16(42);
  uint16_t res_u16[10] = {0};
  uint16_t *res_ptr = res_u16;
  str_simd_h_simmpre(ht, &res_ptr);
  assert(42 == res_u16[1]);
  assert(res_u16 + 1 == res_ptr);
  printf("ok STR <Ht>, [<Xn|SP>, #<simm>]!\n");
}
// STR <St>, [<Xn|SP>, #<simm>]!
void test_str_simd_s_simmpre() {
  float st = 42.5f;
  float res_f32[10] = {0};
  float *res_ptr = res_f32;
  str_simd_s_simmpre(st, &res_ptr);
  assert(42.5f == res_f32[1]);
  assert(res_f32 + 1 == res_ptr);
  printf("ok STR <St>, [<Xn|SP>, #<simm>]!\n");
}
// STR <Dt>, [<Xn|SP>, #<simm>]!
void test_str_simd_d_simmpre() {
  double dt = 42.5f;
  double res_f64[10] = {0};
  double *res_ptr = res_f64;
  str_simd_d_simmpre(dt, &res_ptr);
  assert(42.5f == res_f64[1]);
  assert(res_f64 + 1 == res_ptr);
  printf("ok STR <Dt>, [<Xn|SP>, #<simm>]!\n");
}
// STR <St>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
void test_str_simd_s_regoff() {
  float res_f32[100] = {0};
  // no option
  {
    uint64_t offset = sizeof(float) * 14;
    str_simd_s_regoff(43.5f, res_f32, offset);
    assert(43.5f == res_f32[14]);
    res_f32[14] = 0;
  }
  // lsl
  {
    uint64_t offset = 15;
    str_simd_s_regoff_lsl(43.6f, res_f32, offset);
    assert(43.6f == res_f32[15]);
    res_f32[15] = 0;
  }
  // sxtx
  {
    uint64_t offset = 16;
    str_simd_s_regoff_lsl(43.7f, res_f32, offset);
    assert(43.7f == res_f32[16]);
    res_f32[16] = 0;
  }
  printf("ok STR <St>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]\n");
}
// STR <Dt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
void test_str_simd_d_regoff() {
  double res_f64[100] = {0};
  // no option
  {
    uint64_t offset = sizeof(double) * 11;
    str_simd_d_regoff(43.2f, res_f64, offset);
    assert(43.2f == res_f64[11]);
    res_f64[11] = 0;
  }
  // lsl
  {
    uint64_t offset = 12;
    str_simd_d_regoff_lsl(43.3f, res_f64, offset);
    assert(43.3f == res_f64[12]);
    res_f64[12] = 0;
  }
  // sxtx
  {
    uint64_t offset = 13;
    str_simd_d_regoff_sxtx(43.4f, res_f64, offset);
    assert(43.4f == res_f64[13]);
    res_f64[13] = 0;
  }
  printf("ok STR <Dt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]\n");
}
// STLR <Xt>, [<Xn|SP>{,#0}]
void test_stlr_x() {
  uint64_t mem_val = 0;
  stlr_x(44, &mem_val);
  assert(44 == mem_val);
  printf("ok STLR <Xt>, [<Xn|SP>{,#0}]\n");
}
// STP <Qt1>, <Qt2>, [<Xn|SP>, #<imm>]!
void test_stp_q_immpre() {
  double res_f64[100] = {0};
  double a1 = 43.8f;
  double a2 = 43.9f;
  double b1 = 44.0f;
  double b2 = 44.1f;
  double *mem_ptr_reg = res_f64;
  uint64x2_t qt1 = vcombine_u64(vcreate_u64(*((uint64_t *) &a1)), vcreate_u64(*((uint64_t *) &a2)));
  uint64x2_t qt2 = vcombine_u64(vcreate_u64(*((uint64_t *) &b1)), vcreate_u64(*((uint64_t *) &b2)));
  stp_q_immpre(qt1, qt2, &mem_ptr_reg);
  assert(43.8f == res_f64[2]);
  assert(43.9f == res_f64[3]);
  assert(44.0f == res_f64[4]);
  assert(44.1f == res_f64[5]);
  assert(res_f64 + 2 == mem_ptr_reg);
  printf("ok STP <Qt1>, <Qt2>, [<Xn|SP>, #<imm>]!\n");
}
// STP <Qt1>, <Qt2>, [<Xn|SP>], #<imm>
void test_stp_q_imm_post() {
  double res_f64[100] = {0};
  double a1 = 1.2f;
  double a2 = 12.3f;
  double b1 = 123.4f;
  double b2 = 1234.5f;
  double *mem_ptr_reg = res_f64;
  uint64x2_t qt1 = vcombine_u64(vcreate_u64(*((uint64_t *) &a1)), vcreate_u64(*((uint64_t *) &a2)));
  uint64x2_t qt2 = vcombine_u64(vcreate_u64(*((uint64_t *) &b1)), vcreate_u64(*((uint64_t *) &b2)));
  stp_q_imm_post(qt1, qt2, &mem_ptr_reg);
  assert(1.2f == res_f64[0]);
  assert(12.3f == res_f64[1]);
  assert(123.4f == res_f64[2]);
  assert(1234.5f == res_f64[3]);
  assert(res_f64 + 2 == mem_ptr_reg);
  printf("ok STP <Qt1>, <Qt2>, [<Xn|SP>], #<imm>\n");
}
// MOV  <Vd>.<Ts>[<index1>], <Vn>.<Ts>[<index2>]
void test_mov_ins_v_v() {
  double a1 = 44.2f;
  double a2 = 44.3f;
  double b1 = 44.4f;
  double b2 = 44.5f;
  uint64x2_t qt1 = vcombine_u64(vcreate_u64(*((uint64_t *) &a1)), vcreate_u64(*((uint64_t *) &a2)));
  uint64x2_t qt2 = vcombine_u64(vcreate_u64(*((uint64_t *) &b1)), vcreate_u64(*((uint64_t *) &b2)));
  mov_ins_v_v(&qt1, qt2);
  assert(44.4f == vgetq_lane_f64(qt1, 1));
  printf("ok MOV  <Vd>.<Ts>[<index1>], <Vn>.<Ts>[<index2>]\n");
}
// SWP <Ws>, <Wt>, [<Xn|SP>]
void test_swp_word() {
  uint32_t ws = 0;
  uint32_t wt = 12;
  uint32_t mem = 123;
  swp_word(&ws, wt, &mem);
  assert(123 == ws);
  assert(12 == mem);
  printf("ok SWP <Ws>, <Wt>, [<Xn|SP>]\n");
}
// SWP <Xs>, <Xt>, [<Xn|SP>]
void test_swp_doubleword() {
  uint64_t xs = 0;
  uint64_t xt = 12;
  uint64_t mem = 123;
  swp_doubleword(&xs, xt, &mem);
  assert(123 == xs);
  assert(12 == mem);
  printf("ok SWP <Xs>, <Xt>, [<Xn|SP>]\n");
}
// SWPA <Ws>, <Wt>, [<Xn|SP>]
void test_swpa_word() {
  uint32_t ws = 0;
  uint32_t wt = 12;
  uint32_t mem = 123;
  swpa_word(&ws, wt, &mem);
  assert(123 == ws);
  assert(12 == mem);
  printf("ok SWPA <Ws>, <Wt>, [<Xn|SP>]\n");
}
// SWPA <Xs>, <Xt>, [<Xn|SP>]
void test_swpa_doubleword() {
  uint64_t xs = 0;
  uint64_t xt = 12;
  uint64_t mem = 123;
  swpa_doubleword(&xs, xt, &mem);
  assert(123 == xs);
  assert(12 == mem);
  printf("ok SWPA <Xs>, <Xt>, [<Xn|SP>]\n");
}
// SWPL <Ws>, <Wt>, [<Xn|SP>]
void test_swpl_word() {
  uint32_t ws = 0;
  uint32_t wt = 12;
  uint32_t mem = 123;
  swpl_word(&ws, wt, &mem);
  assert(123 == ws);
  assert(12 == mem);
  printf("ok SWPL <Ws>, <Wt>, [<Xn|SP>]\n");
}
// SWPL <Xs>, <Xt>, [<Xn|SP>]
void test_swpl_doubleword() {
  uint64_t xs = 0;
  uint64_t xt = 12;
  uint64_t mem = 123;
  swpl_doubleword(&xs, xt, &mem);
  assert(123 == xs);
  assert(12 == mem);
  printf("ok SWPL <Xs>, <Xt>, [<Xn|SP>]\n");
}
// LDR <Bt>, [<Xn|SP>, (<Wm>|<Xm>), <extend> {<amount>}]
void test_ldr_byte() {
  uint8x8_t qt2 = vcreate_u8(0);
  uint8x8_t bt = vcreate_u8(0);
  uint64_t xm_off = 3;
  qt2 = vset_lane_u8(0b1, qt2, 1);
  qt2 = vset_lane_u8(0b11, qt2, 2);
  qt2 = vset_lane_u8(0b111, qt2, 3);
  qt2 = vset_lane_u8(0b1111, qt2, 4);
  qt2 = vset_lane_u8(0b11111, qt2, 5);
  qt2 = vset_lane_u8(0b111111, qt2, 6);
  qt2 = vset_lane_u8(0b1001011, qt2, 7);
  ldr_byte(&bt, &qt2, xm_off);
  assert(vget_lane_u8(bt, 0) == 0b111);
  printf("ok LDR <Bt>, [<Xn|SP>, (<Wm>|<Xm>), <extend> {<amount>}]\n");
}
// LDADD  <Ws>, <Wt>, [<Xn|SP>]
void test_ldadd_word() {
  uint32_t ws = 0;
  uint32_t wt = 12;
  uint32_t mem = 123;
  ldadd_word(&ws, wt, &mem);
  assert(123 == ws);
  assert(135 == mem);
  printf("ok LDADD  <Ws>, <Wt>, [<Xn|SP>]\n");
}
// LDADD <Xs>, <Xt>, [<Xn|SP>]
void test_ldadd_doubleword() {
  uint64_t xs = 0;
  uint64_t xt = 12;
  uint64_t mem = 123;
  ldadd_doubleword(&xs, xt, &mem);
  assert(123 == xs);
  assert(135 == mem);
  printf("ok LDADD <Xs>, <Xt>, [<Xn|SP>]\n");
}
// LDADDA <Ws>, <Wt>, [<Xn|SP>]
void test_ldadda_word() {
  uint32_t ws = 0;
  uint32_t wt = 12;
  uint32_t mem = 123;
  ldadda_word(&ws, wt, &mem);
  assert(123 == ws);
  assert(135 == mem);
  printf("ok LDADDA <Ws>, <Wt>, [<Xn|SP>]\n");
}
// LDADDA <Xs>, <Xt>, [<Xn|SP>]
void test_ldadda_doubleword() {
  uint64_t xs = 0;
  uint64_t xt = 12;
  uint64_t mem = 123;
  ldadda_doubleword(&xs, xt, &mem);
  assert(123 == xs);
  assert(135 == mem);
  printf("ok LDADDA <Xs>, <Xt>, [<Xn|SP>]\n");
}
// LDADDL <Ws>, <Wt>, [<Xn|SP>]
void test_ldaddl_word() {
  uint32_t ws = 0;
  uint32_t wt = 12;
  uint32_t mem = 123;
  ldaddl_word(&ws, wt, &mem);
  assert(123 == ws);
  assert(135 == mem);
  printf("ok LDADDL <Ws>, <Wt>, [<Xn|SP>]\n");
}
// LDADDL <Xs>, <Xt>, [<Xn|SP>]
void test_ldaddl_doubleword() {
  uint64_t xs = 0;
  uint64_t xt = 12;
  uint64_t mem = 123;
  ldaddl_doubleword(&xs, xt, &mem);
  assert(123 == xs);
  assert(135 == mem);
  printf("ok LDADDL <Xs>, <Xt>, [<Xn|SP>]\n");
}
// LDADDAL <Ws>, <Wt>, [<Xn|SP>]
void test_ldaddal_word() {
  uint32_t ws = 0;
  uint32_t wt = 12;
  uint32_t mem = 123;
  ldaddal_word(&ws, wt, &mem);
  assert(123 == ws);
  assert(135 == mem);
  printf("ok LDADDAL <Ws>, <Wt>, [<Xn|SP>]\n");
}
// LDADDAL <Xs>, <Xt>, [<Xn|SP>]
void test_ldaddal_doubleword() {
  uint64_t xs = 0;
  uint64_t xt = 12;
  uint64_t mem = 123;
  ldaddal_doubleword(&xs, xt, &mem);
  assert(123 == xs);
  assert(135 == mem);
  printf("ok LDADDAL <Ws>, <Wt>, [<Xn|SP>]\n");
}
// LDSET <Ws>, <Wt>, [<Xn|SP>]
void test_ldset_word() {
  uint32_t ws = 0;
  uint32_t wt = 12;
  uint32_t mem = 123;
  ldset_word(&ws, wt, &mem);
  assert(123 == ws);
  assert(127 == mem);
  printf("ok LDSET <Ws>, <Wt>, [<Xn|SP>]\n");
}
// LDSET <Xs>, <Xt>, [<Xn|SP>]
void test_ldset_doubleword() {
  uint64_t xs = 0;
  uint64_t xt = 12;
  uint64_t mem = 123;
  ldset_doubleword(&xs, xt, &mem);
  assert(123 == xs);
  assert(127 == mem);
  printf("ok LDSET <Xs>, <Xt>, [<Xn|SP>]\n");
}
// LDSETA <Ws>, <Wt>, [<Xn|SP>]
void test_ldseta_word() {
  uint32_t ws = 0;
  uint32_t wt = 12;
  uint32_t mem = 123;
  ldseta_word(&ws, wt, &mem);
  assert(123 == ws);
  assert(127 == mem);
  printf("ok LDSETA <Ws>, <Wt>, [<Xn|SP>]\n");
}
// LDSETA <Xs>, <Xt>, [<Xn|SP>]
void test_ldseta_doubleword() {
  uint64_t xs = 0;
  uint64_t xt = 12;
  uint64_t mem = 123;
  ldseta_doubleword(&xs, xt, &mem);
  assert(123 == xs);
  assert(127 == mem);
  printf("ok LDSETA <Xs>, <Xt>, [<Xn|SP>]\n");
}
// LDSETL <Ws>, <Wt>, [<Xn|SP>]
void test_ldsetl_word() {
  uint32_t ws = 0;
  uint32_t wt = 12;
  uint32_t mem = 123;
  ldsetl_word(&ws, wt, &mem);
  assert(123 == ws);
  assert(127 == mem);
  printf("ok LDSETL <Ws>, <Wt>, [<Xn|SP>]\n");
}
// LDSETL <Xs>, <Xt>, [<Xn|SP>]
void test_ldsetl_doubleword() {
  uint64_t xs = 0;
  uint64_t xt = 12;
  uint64_t mem = 123;
  ldsetl_doubleword(&xs, xt, &mem);
  assert(123 == xs);
  assert(127 == mem);
  printf("ok LDSETL <Xs>, <Xt>, [<Xn|SP>]\n");
}
// LDSETAL <Ws>, <Wt>, [<Xn|SP>]
void test_ldsetal_word() {
  uint32_t ws = 0;
  uint32_t wt = 12;
  uint32_t mem = 123;
  ldsetal_word(&ws, wt, &mem);
  assert(123 == ws);
  assert(127 == mem);
  printf("ok LDSETAL <Ws>, <Wt>, [<Xn|SP>]\n");
}
// LDSETAL <Xs>, <Xt>, [<Xn|SP>]
void test_ldsetal_doubleword() {
  uint64_t xs = 0;
  uint64_t xt = 12;
  uint64_t mem = 123;
  ldsetal_doubleword(&xs, xt, &mem);
  assert(123 == xs);
  assert(127 == mem);
  printf("ok LDSETAL <Xs>, <Xt>, [<Xn|SP>]\n");
}
// CAS <Ws>, <Wt>, [<Xn|SP>{,#0}]
void test_cas_word() {
  // ws != mem
  {
    uint32_t ws = 0;
    uint32_t wt = 12;
    uint32_t mem = 123;
    cas_word(&ws, wt, &mem);
    assert(123 == ws);
    assert(123 == mem);
  }
  // ws == mem
  {
    uint32_t ws = 123;
    uint32_t wt = 12;
    uint32_t mem = 123;
    cas_word(&ws, wt, &mem);
    assert(123 == ws);
    assert(12 == mem);
  }
  printf("ok CAS <Ws>, <Wt>, [<Xn|SP>{,#0}]\n");
}
// CAS <Xs>, <Xt>, [<Xn|SP>{,#0}]
void test_cas_doubleword() {
  // xs != mem
  {
    uint64_t xs = 0;
    uint64_t xt = 12;
    uint64_t mem = 123;
    cas_doubleword(&xs, xt, &mem);
    assert(123 == xs);
    assert(123 == mem);
  }
  // xs == mem
  {
    uint64_t xs = 123;
    uint64_t xt = 12;
    uint64_t mem = 123;
    cas_doubleword(&xs, xt, &mem);
    assert(123 == xs);
    assert(12 == mem);
  }
  printf("ok CAS <Xs>, <Xt>, [<Xn|SP>{,#0}]\n");
}
// CASA <Ws>, <Wt>, [<Xn|SP>{,#0}]
void test_casa_word() {
  // ws != mem
  {
    uint32_t ws = 0;
    uint32_t wt = 12;
    uint32_t mem = 123;
    casa_word(&ws, wt, &mem);
    assert(123 == ws);
    assert(123 == mem);
  }
  // ws == mem
  {
    uint32_t ws = 123;
    uint32_t wt = 12;
    uint32_t mem = 123;
    casa_word(&ws, wt, &mem);
    assert(123 == ws);
    assert(12 == mem);
  }
  printf("ok CASA <Ws>, <Wt>, [<Xn|SP>{,#0}]\n");
}
// CASA <Xs>, <Xt>, [<Xn|SP>{,#0}]
void test_casa_doubleword() {
  // xs != mem
  {
    uint64_t xs = 0;
    uint64_t xt = 12;
    uint64_t mem = 123;
    casa_doubleword(&xs, xt, &mem);
    assert(123 == xs);
    assert(123 == mem);
  }
  // xs == mem
  {
    uint64_t xs = 123;
    uint64_t xt = 12;
    uint64_t mem = 123;
    casa_doubleword(&xs, xt, &mem);
    assert(123 == xs);
    assert(12 == mem);
  }
  printf("ok CASA <Xs>, <Xt>, [<Xn|SP>{,#0}]\n");
}
// CASAL <Ws>, <Wt>, [<Xn|SP>{,#0}]
void test_casal_word() {
  // ws != mem
  {
    uint32_t ws = 0;
    uint32_t wt = 12;
    uint32_t mem = 123;
    casal_word(&ws, wt, &mem);
    assert(123 == ws);
    assert(123 == mem);
  }
  // ws == mem
  {
    uint32_t ws = 123;
    uint32_t wt = 12;
    uint32_t mem = 123;
    casal_word(&ws, wt, &mem);
    assert(123 == ws);
    assert(12 == mem);
  }
  printf("ok CASAL <Ws>, <Wt>, [<Xn|SP>{,#0}]\n");
}
// CASAL <Xs>, <Xt>, [<Xn|SP>{,#0}]
void test_casal_doubleword() {
  // xs != mem
  {
    uint64_t xs = 0;
    uint64_t xt = 12;
    uint64_t mem = 123;
    casal_doubleword(&xs, xt, &mem);
    assert(123 == xs);
    assert(123 == mem);
  }
  // xs == mem
  {
    uint64_t xs = 123;
    uint64_t xt = 12;
    uint64_t mem = 123;
    casal_doubleword(&xs, xt, &mem);
    assert(123 == xs);
    assert(12 == mem);
  }
  printf("ok CASAL <Xs>, <Xt>, [<Xn|SP>{,#0}]\n");
}
// CASL <Ws>, <Wt>, [<Xn|SP>{,#0}]
void test_casl_word() {
  // ws != mem
  {
    uint32_t ws = 0;
    uint32_t wt = 12;
    uint32_t mem = 123;
    casl_word(&ws, wt, &mem);
    assert(123 == ws);
    assert(123 == mem);
  }
  // ws == mem
  {
    uint32_t ws = 123;
    uint32_t wt = 12;
    uint32_t mem = 123;
    casl_word(&ws, wt, &mem);
    assert(123 == ws);
    assert(12 == mem);
  }
  printf("ok CASL <Ws>, <Wt>, [<Xn|SP>{,#0}]\n");
}
// CASL <Xs>, <Xt>, [<Xn|SP>{,#0}]
void test_casl_doubleword() {
  // xs != mem
  {
    uint64_t xs = 0;
    uint64_t xt = 12;
    uint64_t mem = 123;
    casl_doubleword(&xs, xt, &mem);
    assert(123 == xs);
    assert(123 == mem);
  }
  // xs == mem
  {
    uint64_t xs = 123;
    uint64_t xt = 12;
    uint64_t mem = 123;
    casl_doubleword(&xs, xt, &mem);
    assert(123 == xs);
    assert(12 == mem);
  }
  printf("ok CASL <Xs>, <Xt>, [<Xn|SP>{,#0}]\n");
}
// LDURSH <Xt>, [<Xn|SP>{, #<simm>}]
void test_ldursh_doubleword() {
  uint64_t xt = 0;
  uint64_t mem[10];
  mem[1] = 12;
  ldursh_doubleword_preimm(&xt, mem);
  assert(12 == xt);
  printf("ok LDURSH <Xt>, [<Xn|SP>{, #<simm>}]\n");
}
// BIC <Vd>.<T>, #<imm8>{, LSL #<amount>}
void test_bic_asimd_imm() {
  uint16_t elems[4] = {1, 12, 123, 1234};
  uint16x4_t qt1 = vmov_n_u16(elems[0]);
  qt1 = vset_lane_u16(elems[1], qt1, 1);
  qt1 = vset_lane_u16(elems[2], qt1, 2);
  qt1 = vset_lane_u16(elems[3], qt1, 3);
  bic_asimd_imm(&qt1);
  uint16_t rhs = ~(12 << 8);
  assert((1 & rhs) == vget_lane_u16(qt1, 0));
  assert((12 & rhs) == vget_lane_u16(qt1, 1));
  assert((123 & rhs) == vget_lane_u16(qt1, 2));
  assert((1234 & rhs) == vget_lane_u16(qt1, 3));
  printf("ok BIC <Vd>.<T>, #<imm8>{, LSL #<amount>}\n");
}
// LD1R { <Vt>.<T> }, [<Xn|SP>] (T = 4H)
void test_ld1r_4h() {
  uint16_t elems[4] = {1, 12, 123, 1234};
  uint16x4_t qt1 = vmov_n_u16(elems[0]);
  qt1 = vset_lane_u16(elems[1], qt1, 1);
  qt1 = vset_lane_u16(elems[2], qt1, 2);
  qt1 = vset_lane_u16(elems[3], qt1, 3);
  uint16_t mem = 16;
  ld1r_4h(&qt1, &mem);
  assert(16 == vget_lane_u16(qt1, 0));
  assert(16 == vget_lane_u16(qt1, 1));
  assert(16 == vget_lane_u16(qt1, 2));
  assert(16 == vget_lane_u16(qt1, 3));
  printf("ok LD1R { <Vt>.<T> }, [<Xn|SP>] (T = 4H)\n");
}
// LD1R { <Vt>.<T> }, [<Xn|SP>] (T = 4S)
void test_ld1r_4s() {
  uint32_t elems[4] = {1, 12, 123, 1234};
  uint32x4_t qt1 = vmovq_n_u32(elems[0]);
  qt1 = vsetq_lane_u32(elems[1], qt1, 1);
  qt1 = vsetq_lane_u32(elems[2], qt1, 2);
  qt1 = vsetq_lane_u32(elems[3], qt1, 3);
  uint32_t mem = 16;
  ld1r_4s(&qt1, &mem);
  assert(16 == vgetq_lane_u32(qt1, 0));
  assert(16 == vgetq_lane_u32(qt1, 1));
  assert(16 == vgetq_lane_u32(qt1, 2));
  assert(16 == vgetq_lane_u32(qt1, 3));
  printf("ok LD1R { <Vt>.<T> }, [<Xn|SP>] (T = 4S)\n");
}
// STXR <Ws>, <Wt>, [<Xn|SP>{,#0}]
void test_stxr_word() {
  uint32_t ws1 = 2;  // for LDXR
  uint32_t w_status = 12;
  uint32_t wt = 123;
  uint32_t mem = 1234;
  stxr_word(&ws1, &w_status, wt, &mem);
  assert(1234 == ws1);
  assert(0 == w_status);
  assert(123 == mem);
  printf("ok STXR <Ws>, <Wt>, [<Xn|SP>{,#0}]\n");
}
// STXR <Ws>, <Xt>, [<Xn|SP>{,#0}]
void test_stxr_doubleword() {
  uint64_t xs1 = 2;  // for LDXR
  uint32_t w_status = 12;
  uint64_t xt = 123;
  uint64_t mem = 1234;
  stxr_doubleword(&xs1, &w_status, xt, &mem);
  assert(1234 == xs1);
  assert(0 == w_status);
  assert(123 == mem);
  printf("ok STXR <Ws>, <Xt>, [<Xn|SP>{,#0}]\n");
}
// DC <dc_op>, <Xt> (dc_op = zva)
void test_dc_zva() {
  uint64_t mem[16];
  for (int i = 0; i < 16; i++)
    mem[i] = 12;
  dc_zva(mem);
  assert(0 == mem[0]);
  printf("ok DC <dc_op>, <Xt> (dc_op = zva)\n");
}
// CNT  <Vd>.<T>, <Vn>.<T> (T = 8B)
void test_cnt_vector_8b() {
  uint8x8_t qt1 = vcreate_u8(0);
  uint8x8_t qt2 = vcreate_u8(0);
  qt2 = vset_lane_u8(0b1, qt2, 1);
  qt2 = vset_lane_u8(0b11, qt2, 2);
  qt2 = vset_lane_u8(0b111, qt2, 3);
  qt2 = vset_lane_u8(0b1111, qt2, 4);
  qt2 = vset_lane_u8(0b11111, qt2, 5);
  qt2 = vset_lane_u8(0b111111, qt2, 6);
  qt2 = vset_lane_u8(0b1001011, qt2, 7);
  cnt_vector_8b(&qt1, qt2);
  assert(0 == vget_lane_u8(qt1, 0));
  assert(1 == vget_lane_u8(qt1, 1));
  assert(2 == vget_lane_u8(qt1, 2));
  assert(3 == vget_lane_u8(qt1, 3));
  assert(4 == vget_lane_u8(qt1, 4));
  assert(5 == vget_lane_u8(qt1, 5));
  assert(6 == vget_lane_u8(qt1, 6));
  assert(4 == vget_lane_u8(qt1, 7));
  printf("ok CNT  <Vd>.<T>, <Vn>.<T> (T = 8B)\n");
}
// CNT  <Vd>.<T>, <Vn>.<T> (T = 16B)
void test_cnt_vector_16b() {
  uint8x16_t qt1 = vcombine_u8(vcreate_u8(0), vcreate_u8(0));
  uint8x16_t qt2 = vcombine_u8(vcreate_u8(0), vcreate_u8(0));
  qt2 = vsetq_lane_u8(0b1, qt2, 1);
  qt2 = vsetq_lane_u8(0b11, qt2, 2);
  qt2 = vsetq_lane_u8(0b111, qt2, 3);
  qt2 = vsetq_lane_u8(0b1111, qt2, 4);
  qt2 = vsetq_lane_u8(0b11111, qt2, 5);
  qt2 = vsetq_lane_u8(0b111111, qt2, 6);
  qt2 = vsetq_lane_u8(0b1111111, qt2, 7);
  qt2 = vsetq_lane_u8(0b11111111, qt2, 8);
  qt2 = vsetq_lane_u8(0b11111110, qt2, 9);
  qt2 = vsetq_lane_u8(0b11111100, qt2, 10);
  qt2 = vsetq_lane_u8(0b11111000, qt2, 11);
  qt2 = vsetq_lane_u8(0b11110000, qt2, 12);
  qt2 = vsetq_lane_u8(0b11100000, qt2, 13);
  qt2 = vsetq_lane_u8(0b11000000, qt2, 14);
  qt2 = vsetq_lane_u8(0b01101101, qt2, 15);
  cnt_vector_16b(&qt1, qt2);
  assert(0 == vgetq_lane_u8(qt1, 0));
  assert(1 == vgetq_lane_u8(qt1, 1));
  assert(2 == vgetq_lane_u8(qt1, 2));
  assert(3 == vgetq_lane_u8(qt1, 3));
  assert(4 == vgetq_lane_u8(qt1, 4));
  assert(5 == vgetq_lane_u8(qt1, 5));
  assert(6 == vgetq_lane_u8(qt1, 6));
  assert(7 == vgetq_lane_u8(qt1, 7));
  assert(8 == vgetq_lane_u8(qt1, 8));
  assert(7 == vgetq_lane_u8(qt1, 9));
  assert(6 == vgetq_lane_u8(qt1, 10));
  assert(5 == vgetq_lane_u8(qt1, 11));
  assert(4 == vgetq_lane_u8(qt1, 12));
  assert(3 == vgetq_lane_u8(qt1, 13));
  assert(2 == vgetq_lane_u8(qt1, 14));
  assert(5 == vgetq_lane_u8(qt1, 15));
  printf("ok CNT  <Vd>.<T>, <Vn>.<T> (T = 16B)\n");
}
/* 
  COND.c
*/
// FCSEL  <Dd>, <Dn>, <Dm>, <cond>
void test_fcsel_double() {
  // ge
  {
    uint32_t r1 = 13;
    uint32_t r2 = 12;
    double dd = 0;
    double dn = 12.3;
    double dm = 123.4;
    fcsel_double_ge(r1, r2, &dd, dn, dm);
    assert(12.3 == dd);
  }
  {
    uint32_t r1 = 11;
    uint32_t r2 = 12;
    double dd = 0;
    double dn = 12.3;
    double dm = 123.4;
    fcsel_double_ge(r1, r2, &dd, dn, dm);
    assert(123.4 == dd);
  }
  // gt
  {
    uint32_t r1 = 13;
    uint32_t r2 = 12;
    double dd = 0;
    double dn = 12.3;
    double dm = 123.4;
    fcsel_double_gt(r1, r2, &dd, dn, dm);
    assert(12.3 == dd);
  }
  {
    uint32_t r1 = 12;
    uint32_t r2 = 12;
    double dd = 0;
    double dn = 12.3;
    double dm = 123.4;
    fcsel_double_gt(r1, r2, &dd, dn, dm);
    assert(123.4 == dd);
  }
  // le
  {
    uint32_t r1 = 11;
    uint32_t r2 = 12;
    double dd = 0;
    double dn = 12.3;
    double dm = 123.4;
    fcsel_double_le(r1, r2, &dd, dn, dm);
    assert(12.3 == dd);
  }
  {
    uint32_t r1 = 13;
    uint32_t r2 = 12;
    double dd = 0;
    double dn = 12.3;
    double dm = 123.4;
    fcsel_double_le(r1, r2, &dd, dn, dm);
    assert(123.4 == dd);
  }
  // lt
  {
    uint32_t r1 = 11;
    uint32_t r2 = 12;
    double dd = 0;
    double dn = 12.3;
    double dm = 123.4;
    fcsel_double_lt(r1, r2, &dd, dn, dm);
    assert(12.3 == dd);
  }
  {
    uint32_t r1 = 12;
    uint32_t r2 = 12;
    double dd = 0;
    double dn = 12.3;
    double dm = 123.4;
    fcsel_double_lt(r1, r2, &dd, dn, dm);
    assert(123.4 == dd);
  }
  // eq
  {
    uint32_t r1 = 12;
    uint32_t r2 = 12;
    double dd = 0;
    double dn = 12.3;
    double dm = 123.4;
    fcsel_double_eq(r1, r2, &dd, dn, dm);
    assert(12.3 == dd);
  }
  {
    uint32_t r1 = 11;
    uint32_t r2 = 12;
    double dd = 0;
    double dn = 12.3;
    double dm = 123.4;
    fcsel_double_eq(r1, r2, &dd, dn, dm);
    assert(123.4 == dd);
  }
  // ne
  {
    uint32_t r1 = 11;
    uint32_t r2 = 12;
    double dd = 0;
    double dn = 12.3;
    double dm = 123.4;
    fcsel_double_ne(r1, r2, &dd, dn, dm);
    assert(12.3 == dd);
  }
  {
    uint32_t r1 = 12;
    uint32_t r2 = 12;
    double dd = 0;
    double dn = 12.3;
    double dm = 123.4;
    fcsel_double_ne(r1, r2, &dd, dn, dm);
    assert(123.4 == dd);
  }
  // cs
  {
    uint32_t r1 = 1 << 31;
    uint32_t r2 = 1 << 31;
    double dd = 0;
    double dn = 12.3;
    double dm = 123.4;
    fcsel_double_cs(r1, r2, &dd, dn, dm);
    assert(12.3 == dd);
  }
  {
    uint32_t r1 = 1 << 30;
    uint32_t r2 = 1 << 31;
    double dd = 0;
    double dn = 12.3;
    double dm = 123.4;
    fcsel_double_cs(r1, r2, &dd, dn, dm);
    assert(123.4 == dd);
  }
  // cc
  {
    uint32_t r1 = 1 << 30;
    uint32_t r2 = 1 << 31;
    double dd = 0;
    double dn = 12.3;
    double dm = 123.4;
    fcsel_double_cc(r1, r2, &dd, dn, dm);
    assert(12.3 == dd);
  }
  {
    uint32_t r1 = 1 << 31;
    uint32_t r2 = 1 << 31;
    double dd = 0;
    double dn = 12.3;
    double dm = 123.4;
    fcsel_double_cc(r1, r2, &dd, dn, dm);
    assert(123.4 == dd);
  }
  // mi
  {
    int r1 = -3;
    int r2 = 1;
    double dd = 0;
    double dn = 12.3;
    double dm = 123.4;
    fcsel_double_mi(r1, r2, &dd, dn, dm);
    assert(12.3 == dd);
  }
  {
    int r1 = 3;
    int r2 = -1;
    double dd = 0;
    double dn = 12.3;
    double dm = 123.4;
    fcsel_double_mi(r1, r2, &dd, dn, dm);
    assert(123.4 == dd);
  }
  // pl
  {
    int r1 = -1;
    int r2 = 1;
    double dd = 0;
    double dn = 12.3;
    double dm = 123.4;
    fcsel_double_pl(r1, r2, &dd, dn, dm);
    assert(12.3 == dd);
  }
  {
    int r1 = -3;
    int r2 = 1;
    double dd = 0;
    double dn = 12.3;
    double dm = 123.4;
    fcsel_double_pl(r1, r2, &dd, dn, dm);
    assert(123.4 == dd);
  }
  // vs
  {
    int r1 = 1 << 30;
    int r2 = 1 << 30;
    double dd = 0;
    double dn = 12.3;
    double dm = 123.4;
    fcsel_double_vs(r1, r2, &dd, dn, dm);
    assert(12.3 == dd);
  }
  {
    int r1 = 1 << 29;
    int r2 = 1 << 30;
    double dd = 0;
    double dn = 12.3;
    double dm = 123.4;
    fcsel_double_vs(r1, r2, &dd, dn, dm);
    assert(123.4 == dd);
  }
  // vc
  {
    int r1 = 1 << 29;
    int r2 = 1 << 30;
    double dd = 0;
    double dn = 12.3;
    double dm = 123.4;
    fcsel_double_vc(r1, r2, &dd, dn, dm);
    assert(12.3 == dd);
  }
  {
    int r1 = 1 << 30;
    int r2 = 1 << 30;
    double dd = 0;
    double dn = 12.3;
    double dm = 123.4;
    fcsel_double_vc(r1, r2, &dd, dn, dm);
    assert(123.4 == dd);
  }
  // hi
  {
    uint32_t r1 = 1 << 31;
    uint32_t r2 = 1 << 30;
    double dd = 0;
    double dn = 12.3;
    double dm = 123.4;
    fcsel_double_hi(r1, r2, &dd, dn, dm);
    assert(12.3 == dd);
  }
  {
    uint32_t r1 = 1 << 30;
    uint32_t r2 = 1 << 31;
    double dd = 0;
    double dn = 12.3;
    double dm = 123.4;
    fcsel_double_hi(r1, r2, &dd, dn, dm);
    assert(123.4 == dd);
  }
  // ls
  {
    uint32_t r1 = 1 << 30;
    uint32_t r2 = 1 << 31;
    double dd = 0;
    double dn = 12.3;
    double dm = 123.4;
    fcsel_double_ls(r1, r2, &dd, dn, dm);
    assert(12.3 == dd);
  }
  {
    uint32_t r1 = 1 << 31;
    uint32_t r2 = 1 << 30;
    double dd = 0;
    double dn = 12.3;
    double dm = 123.4;
    fcsel_double_ls(r1, r2, &dd, dn, dm);
    assert(123.4 == dd);
  }
  printf("ok FCSEL  <Dd>, <Dn>, <Dm>, <cond>\n");
}
/*
  MISC.c
*/
// PRFM  (<prfop>|#<imm5>), [<Xn|SP>{, #<pimm>}]
void test_prfm_pldl1keep() {
  uint64_t mem[10];
  for (int i = 0; i < 10; i++)
    mem[i] = i;
  prfm_pldl1keep(mem);
  for (int i = 0; i < 10; i++)
    assert(i == mem[i]);
  printf("ok PRFM  (<prfop>|#<imm5>), [<Xn|SP>{, #<pimm>}]\n");
}
/*
  SIMD.c
*/
// CMGE  <V><d>, <V><n>, #0
void test_cmge_onlyd() {
  int64x2_t qt1 = vcombine_s64(vcreate_s64(1), vcreate_s64(1));
  int64x2_t qt2 = vcombine_s64(vcreate_s64(10), vcreate_s64(-10));
  cmge_onlyd(&qt1, qt2);
  assert(vgetq_lane_s64(qt1, 0) == UINT64_MAX);
  assert(vgetq_lane_s64(qt1, 1) == 0);
  printf("ok CMGE  <V><d>, <V><n>, #0\n");
}
// DUP  <Vd>.<T>, <Vn>.<Ts>[<index>]
void test_dup_vector() {
  uint64x2_t qt1 = vcombine_u64(vcreate_u64(1), vcreate_u64(2));
  uint64x2_t qt2 = vcombine_u64(vcreate_u64(12), vcreate_u64(123));
  dup_vector(&qt1, qt2);
  assert(123 == vgetq_lane_u64(qt1, 0));
  assert(123 == vgetq_lane_u64(qt1, 1));
  printf("ok DUP  <Vd>.<T>, <Vn>.<Ts>[<index>]\n");
}
// FMLA  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
void test_fmla_vector() {
  float32x4_t qt1 = vcombine_f32(vcreate_f32(0), vcreate_f32(0));
  qt1 = vsetq_lane_f32(1, qt1, 0);
  qt1 = vsetq_lane_f32(2, qt1, 1);
  qt1 = vsetq_lane_f32(3, qt1, 2);
  qt1 = vsetq_lane_f32(4, qt1, 3);
  float32x4_t qt2 = vcombine_f32(vcreate_f32(0), vcreate_f32(0));
  qt2 = vsetq_lane_f32(1.25, qt2, 0);
  qt2 = vsetq_lane_f32(2.25, qt2, 1);
  qt2 = vsetq_lane_f32(3.25, qt2, 2);
  qt2 = vsetq_lane_f32(4.25, qt2, 3);
  float32x4_t qt3 = vcombine_f32(vcreate_f32(0), vcreate_f32(0));
  qt3 = vsetq_lane_f32(2.25, qt3, 0);
  qt3 = vsetq_lane_f32(3.25, qt3, 1);
  qt3 = vsetq_lane_f32(4.25, qt3, 2);
  qt3 = vsetq_lane_f32(5.25, qt3, 3);
  fmla_vector(&qt1, qt2, qt3);
  assert(3.8125 == vgetq_lane_f32(qt1, 0));
  assert(9.3125 == vgetq_lane_f32(qt1, 1));
  assert(16.8125 == vgetq_lane_f32(qt1, 2));
  assert(26.3125 == vgetq_lane_f32(qt1, 3));
  printf("ok FMLA  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>\n");
}
// FADD  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
void test_fadd_vector() {
  float32x4_t qt1;
  float32x4_t qt2 = vcombine_f32(vcreate_f32(0), vcreate_f32(0));
  qt2 = vsetq_lane_f32(1.25, qt2, 0);
  qt2 = vsetq_lane_f32(2.25, qt2, 1);
  qt2 = vsetq_lane_f32(3.25, qt2, 2);
  qt2 = vsetq_lane_f32(4.25, qt2, 3);
  float32x4_t qt3 = vcombine_f32(vcreate_f32(0), vcreate_f32(0));
  qt3 = vsetq_lane_f32(2.25, qt3, 0);
  qt3 = vsetq_lane_f32(3.25, qt3, 1);
  qt3 = vsetq_lane_f32(4.25, qt3, 2);
  qt3 = vsetq_lane_f32(5.25, qt3, 3);
  fadd_vector(&qt1, qt2, qt3);
  assert(3.5 == vgetq_lane_f32(qt1, 0));
  assert(5.5 == vgetq_lane_f32(qt1, 1));
  assert(7.5 == vgetq_lane_f32(qt1, 2));
  assert(9.5 == vgetq_lane_f32(qt1, 3));
  printf("ok FADD  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>\n");
}
// FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
void test_fmul_vector() {
  float32x4_t qt1;
  float32x4_t qt2 = vcombine_f32(vcreate_f32(0), vcreate_f32(0));
  qt2 = vsetq_lane_f32(1.25, qt2, 0);
  qt2 = vsetq_lane_f32(2.25, qt2, 1);
  qt2 = vsetq_lane_f32(3.25, qt2, 2);
  qt2 = vsetq_lane_f32(4.25, qt2, 3);
  float32x4_t qt3 = vcombine_f32(vcreate_f32(0), vcreate_f32(0));
  qt3 = vsetq_lane_f32(2.25, qt3, 0);
  qt3 = vsetq_lane_f32(3.25, qt3, 1);
  qt3 = vsetq_lane_f32(4.25, qt3, 2);
  qt3 = vsetq_lane_f32(5.25, qt3, 3);
  fmul_vector(&qt1, qt2, qt3);
  assert(2.8125 == vgetq_lane_f32(qt1, 0));
  assert(7.3125 == vgetq_lane_f32(qt1, 1));
  assert(13.8125 == vgetq_lane_f32(qt1, 2));
  assert(22.3125 == vgetq_lane_f32(qt1, 3));
  printf("ok FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>\n");
}
// FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
void test_fmul_vector_byelem() {
  float32x4_t qt1;
  float32x4_t qt2 = vcombine_f32(vcreate_f32(0), vcreate_f32(0));
  qt2 = vsetq_lane_f32(1.25, qt2, 0);
  qt2 = vsetq_lane_f32(2.25, qt2, 1);
  qt2 = vsetq_lane_f32(3.25, qt2, 2);
  qt2 = vsetq_lane_f32(4.25, qt2, 3);
  float32x4_t qt3 = vcombine_f32(vcreate_f32(0), vcreate_f32(0));
  qt3 = vsetq_lane_f32(2.25, qt3, 0);
  qt3 = vsetq_lane_f32(3.25, qt3, 1);
  qt3 = vsetq_lane_f32(4.25, qt3, 2);
  qt3 = vsetq_lane_f32(5.25, qt3, 3);
  fmul_vector_byelem(&qt1, qt2, qt3);
  assert(5.3125 == vgetq_lane_f32(qt1, 0));
  assert(9.5625 == vgetq_lane_f32(qt1, 1));
  assert(13.8125 == vgetq_lane_f32(qt1, 2));
  assert(18.0625 == vgetq_lane_f32(qt1, 3));
  printf("ok FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]\n");
}
// CMHS  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
void test_cmhs_vector() {
  uint32x4_t qt1;
  uint32x4_t qt2 = vcombine_u32(vcreate_u32(0), vcreate_u32(0));
  qt2 = vsetq_lane_u32(10, qt2, 0);
  qt2 = vsetq_lane_u32(1, qt2, 1);
  qt2 = vsetq_lane_u32(100, qt2, 2);
  qt2 = vsetq_lane_u32(2, qt2, 3);
  uint32x4_t qt3 = vcombine_u32(vcreate_u32(0), vcreate_u32(0));
  qt3 = vsetq_lane_u32(1, qt3, 0);
  qt3 = vsetq_lane_u32(10, qt3, 1);
  qt3 = vsetq_lane_u32(3, qt3, 2);
  qt3 = vsetq_lane_u32(100, qt3, 3);
  cmhs_vector(&qt1, qt2, qt3);
  assert(UINT32_MAX == vgetq_lane_u32(qt1, 0));
  assert(0 == vgetq_lane_u32(qt1, 1));
  assert(UINT32_MAX == vgetq_lane_u32(qt1, 2));
  assert(0 == vgetq_lane_u32(qt1, 3));
  printf("ok CMHS  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>\n");
}
// USHLL  <Vd>.<Ta>, <Vn>.<Tb>, #<shift>
void test_ushll_vector() {
  uint16x4_t qtn = vcreate_u16(0b1);
  qtn = vset_lane_u16(0b111, qtn, 1);
  qtn = vset_lane_u16(0b100, qtn, 2);
  qtn = vset_lane_u16(0b1100, qtn, 3);
  uint32x4_t qtd = vcombine_u32(vcreate_u32(0), vcreate_u32(0));
  ushll_vector(&qtd, qtn);
  assert(0b10 == vgetq_lane_u32(qtd, 0));
  assert(0b1110 == vgetq_lane_u32(qtd, 1));
  assert(0b1000 == vgetq_lane_u32(qtd, 2));
  assert(0b11000 == vgetq_lane_u32(qtd, 3));
  assert(0b111 == vget_lane_u16(qtn, 1));
  printf("ok USHLL  <Vd>.<Ta>, <Vn>.<Tb>, #<shift>\n");
}
// USHLL2  <Vd>.<Ta>, <Vn>.<Tb>, #<shift>
void test_ushll2_vector() {
  uint16x8_t qtn = vcombine_u16(vcreate_u16(0), vcreate_u16(0));
  qtn = vsetq_lane_u16(0b1, qtn, 1);
  qtn = vsetq_lane_u16(0b10, qtn, 2);
  qtn = vsetq_lane_u16(0b101, qtn, 3);
  qtn = vsetq_lane_u16(0b1010, qtn, 4);
  qtn = vsetq_lane_u16(0b10101, qtn, 5);
  qtn = vsetq_lane_u16(0b101010, qtn, 6);
  qtn = vsetq_lane_u16(0b1010101, qtn, 7);
  uint32x4_t qtd = vcombine_u32(vcreate_u32(0), vcreate_u32(0));
  ushll2_vector(&qtd, qtn);
  assert(0b101000 == vgetq_lane_u32(qtd, 0));
  assert(0b1010100 == vgetq_lane_u32(qtd, 1));
  assert(0b10101000 == vgetq_lane_u32(qtd, 2));
  assert(0b101010100 == vgetq_lane_u32(qtd, 3));
  assert(0b1 == vgetq_lane_u16(qtn, 1));
  printf("ok USHLL2  <Vd>.<Ta>, <Vn>.<Tb>, #<shift>\n");
}
// SCVTF  <Vd>.<T>, <Vn>.<T> (only 32bit or 64bit)
void test_scvtf_vector() {
  uint32x4_t qtn = vcombine_u32(vcreate_u32(0), vcreate_u32(0));
  qtn = vsetq_lane_u32(0b10, qtn, 1);
  qtn = vsetq_lane_u32(0b1010, qtn, 2);
  qtn = vsetq_lane_u32(0b101010, qtn, 3);
  float32x4_t qtd = vcombine_f32(vcreate_f32(0), vcreate_f32(0));
  scvtf_vector(&qtd, qtn);
  assert(0 == vgetq_lane_f32(qtd, 0));
  assert(2.0 == vgetq_lane_f32(qtd, 1));
  assert(10.0 == vgetq_lane_f32(qtd, 2));
  assert(42.0 == vgetq_lane_f32(qtd, 3));
  printf("ok SCVTF  <Vd>.<T>, <Vn>.<T> (only 32bit or 64bit)\n");
}
// REV32  <Vd>.<T>, <Vn>.<T>
void test_rev32_vector() {
  uint8x8_t qtn = vcreate_u8(0);
  qtn = vset_lane_u8(0x01, qtn, 0);
  qtn = vset_lane_u8(0x23, qtn, 1);
  qtn = vset_lane_u8(0x45, qtn, 2);
  qtn = vset_lane_u8(0x67, qtn, 3);
  qtn = vset_lane_u8(0x89, qtn, 4);
  qtn = vset_lane_u8(0xab, qtn, 5);
  qtn = vset_lane_u8(0xcd, qtn, 6);
  qtn = vset_lane_u8(0xef, qtn, 7);
  uint8x8_t qtd = vcreate_u8(0);
  rev32_vector(&qtd, qtn);
  assert(0x67 == vget_lane_u8(qtd, 0));
  assert(0x45 == vget_lane_u8(qtd, 1));
  assert(0x23 == vget_lane_u8(qtd, 2));
  assert(0x01 == vget_lane_u8(qtd, 3));
  assert(0xef == vget_lane_u8(qtd, 4));
  assert(0xcd == vget_lane_u8(qtd, 5));
  assert(0xab == vget_lane_u8(qtd, 6));
  assert(0x89 == vget_lane_u8(qtd, 7));
  printf("ok REV32  <Vd>.<T>, <Vn>.<T>\n");
}

int main() {
  // BINARY.c
  test_fmsub_float();
  test_fmsub_double();
  test_adc_word();
  test_adc_doubleword();
  test_umsubl();
  test_fsub_vector();
  test_fdiv_vector();
  // CONVERT.c
  test_ucvtf_float();
  test_ucvtf_double();
  test_scvtf_float();
  test_scvtf_double();
  test_frinta_doubleword();
  test_fcvtas_doubleword();
  // DATAFXER.c
  test_st1_simd_d_index();
  test_st1_simd_d_index_postimm();
  test_st1_simd_d_index_postreg();
  test_str_simd_b_simmpost();
  test_str_simd_h_simmpost();
  test_str_simd_s_simmpost();
  test_str_simd_d_simmpost();
  test_str_simd_q_simmpost();
  test_str_simd_b_simmpre();
  test_str_simd_h_simmpre();
  test_str_simd_s_simmpre();
  test_str_simd_d_simmpre();
  test_str_simd_s_regoff();
  test_str_simd_d_regoff();
  test_stlr_x();
  test_stp_q_immpre();
  test_stp_q_imm_post();
  test_mov_ins_v_v();
  test_swp_word();
  test_swp_doubleword();
  test_swpa_word();
  test_swpa_doubleword();
  test_swpl_word();
  test_swpl_doubleword();
  test_ldr_byte();
  test_ldadd_word();
  test_ldadd_doubleword();
  test_ldadda_word();
  test_ldadda_doubleword();
  test_ldaddl_word();
  test_ldaddl_doubleword();
  test_ldaddal_word();
  test_ldaddal_doubleword();
  test_ldset_word();
  test_ldset_doubleword();
  test_ldseta_word();
  test_ldseta_doubleword();
  test_ldsetl_word();
  test_ldsetl_doubleword();
  test_ldsetal_word();
  test_ldsetal_doubleword();
  test_cas_word();
  test_cas_doubleword();
  test_casa_word();
  test_casa_doubleword();
  test_casal_word();
  test_casal_doubleword();
  test_casl_word();
  test_casl_doubleword();
  test_ldursh_doubleword();
  test_bic_asimd_imm();
  test_ld1r_4h();
  test_ld1r_4s();
  test_stxr_word();
  test_stxr_doubleword();
  test_dc_zva();
  test_cnt_vector_8b();
  // test_cnt_vector_16b();
  // COND.c
  test_fcsel_double();
  // MISC.c
  test_prfm_pldl1keep();
  // SIMD.c
  test_cmge_onlyd();
  test_dup_vector();
  test_fmla_vector();
  test_fadd_vector();
  test_fmul_vector();
  test_fmul_vector_byelem();
  test_cmhs_vector();
  test_ushll_vector();
  test_ushll2_vector();
  test_scvtf_vector();
  test_rev32_vector();
  printf("TEST SUCCESS\n");
  return 0;
}
