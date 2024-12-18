#include <arm_neon.h>

// FMSUB  <Sd>, <Sn>, <Sm>, <Sa>
void fmsub_float(float *sd, float sn, float sm, float sa) {
  asm __volatile__("FMSUB %s0, %s1, %s2, %s3" : "=w"(*sd) : "w"(sn), "w"(sm), "w"(sa));
}
// FMSUB  <Dd>, <Dn>, <Dm>, <Da>
void fmsub_double(double *dd, double dn, double dm, double da) {
  asm __volatile__("FMSUB %d0, %d1, %d2, %d3" : "=w"(*dd) : "w"(dn), "w"(dm), "w"(da));
}
// ADC  <Wd>, <Wn>, <Wm>
void adc_word(uint32_t _r1, uint32_t _r2, uint32_t *wd, uint32_t wn, uint32_t wm) {
  asm __volatile__("ADDS %w[r1], %w[r1], %w[r2] \n\t"
                   "ADC %w0, %w1, %w2 \n\t"
                   : "=r"(*wd)
                   : "r"(wn), "r"(wm), [r1] "r"(_r1), [r2] "r"(_r2));
}
// ADC  <Xd>, <Xn>, <Xm>
void adc_doubleword(uint64_t _r1, uint64_t _r2, uint64_t *xd, uint64_t xn, uint64_t xm) {
  asm __volatile__("ADDS %x[r1], %x[r1], %x[r2] \n\t"
                   "ADC %x0, %x1, %x2 \n\t"
                   : "=r"(*xd)
                   : "r"(xn), "r"(xm), [r1] "r"(_r1), [r2] "r"(_r2));
}
// UMSUBL <Xd>, <Wn>, <Wm>, <Xa>
void umsubl(uint64_t *xd, uint32_t wn, uint32_t wm, uint64_t xa) {
  asm __volatile__("UMSUBL %x0, %w1, %w2, %x3" : "=r"(*xd) : "r"(wn), "r"(wm), "r"(xa));
}
// FSUB <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
void fsub_vector(float32x4_t *qtd, float32x4_t qtn, float32x4_t qtm) {
  asm __volatile__("FSUB %0.4S, %1.4S, %2.4S" : "+w"(*qtd) : "w"(qtn), "w"(qtm));
}
// FDIV  <Vd>.<T>, <Vn>.<T>, <Vm>.<T> (only 32bit or 64bit)
void fdiv_vector(float32x4_t *qtd, float32x4_t qtn, float32x4_t qtm) {
  asm __volatile__("FDIV %0.4S, %1.4S, %2.4S" : "+w"(*qtd) : "w"(qtn), "w"(qtm));
}
