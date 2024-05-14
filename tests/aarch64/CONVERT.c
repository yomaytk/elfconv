#include <arm_neon.h>

// UCVTF  <V><d>, <V><n> (<V> = S)
void ucvtf_float(float *sd, uint32_t n32) {
  asm __volatile__("UCVTF %s0, %w1" : "=w"(*sd) : "r"(n32));
}
// UCVTF  <V><d>, <V><n> (<V> = D)
void ucvtf_double(double *dd, uint64_t n64) {
  asm __volatile__("UCVTF %d0, %w1" : "=w"(*dd) : "r"(n64));
}
// SCVTF  <V><d>, <V><n> (<V> = S)
void scvtf_float(float *sd, int n32) {
  asm __volatile__("SCVTF %s0, %w1" : "=w"(*sd) : "r"(n32));
}
// SCVTF  <V><d>, <V><n> (<V> = D)
void scvtf_double(double *dd, long n64) {
  asm __volatile__("SCVTF %d0, %w1" : "=w"(*dd) : "r"(n64));
}
// FRINTA  <Dd>, <Dn>
void frinta_doubleword(double dn, double *dd) {
  asm __volatile__("FRINTA %d0, %d1" : "=w"(*dd) : "w"(dn));
}
// FCVTAS  <Xd>, <Dn>
void fcvtas_doubleword(double dn, long *xd) {
  asm __volatile__("FCVTAS %0, %d1" : "=r"(*xd) : "w"(dn));
}