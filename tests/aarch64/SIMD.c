#include <arm_neon.h>

// CMGE  <V><d>, <V><n>, #0
void cmge_onlyd(int64x2_t *qt1, int64x2_t qt2) {
  asm __volatile__("CMGE %d0, %d1, #0" : "=w"(*qt1) : "w"(qt2));
}
// DUP  <Vd>.<T>, <Vn>.<Ts>[<index>]
void dup_vector(uint64x2_t *qt1, uint64x2_t qt2) {
  asm __volatile__("DUP %0.2D, %1.D[1]" : "=w"(*qt1) : "w"(qt2));
}
// FMLA  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
void fmla_vector(float32x4_t *qt1, float32x4_t qt2, float32x4_t qt3) {
  asm __volatile__("FMLA %0.4S, %1.4S, %2.4S" : "+w"(*qt1) : "w"(qt2), "w"(qt3));
}
// FADD  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
void fadd_vector(float32x4_t *qt1, float32x4_t qt2, float32x4_t qt3) {
  asm __volatile__("FADD %0.4S, %1.4S, %2.4S" : "+w"(*qt1) : "w"(qt2), "w"(qt3));
}
// FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
void fmul_vector(float32x4_t *qt1, float32x4_t qt2, float32x4_t qt3) {
  asm __volatile__("FMUL %0.4S, %1.4S, %2.4S" : "+w"(*qt1) : "w"(qt2), "w"(qt3));
}
// FMUL  <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
void fmul_vector_byelem(float32x4_t *qt1, float32x4_t qt2, float32x4_t qt3) {
  asm __volatile__("FMUL %0.4S, %1.4S, %2.S[2]" : "+w"(*qt1) : "w"(qt2), "w"(qt3));
}
// CMHS  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
void cmhs_vector(uint32x4_t *qt1, uint32x4_t qt2, uint32x4_t qt3) {
  asm __volatile__("CMHS %0.4S, %1.4S, %2.4S" : "+w"(*qt1) : "w"(qt2), "w"(qt3));
}
// USHLL  <Vd>.<Ta>, <Vn>.<Tb>, #<shift>
void ushll_vector(uint32x4_t *qtd, uint16x4_t qtn) {
  asm __volatile__("USHLL %0.4S, %1.4H, #1" : "=w"(*qtd) : "w"(qtn));
}
// USHLL2  <Vd>.<Ta>, <Vn>.<Tb>, #<shift>
void ushll2_vector(uint32x4_t *qtd, uint16x8_t qtn) {
  asm __volatile__("USHLL2 %0.4S, %1.8H, #2" : "=w"(*qtd) : "w"(qtn));
}
// SCVTF  <Vd>.<T>, <Vn>.<T> (only 32bit or 64bit)
void scvtf_vector(float32x4_t *qtd, int32x4_t qtn) {
  asm __volatile__("SCVTF %0.4S, %1.4S" : "=w"(*qtd) : "w"(qtn));
}
// REV32  <Vd>.<T>, <Vn>.<T>
void rev32_vector(uint8x8_t *qtd, uint8x8_t qtn) {
  asm __volatile__("REV32 %0.8B, %0.8B" : "=w"(*qtd) : "w"(qtn));
}