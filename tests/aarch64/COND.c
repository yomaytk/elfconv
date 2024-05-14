#include "aarch64_ttype.h"

#include <stdint.h>

// FCSEL  <Dd>, <Dn>, <Dm>, <cond>
#define MAKE_FCSEL_DOUBLEWORD_CMP(cond) \
  void fcsel_double_##cond(uint32_t _r1, uint32_t _r2, double *dd, double dn, double dm) { \
    asm __volatile__("CMP %w[r1], %w[r2] \n\t" \
                     "FCSEL %d0, %d1, %d2, " #cond "" \
                     : "=w"(*dd) \
                     : "w"(dn), "w"(dm), [r1] "r"(_r1), [r2] "r"(_r2)); \
  }
#define MAKE_FCSEL_DOUBLEWORD_UNSIGNED_ADDS(cond) \
  void fcsel_double_##cond(uint32_t _r1, uint32_t _r2, double *dd, double dn, double dm) { \
    asm __volatile__("ADDS %w[r1], %w[r1], %w[r2] \n\t" \
                     "FCSEL %d0, %d1, %d2, " #cond "" \
                     : "=w"(*dd) \
                     : "w"(dn), "w"(dm), [r1] "r"(_r1), [r2] "r"(_r2)); \
  }
#define MAKE_FCSEL_DOUBLEWORD_SIGNED_ADDS(cond) \
  void fcsel_double_##cond(int _r1, int _r2, double *dd, double dn, double dm) { \
    asm __volatile__("ADDS %w[r1], %w[r1], %w[r2] \n\t" \
                     "FCSEL %d0, %d1, %d2, " #cond "" \
                     : "=w"(*dd) \
                     : "w"(dn), "w"(dm), [r1] "r"(_r1), [r2] "r"(_r2)); \
  }
#define MAKE_FCSEL_DOUBLEWORD_UNSIGNED_SUBS(cond) \
  void fcsel_double_##cond(uint32_t _r1, uint32_t _r2, double *dd, double dn, double dm) { \
    asm __volatile__("SUBS %w[r1], %w[r1], %w[r2] \n\t" \
                     "FCSEL %d0, %d1, %d2, " #cond "" \
                     : "=w"(*dd) \
                     : "w"(dn), "w"(dm), [r1] "r"(_r1), [r2] "r"(_r2)); \
  }

MAKE_FCSEL_DOUBLEWORD_CMP(ge)
MAKE_FCSEL_DOUBLEWORD_CMP(gt)
MAKE_FCSEL_DOUBLEWORD_CMP(le)
MAKE_FCSEL_DOUBLEWORD_CMP(lt)
MAKE_FCSEL_DOUBLEWORD_CMP(eq)
MAKE_FCSEL_DOUBLEWORD_CMP(ne)
MAKE_FCSEL_DOUBLEWORD_UNSIGNED_ADDS(cs)
MAKE_FCSEL_DOUBLEWORD_UNSIGNED_ADDS(cc)
MAKE_FCSEL_DOUBLEWORD_SIGNED_ADDS(mi)
MAKE_FCSEL_DOUBLEWORD_SIGNED_ADDS(pl)
MAKE_FCSEL_DOUBLEWORD_SIGNED_ADDS(vs)
MAKE_FCSEL_DOUBLEWORD_SIGNED_ADDS(vc)
MAKE_FCSEL_DOUBLEWORD_UNSIGNED_SUBS(hi)
MAKE_FCSEL_DOUBLEWORD_UNSIGNED_SUBS(ls)
// MAKE_FCSEL_DOUBLEWORD_CMP(al) failed to lift ???