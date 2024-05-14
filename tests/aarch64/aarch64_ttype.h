#pragma once

#include <arm_neon.h>

typedef union {
  float f4[4];
  double d2[2];
  uint64x2_t v2;
} qt;
