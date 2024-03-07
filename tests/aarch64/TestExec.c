#include "TargetInstructions.c"

#include <assert.h>
#include <stdio.h>

int main() {
  // FCVTAS  <Xd>, <Dn>
  assert(fcvtas_Xd_Dn(43.3f) == 43);
  // FRINTA <Dd>, <Dn>
  assert(frinta_Dd_Dn(43.3f) == 43);

  printf("Test Success!\n");
  return 0;
}
