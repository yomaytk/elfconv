#include <float.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define MAX_NUM 30000000

int digit_num(int num) {
  int res = 0;
  for (;;) {
    if (num > 0) {
      num /= 10;
      res++;
    } else {
      break;
    }
  }
  return res;
}

int mhex(int num) {
  int res = 1;
  for (;;) {
    if (num / res > 9) {
      res *= 10;
    } else {
      break;
    }
  }
  return res;
}

static double second(void)

{
  return ((double) ((double) clock() / (double) CLOCKS_PER_SEC));
}

int main() {

  double st = second();

  int *nums = (int *) malloc(MAX_NUM * sizeof(int));
  char s[100];

  nums[0] = nums[1] = 0;
  for (int i = 2; i < MAX_NUM; i++) {
    nums[i] = 1;
  }

  // cal
  for (int base = 2; base < MAX_NUM; base++) {
    if (!nums[base]) {
      continue;
    }
    for (int target = base * 2; target < MAX_NUM; target += base) {
      nums[target] = 0;
    }
  }
  int seek;
  for (int i = 0; i < MAX_NUM; i++) {
    if (!nums[i]) {
      continue;
    }
    int mm = mhex(i);
    seek = 0;
    for (int j = i; j > 0;) {
      s[seek++] = '0' + (j / mm);
      j -= mm * (j / mm);
      mm /= 10;
    }
  }
  s[seek] = '\n';
  s[++seek] = '\0';

  double et = second();

  // // stdout
  printf("max prime: %s", s);
  printf("time: %f\n", et - st);
}