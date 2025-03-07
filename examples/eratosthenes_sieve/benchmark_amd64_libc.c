#include <float.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define MAX_NUM 30000000

static double second(void)

{
  return ((double) ((double) clock() / (double) CLOCKS_PER_SEC));
}

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

int nums[MAX_NUM];

int main() {

  char s[1000];

  double ts = second();

  nums[0] = nums[1] = 0;
  for (int i = 2; i < MAX_NUM; i++) {
    nums[i] = 1;
  }

  // cal
  for (int base = 2; base < 1000; base++) {
    if (!nums[base]) {
      continue;
    }
    for (int target = base * 2; target < MAX_NUM; target += base) {
      nums[target] = 0;
    }
  }

  // make output string
  int seek = 0;
  for (int i = 0; i < 100; i++) {
    if (!nums[i]) {
      continue;
    }
    int mm = mhex(i);
    for (int j = i; j > 0;) {
      s[seek++] = '0' + (j / mm);
      j -= mm * (j / mm);
      mm /= 10;
    }
    s[seek++] = ',';
  }
  // s[--seek] = ' ';
  // s[seek++] = ' ';
  s[seek++] = '.';
  s[seek++] = '.';
  s[seek++] = '.';
  s[seek++] = ',';

  // prime number sequence
  printf("%s", s);

  // Get max prime
  for (int i = MAX_NUM - 1; i > 0; i--) {
    if (nums[i]) {
      int num = i;
      printf("%d\n", num);
      break;
    }
  }

  double te = second();

  printf("time: %1.4f\n", te - ts);

  return 0;
}