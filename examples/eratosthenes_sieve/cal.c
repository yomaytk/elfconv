#define SLENGTH 10000
#define MAX_NUM 10000

void write_stdout(char *str, unsigned long length) {
  __asm__ volatile("mov x2, x1;"  // x2 = length
                   "mov x1, x0;"  // x1 = str
                   "mov x0, #1;"  // fd = STDOUT
                   "mov x8, #64;"  // syscall: write
                   "svc #0;"  // make syscall
                   :
                   : "r"(str), "r"(length)
                   : "x0", "x1", "x2", "x8");
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

// void simple_cal_1() {
//   char s[SLENGTH];
//   for (int i = 0; i < 100; i++) {
//     for (int j = i; j < 120; j += 2) {
//       s[j] = 'a';
//     }
//   }
//   int a = 10;
//   for (int i = 0; i < 5; i++) {
//     a *= 10;
//     mhex(a);
//   }
//   s[119] = 'm';
//   s[120] = '\n';
//   write_stdout(s, SLENGTH);
// }

void prime_cal() {

  int nums[MAX_NUM];
  char s[SLENGTH];

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
  int seek = 0;
  int count = 0;
  for (int i = 0; i < MAX_NUM && count < 100; i++) {
    if (!nums[i]) {
      continue;
    }
    count++;
    int mm = mhex(i);
    for (int j = i; j > 0;) {
      s[seek++] = '0' + (j / mm);
      j -= mm * (j / mm);
      mm /= 10;
    }
    if (count < 100)
      s[seek++] = ',';
  }
  s[seek] = '\n';

  // // stdout
  write_stdout(s, SLENGTH);
}