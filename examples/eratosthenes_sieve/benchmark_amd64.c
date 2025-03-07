#define MAX_NUM 30000000
#define CLOCKS_PER_01MSEC 100000L

void gettime(void *tp) {
  __asm__ volatile("movq %0, %%rsi;"  // rsi = str (pointer to buffer)
                   "movq $0, %%rdi;"  // rdi = STDOUT (file descriptor)
                   "movq $228, %%rax;"  // rax = syscall number for write
                   "syscall;"  // make syscall
                   :
                   : "r"(tp)
                   : "rax", "rdi", "rsi");
}

void write_stdout(char *str, unsigned long length) {
  __asm__ volatile("movq %0, %%rsi;"  // rsi = str (pointer to buffer)
                   "movq %1, %%rdx;"  // rdx = length
                   "movq $1, %%rdi;"  // rdi = STDOUT (file descriptor)
                   "movq $1, %%rax;"  // rax = syscall number for write
                   "syscall;"  // make syscall
                   :
                   : "r"(str), "r"(length)
                   : "rax", "rdi", "rsi", "rdx");
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

void prime_cal() {

  struct {
    unsigned long tv_sec;
    unsigned long tv_nsec;
  } emu_tp_s, emu_tp_e;

  gettime(&emu_tp_s);

  char s[1000];
  char time[100];

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
  write_stdout(s, seek);

  // Get max prime
  for (int i = MAX_NUM - 1; i > 0; i--) {
    if (nums[i]) {
      int num = i;
      int dn = digit_num(num);
      for (int j = dn; j > 0; j--) {
        s[dn - j] = '0' + (num / mhex(num));
        num -= mhex(num) * (num / mhex(num));
      }
      s[dn] = '\n';
      write_stdout(s, dn + 1);
      break;
    }
  }

  gettime(&emu_tp_e);
  unsigned long diff = ((emu_tp_e.tv_sec - emu_tp_s.tv_sec) * 1000000000 + (emu_tp_e.tv_nsec - emu_tp_s.tv_nsec)) / CLOCKS_PER_01MSEC;

  int t_pos = 0;

  time[t_pos++] = 't';
  time[t_pos++] = 'i';
  time[t_pos++] = 'm';
  time[t_pos++] = 'e';
  time[t_pos++] = ':';
  time[t_pos++] = ' ';
  time[t_pos++] = '0' + (diff / 10000);
  time[t_pos++] = '.';
  time[t_pos++] = '0' + ((diff / 1000) % 10);
  time[t_pos++] = '0' + ((diff / 100) % 10);
  time[t_pos++] = '0' + ((diff / 10) % 10);
  time[t_pos++] = '0' + (diff % 10);
  time[t_pos++] = '\n';

  write_stdout(time, t_pos);
}