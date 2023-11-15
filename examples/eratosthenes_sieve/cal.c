#define SLENGTH 100
#define NUMS 1000

void write_stdout(char *str, unsigned long length) {
     __asm__ volatile(
        "mov x2, x1;"          // x2 = length
        "mov x1, x0;"          // x1 = str
        "mov x0, #1;"          // fd = STDOUT
        "mov x8, #64;"         // syscall: write
        "svc #0;"              // make syscall
        :
        : "r" (str), "r" (length)
        : "x0", "x1", "x2", "x8"
    );
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
    for(;;) {
        if (num / res > 9) {
            res *= 10;
        } else {
            break;
        }
    }
    return res;
}

void easy_cal() {
    
    int nums[NUMS];
    char s[SLENGTH];

    nums[0] = nums[1] = 0;
    for(int i = 2;i < NUMS;i++) {
        nums[i] = 1;
    }

    // cal
    for (int base = 2; base < 1000;base++){
        if (!nums[base]) {
            continue;
        }
        for (int target = base * 2; target < NUMS;target += base){
            nums[target] = 0;
        }
    }
    int seek = 0;
    for (int i = 0; i < NUMS && seek + digit_num(i) + 1 < SLENGTH;i++) {
        if (!nums[i]) {
            continue;
        }
        int mm = mhex(i);
        for (int j = i;j > 0;) {
            s[seek++] = '0' + (j / mm);
            j -= mm * (j / mm);
            mm /= 10;
        }
        s[seek++] = ',';
    }
    s[seek] = '\n';

    // stdout
    write_stdout(s, SLENGTH);
}