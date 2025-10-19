#include <stdio.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>

int main(void) {
  struct rusage usage;
  long primes = 0;

  // Apply some computational load (prime number search)
  for (long i = 2; i < 200000; i++) {
    int is_prime = 1;
    for (long j = 2; j * j <= i; j++) {
      if (i % j == 0) {
        is_prime = 0;
        break;
      }
    }
    primes += is_prime;
  }

  // Retrieve statistics for the current process
  if (getrusage(RUSAGE_SELF, &usage) == 0) {
    printf("User time:   %ld.%06ld sec\n", usage.ru_utime.tv_sec, usage.ru_utime.tv_usec);
    printf("System time: %ld.%06ld sec\n", usage.ru_stime.tv_sec, usage.ru_stime.tv_usec);
    printf("Max RSS:     %ld KB\n", usage.ru_maxrss);
    printf("Minor faults:%ld\n", usage.ru_minflt);
    printf("Major faults:%ld\n", usage.ru_majflt);
  } else {
    perror("getrusage");
  }

  printf("Total primes: %ld\n", primes);
  return 0;
}