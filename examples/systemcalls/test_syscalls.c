#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

extern char **environ;

// Test result counters
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_START(name) printf("\n=== Testing %s ===\n", name)
#define TEST_PASS(name) do { printf("[PASS] %s\n", name); tests_passed++; } while(0)
#define TEST_FAIL(name, reason) do { printf("[FAIL] %s: %s\n", name, reason); tests_failed++; } while(0)

// Test fstat system call
int test_fstat() {
    TEST_START("fstat");

    int fd;
    struct stat st;
    const char *test_file = "test_fstat_file.txt";
    const char *content = "Hello, fstat test!";

    // Create a test file
    fd = open(test_file, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        TEST_FAIL("fstat", "open for write failed");
        return -1;
    }

    ssize_t written = write(fd, content, strlen(content));
    if (written != (ssize_t)strlen(content)) {
        close(fd);
        TEST_FAIL("fstat", "write failed");
        return -1;
    }
    close(fd);

    // Reopen for reading
    fd = open(test_file, O_RDONLY);
    if (fd < 0) {
        TEST_FAIL("fstat", "open for read failed");
        return -1;
    }

    // Test fstat
    if (fstat(fd, &st) < 0) {
        close(fd);
        TEST_FAIL("fstat", "fstat() failed");
        return -1;
    }

    printf("  File size: %ld bytes\n", (long)st.st_size);
    printf("  Inode: %ld\n", (long)st.st_ino);
    printf("  Mode: 0%o\n", st.st_mode & 0777);
    printf("  UID: %d\n", st.st_uid);
    printf("  GID: %d\n", st.st_gid);

    // Verify file size
    if (st.st_size != (off_t)strlen(content)) {
        close(fd);
        unlink(test_file);
        TEST_FAIL("fstat", "incorrect file size");
        return -1;
    }

    close(fd);
    unlink(test_file);

    TEST_PASS("fstat");
    return 0;
}

// Test readv system call
int test_readv() {
    TEST_START("readv");

    int fd;
    const char *test_file = "test_readv_file.txt";
    const char *content = "Hello, readv test! This is a multi-buffer read test.";

    // Create a test file
    fd = open(test_file, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        TEST_FAIL("readv", "open for write failed");
        return -1;
    }

    ssize_t written = write(fd, content, strlen(content));
    if (written != (ssize_t)strlen(content)) {
        close(fd);
        TEST_FAIL("readv", "write failed");
        return -1;
    }
    close(fd);

    // Reopen for reading
    fd = open(test_file, O_RDONLY);
    if (fd < 0) {
        TEST_FAIL("readv", "open for read failed");
        return -1;
    }

    // Prepare buffers for readv
    char buf1[20];
    char buf2[20];
    char buf3[30];
    memset(buf1, 0, sizeof(buf1));
    memset(buf2, 0, sizeof(buf2));
    memset(buf3, 0, sizeof(buf3));

    struct iovec iov[3];
    iov[0].iov_base = buf1;
    iov[0].iov_len = sizeof(buf1) - 1;
    iov[1].iov_base = buf2;
    iov[1].iov_len = sizeof(buf2) - 1;
    iov[2].iov_base = buf3;
    iov[2].iov_len = sizeof(buf3) - 1;

    // Test readv
    ssize_t bytes_read = readv(fd, iov, 3);
    if (bytes_read < 0) {
        close(fd);
        unlink(test_file);
        TEST_FAIL("readv", "readv() failed");
        return -1;
    }

    printf("  Total bytes read: %ld\n", (long)bytes_read);
    printf("  Buffer 1: %s\n", buf1);
    printf("  Buffer 2: %s\n", buf2);
    printf("  Buffer 3: %s\n", buf3);

    // Verify total bytes read
    if (bytes_read != (ssize_t)strlen(content)) {
        close(fd);
        unlink(test_file);
        TEST_FAIL("readv", "incorrect number of bytes read");
        return -1;
    }

    // Reconstruct and verify content
    char reconstructed[200];
    snprintf(reconstructed, sizeof(reconstructed), "%s%s%s", buf1, buf2, buf3);
    if (strcmp(reconstructed, content) != 0) {
        close(fd);
        unlink(test_file);
        TEST_FAIL("readv", "content mismatch");
        return -1;
    }

    close(fd);
    unlink(test_file);

    TEST_PASS("readv");
    return 0;
}

// Test pread system call
int test_pread() {
    TEST_START("pread");

    int fd;
    const char *test_file = "test_pread_file.txt";
    const char *content = "0123456789ABCDEFGHIJ";

    // Create a test file
    fd = open(test_file, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        TEST_FAIL("pread", "open for write failed");
        return -1;
    }

    ssize_t written = write(fd, content, strlen(content));
    if (written != (ssize_t)strlen(content)) {
        close(fd);
        TEST_FAIL("pread", "write failed");
        return -1;
    }
    close(fd);

    // Reopen for reading
    fd = open(test_file, O_RDONLY);
    if (fd < 0) {
        TEST_FAIL("pread", "open for read failed");
        return -1;
    }

    // Test pread at different offsets
    char buf1[10];
    char buf2[10];
    char buf3[10];
    memset(buf1, 0, sizeof(buf1));
    memset(buf2, 0, sizeof(buf2));
    memset(buf3, 0, sizeof(buf3));

    // Read from offset 0
    ssize_t bytes_read = pread(fd, buf1, 5, 0);
    if (bytes_read != 5) {
        close(fd);
        unlink(test_file);
        TEST_FAIL("pread", "pread at offset 0 failed");
        return -1;
    }

    // Read from offset 10
    bytes_read = pread(fd, buf2, 5, 10);
    if (bytes_read != 5) {
        close(fd);
        unlink(test_file);
        TEST_FAIL("pread", "pread at offset 10 failed");
        return -1;
    }

    // Read from offset 5
    bytes_read = pread(fd, buf3, 5, 5);
    if (bytes_read != 5) {
        close(fd);
        unlink(test_file);
        TEST_FAIL("pread", "pread at offset 5 failed");
        return -1;
    }

    printf("  Read at offset 0: %s\n", buf1);
    printf("  Read at offset 10: %s\n", buf2);
    printf("  Read at offset 5: %s\n", buf3);

    // Verify content
    if (strncmp(buf1, "01234", 5) != 0 ||
        strncmp(buf2, "ABCDE", 5) != 0 ||
        strncmp(buf3, "56789", 5) != 0) {
        close(fd);
        unlink(test_file);
        TEST_FAIL("pread", "content mismatch");
        return -1;
    }

    close(fd);
    unlink(test_file);

    TEST_PASS("pread");
    return 0;
}

// Test pwrite system call
int test_pwrite() {
    TEST_START("pwrite");

    int fd;
    const char *test_file = "test_pwrite_file.txt";
    const char *initial = "XXXXXXXXXXXXXXXXXXXX";
    const char *patch1 = "AAAAA";
    const char *patch2 = "BBBBB";

    // Create a test file with initial content
    fd = open(test_file, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        TEST_FAIL("pwrite", "open for write failed");
        return -1;
    }

    ssize_t written = write(fd, initial, strlen(initial));
    if (written != (ssize_t)strlen(initial)) {
        close(fd);
        TEST_FAIL("pwrite", "write failed");
        return -1;
    }
    close(fd);

    // Reopen for read-write
    fd = open(test_file, O_RDWR);
    if (fd < 0) {
        TEST_FAIL("pwrite", "open for read-write failed");
        return -1;
    }

    // Test pwrite at different offsets
    written = pwrite(fd, patch1, strlen(patch1), 0);
    if (written != (ssize_t)strlen(patch1)) {
        close(fd);
        unlink(test_file);
        TEST_FAIL("pwrite", "pwrite at offset 0 failed");
        return -1;
    }

    written = pwrite(fd, patch2, strlen(patch2), 10);
    if (written != (ssize_t)strlen(patch2)) {
        close(fd);
        unlink(test_file);
        TEST_FAIL("pwrite", "pwrite at offset 10 failed");
        return -1;
    }

    // Read back the entire file
    lseek(fd, 0, SEEK_SET);
    char result[30];
    memset(result, 0, sizeof(result));
    ssize_t bytes_read = read(fd, result, strlen(initial));
    if (bytes_read != (ssize_t)strlen(initial)) {
        close(fd);
        unlink(test_file);
        TEST_FAIL("pwrite", "read back failed");
        return -1;
    }

    printf("  Final content: %s\n", result);

    // Verify content: should be "AAAAAXXXXBBBBBXXXXX"
    if (strncmp(result, "AAAAA", 5) != 0 ||
        strncmp(result + 5, "XXXXX", 5) != 0 ||
        strncmp(result + 10, "BBBBB", 5) != 0) {
        close(fd);
        unlink(test_file);
        TEST_FAIL("pwrite", "content mismatch");
        return -1;
    }

    close(fd);
    unlink(test_file);

    TEST_PASS("pwrite");
    return 0;
}

// Test fsync and unlink system calls
int test_fsync_unlink() {
    TEST_START("fsync/unlink");

    const char *filename = "test_fsync_file.txt";
    int fd;

    // Create a file
    fd = open(filename, O_CREAT | O_WRONLY, 0644);
    if (fd < 0) {
        TEST_FAIL("fsync/unlink", "open failed");
        return -1;
    }

    // Write data
    const char *data = "Hello, World!\n";
    if (write(fd, data, 14) < 0) {
        close(fd);
        TEST_FAIL("fsync/unlink", "write failed");
        return -1;
    }

    // Sync data to disk
    if (fsync(fd) < 0) {
        close(fd);
        TEST_FAIL("fsync/unlink", "fsync failed");
        return -1;
    }

    printf("  Data written and synchronized to disk\n");
    close(fd);

    // Delete the file
    if (unlink(filename) < 0) {
        TEST_FAIL("fsync/unlink", "unlink failed");
        return -1;
    }

    printf("  File deleted successfully\n");

    TEST_PASS("fsync/unlink");
    return 0;
}

// Test getrusage system call
int test_getrusage() {
    TEST_START("getrusage");

    struct rusage usage;
    long primes = 0;

    // Apply some computational load (prime number search)
    for (long i = 2; i < 10000; i++) {
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
        printf("  User time:   %ld.%06ld sec\n", usage.ru_utime.tv_sec, usage.ru_utime.tv_usec);
        printf("  System time: %ld.%06ld sec\n", usage.ru_stime.tv_sec, usage.ru_stime.tv_usec);
        printf("  Max RSS:     %ld KB\n", usage.ru_maxrss);
        printf("  Total primes found: %ld\n", primes);

        TEST_PASS("getrusage");
    } else {
        TEST_FAIL("getrusage", "getrusage failed");
        return -1;
    }

    return 0;
}

// Test environment variables access
int test_environ() {
    TEST_START("environ");

    if (environ == NULL) {
        TEST_FAIL("environ", "environ is NULL");
        return -1;
    }

    int count = 0;
    for (int i = 0; environ[i] != NULL; i++) {
        count++;
    }

    printf("  Found %d environment variables\n", count);

    if (count > 0) {
        printf("  First env var: %s\n", environ[0]);
        TEST_PASS("environ");
    } else {
        TEST_FAIL("environ", "no environment variables found");
        return -1;
    }

    return 0;
}

// Test fork system call
int test_fork() {
    TEST_START("fork");

    pid_t pid = fork();

    if (pid < 0) {
        TEST_FAIL("fork", "fork failed");
        return -1;
    } else if (pid == 0) {
        // Child process
        printf("  Child process: PID=%d, Parent PID=%d\n", getpid(), getppid());
        exit(0);
    } else {
        // Parent process
        printf("  Parent process: PID=%d, Child PID=%d\n", getpid(), pid);

        // Wait for child to avoid zombie
        int status;
        waitpid(pid, &status, 0);

        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            TEST_PASS("fork");
        } else {
            TEST_FAIL("fork", "child process failed");
            return -1;
        }
    }

    return 0;
}

// Test fork and wait system calls
int test_fork_wait() {
    TEST_START("fork/wait");

    pid_t pid = fork();

    if (pid < 0) {
        TEST_FAIL("fork/wait", "fork failed");
        return -1;
    } else if (pid == 0) {
        // Child process
        printf("  Child process: PID=%d, Parent PID=%d\n", getpid(), getppid());
        printf("  Child process terminating with exit code 42\n");
        exit(42);
    } else {
        // Parent process
        printf("  Parent process: PID=%d, Child PID=%d\n", getpid(), pid);

        int status;
        pid_t wpid = wait(&status);

        if (wpid == -1) {
            TEST_FAIL("fork/wait", "wait failed");
            return -1;
        }

        if (WIFEXITED(status)) {
            int exit_code = WEXITSTATUS(status);
            printf("  Child process %d exited normally (exit code=%d)\n", wpid, exit_code);

            if (exit_code == 42) {
                TEST_PASS("fork/wait");
            } else {
                TEST_FAIL("fork/wait", "unexpected exit code");
                return -1;
            }
        } else {
            TEST_FAIL("fork/wait", "child terminated abnormally");
            return -1;
        }
    }

    return 0;
}

int main() {
    printf("====================================\n");
    printf("  System Call Test Suite\n");
    printf("====================================\n");

    // Run all tests
    test_fstat();
    test_readv();
    test_pread();
    test_pwrite();
    test_fsync_unlink();
    test_getrusage();
    test_environ();
    test_fork();
    test_fork_wait();

    // Print summary
    printf("\n====================================\n");
    printf("  Test Summary\n");
    printf("====================================\n");
    printf("  Passed: %d\n", tests_passed);
    printf("  Failed: %d\n", tests_failed);
    printf("  Total:  %d\n", tests_passed + tests_failed);
    printf("====================================\n");

    return (tests_failed > 0) ? 1 : 0;
}
