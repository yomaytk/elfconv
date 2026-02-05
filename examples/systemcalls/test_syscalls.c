#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

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

int main() {
    printf("====================================\n");
    printf("  System Call Test Suite\n");
    printf("====================================\n");

    // Run all tests
    test_fstat();
    test_readv();
    test_pread();
    test_pwrite();

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
