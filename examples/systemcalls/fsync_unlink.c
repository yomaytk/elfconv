#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
  const char *filename = "tempfile.txt";
  int fd;

  // ファイルを作成
  fd = open(filename, O_CREAT | O_WRONLY, 0644);
  if (fd < 0) {
    perror("open");
    return EXIT_FAILURE;
  }

  // データを書き込む
  const char *data = "Hello, World!\n";
  if (write(fd, data, 14) < 0) {
    perror("write");
    close(fd);
    return EXIT_FAILURE;
  }

  // データをディスクに同期
  if (fsync(fd) < 0) {
    perror("fsync");
    close(fd);
    return EXIT_FAILURE;
  }

  printf("Data written and synchronized to disk.\n");

  // ファイルをクローズ
  close(fd);

  // ファイルを削除
  if (unlink(filename) < 0) {
    perror("unlink");
    return EXIT_FAILURE;
  }

  printf("File '%s' has been deleted.\n", filename);

  return EXIT_SUCCESS;
}
