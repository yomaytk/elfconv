#include <gtest/gtest.h>
#include <gtest/internal/gtest-port.h>
#include <stdio.h>
#include <stdlib.h>
#include <utils/Util.h>

using ::testing::InitGoogleTest;
using ::testing::Test;
using ::testing::TestInfo;
using ::testing::UnitTest;

#define ECV_PATH(path) "../../../" #path
#define CLANG_RUNTIME_CMD(ident) \
  "clang++ -I../../../backend/remill/include -I../../../ -o " #ident ".test.aarch64.o " \
  "-c ../../../runtime/" #ident ".cpp"
#define CLAGN_RUNTIME_SYSCALL_CMD(ident) \
  "clang++ -I../../../backend/remill/include -I../../../ -o " #ident ".test.aarch64.o " \
  "-c ../../../runtime/syscalls/" #ident ".cpp"
#define CLANG_UTILS_CMD(ident) \
  "clang++ -I../../../backend/remill/include -I../../../ -o " #ident ".test.aarch64.o " \
  "-c ../../../utils/" #ident ".cpp"
#define RUNTIME_OBJS \
  "Entry.test.aarch64.o Memory.test.aarch64.o Runtime.test.aarch64.o SyscallNative.test.aarch64.o VmIntrinsics.test.aarch64.o Util.test.aarch64.o elfconv.test.aarch64.o"

void compile_runtime();
void compile_test_elf();
void clean_up();

class TestEnvironment : public ::testing::Environment {
 public:
  ~TestEnvironment() override {}
  void TearDown() override {
    clean_up();
  }
};

void cmd_check(int status, const char *cmd) {
  if (-1 == status || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    printf(
        "[AARCH64 INSTRUCTIONS TEST ERROR]: system failed with std::string cmd (%s) at \"%s\".\n",
        cmd, __func__);
    FAIL();
  }
}

// compile `elfconv/runtime`
void compile_runtime() {
  std::string cmds[] = {CLANG_RUNTIME_CMD(Entry),        CLANG_RUNTIME_CMD(Memory),
                        CLANG_RUNTIME_CMD(Runtime),      CLAGN_RUNTIME_SYSCALL_CMD(SyscallNative),
                        CLANG_RUNTIME_CMD(VmIntrinsics), CLANG_UTILS_CMD(Util),
                        CLANG_UTILS_CMD(elfconv)};
  for (auto &cmd : cmds)
    cmd_check(system(cmd.c_str()), cmd.c_str());
}

// compile ./Instructions.c
void compile_test_elf() {
  std::string cmd =
      "clang -static -march=armv8.2-a+lse -o test_elf ../../../tests/aarch64/Instructions.c";
  cmd_check(system(cmd.c_str()), cmd.c_str());
}

// rm generated obj
void clean_up() {
  system("rm *.o *.bc *.aarch64");
}

// binary lifting
void lift(const char *elf_path) {
  std::string cmd = "../../../build/lifter/elflift --arch aarch64 --bc_out lift.bc --target_elf " +
                    std::string(elf_path);
  cmd_check(system(cmd.c_str()), cmd.c_str());
}

void gen_converted_test() {
  std::string cmd = "clang++ -o converted_test.aarch64 lift.bc " RUNTIME_OBJS;
  cmd_check(system(cmd.c_str()), cmd.c_str());
}

void unit_aarch64_test() {
  // compile /runtime
  compile_runtime();
  // compile target test program
  compile_test_elf();
  // binary lifting
  lift("test_elf");
  // generate converted_test.aarch64
  gen_converted_test();
  // execute converted_test.aarch64
  cmd_check(system("./converted_test.aarch64"), "./converted_test.aarch64");
}

TEST(TestAArch64Insn, UnitInsnTest) {
  unit_aarch64_test();
}

int main(int argc, char **argv) {
  InitGoogleTest(&argc, argv);

  ::testing::AddGlobalTestEnvironment(new TestEnvironment);
  return RUN_ALL_TESTS();
}