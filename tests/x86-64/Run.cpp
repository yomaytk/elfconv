#include <gtest/gtest.h>
#include <gtest/internal/gtest-port.h>
#include <stdio.h>
#include <stdlib.h>
#include <utils/Util.h>

using ::testing::InitGoogleTest;
using ::testing::Test;
using ::testing::TestInfo;
using ::testing::UnitTest;

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

// compile ./Instructions.c
void compile_test_elf() {
  std::string cmd =
      "clang -nostdlib -static -o amd64_isa_test --target=x86_64-linux-gnu --sysroot=/usr/x86_64-linux-gnu ../../../tests/x86-64/test.s";
  cmd_check(system(cmd.c_str()), cmd.c_str());
}

// rm generated obj
void clean_up() {
  system("rm *.o *.bc *.aarch64");
}

// binary lifting
void lift(const char *elf_path) {
  std::string cmd = "../../../build/lifter/elflift --arch amd64 --bc_out lift.bc --target_elf " +
                    std::string(elf_path);
  cmd_check(system(cmd.c_str()), cmd.c_str());
}

void gen_converted_test() {
  auto cmd =
      std::string("clang++ -I../../../backend/remill/include -I../../../ -DELF_IS_AMD64 ") +
      " -o converted_test.amd64 lift.bc ../../../runtime/Entry.cpp ../../../runtime/Memory.cpp ../../../runtime/Runtime.cpp" +
      "../../../runtime/syscalls/SyscallNative.cpp ../../../runtime/VmIntrinsics.cpp ../../../utils/Util.cpp ../../../utils/elfconv.cpp";
  cmd_check(system(cmd.c_str()), cmd.c_str());
}

void unit_amd64_test() {
  // compile target test program
  compile_test_elf();
  // binary lifting
  lift("amd64_isa_test");
  // generate converted_test.aarch64
  gen_converted_test();
  // execute converted_test.aarch64
  cmd_check(system("./converted_test.amd64"), "./converted_test.amd64");
}

TEST(TestAArch64Insn, UnitInsnTest) {
  unit_amd64_test();
}

int main(int argc, char **argv) {
  InitGoogleTest(&argc, argv);

  ::testing::AddGlobalTestEnvironment(new TestEnvironment);
  return RUN_ALL_TESTS();
}