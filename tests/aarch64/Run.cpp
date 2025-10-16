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
  auto cmd =
      std::string("clang++ -I../../../backend/remill/include -I../../../ -DELF_IS_AARCH64 ") +
      " -o converted_test.aarch64 lift.bc ../../../runtime/Entry.cpp ../../../runtime/Memory.cpp ../../../runtime/Runtime.cpp" +
      "../../../runtime/syscalls/SyscallNative.cpp ../../../runtime/VmIntrinsics.cpp ../../../utils/Util.cpp ../../../utils/elfconv.cpp";
  cmd_check(system(cmd.c_str()), cmd.c_str());
}

void unit_aarch64_test() {
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