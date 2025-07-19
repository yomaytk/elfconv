#include <gtest/gtest.h>
#include <gtest/internal/gtest-port.h>
#include <stdlib.h>
#include <string>
#include <utils/Util.h>

using ::testing::InitGoogleTest;
using ::testing::Test;

const char *ELFCONV_WASI_MACRO =
    "-DELF_IS_AARCH64 --sysroot=${WASI_SDK_PATH}/share/wasi-sysroot -D_WASI_EMULATED_SIGNAL -D_WASI_EMULATED_MMAN -D_WASI_EMULATED_PROCESS_CLOCKS -DTARGET_IS_WASI=1 -lwasi-emulated-process-clocks -lwasi-emulated-signal -lwasi-emulated-mman -fno-exceptions -I../../../backend/remill/include -I../../../";

enum WASI_RUNTIME : uint8_t { WASMTIME, WASMEDGE };

void clean_up();

class TestEnvironment : public ::testing::Environment {
 public:
  ~TestEnvironment() override {}
  void SetUp() override {}
  void TearDown() override {
    clean_up();
  }
};

// rm generated obj
void clean_up() {
  system("rm *.o *.bc *.wasm");
}

void cmd_check(int status, const char *cmd) {
  if (-1 == status || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    printf(
        "[AARCH64 INSTRUCTIONS TEST ERROR]: system failed with std::string cmd (%s) at \"%s\".\n",
        cmd, __func__);
    FAIL();
  }
}

// binary lifting
std::string binary_lifting(const char *elf_path) {
  char buf[256] = {0};
  FILE *pipe;
  int status;
  std::string stdout_res;
  auto cmd = "../../../build/lifter/elflift --arch aarch64 --bc_out lift.bc --target_elf " +
             std::string(elf_path);

  pipe = popen(cmd.c_str(), "r");
  EXPECT_NE(pipe, nullptr) << "[ERROR] Failed to " << cmd.c_str() << " at binary_lifting.";

  while (NULL != fgets(buf, sizeof(buf), pipe)) {
    stdout_res += buf;
    memset(buf, 0, sizeof(buf));
  }

  status = pclose(pipe);
  EXPECT_NE(status, -1) << "[ERROR] Failed to pclose pipe at b binary_lifting.";
  return stdout_res;
}

void gen_wasm_for_wasi_runtimes() {
  FILE *pipe;
  int status;

  auto cmd =
      std::string("${WASI_SDK_PATH}/bin/clang++ -O3 ") + ELFCONV_WASI_MACRO +
      " -o exe.wasm lift.bc ../../../runtime/Entry.cpp ../../../runtime/Memory.cpp " +
      "../../../runtime/syscalls/SyscallWasi.cpp ../../../runtime/VmIntrinsics.cpp ../../../utils/Util.cpp ../../../utils/elfconv.cpp";
  pipe = popen(cmd.c_str(), "r");
  EXPECT_NE(pipe, nullptr) << "[ERROR] Failed to " << cmd.c_str()
                           << "at gen_wasm_for_wasi_runtimes.";

  status = pclose(pipe);
  EXPECT_NE(status, -1) << "[ERROR] Failed to pclose pipe at gen_wasm_for_wasi_runtimes.";
}

std::string exec_wasm(WASI_RUNTIME wasi_runtime) {
  std::string cmd;
  FILE *pipe;
  char buf[1000];
  int status;

  switch (wasi_runtime) {
    case WASMTIME: cmd = "wasmtime exe.wasm"; break;
    case WASMEDGE: cmd = "wasmedge exe.wasm"; break;
    default: EXPECT_NE(0, 1);
  }

  std::string stdout_res = "";
  pipe = popen(cmd.c_str(), "r");
  if (!pipe) {
    printf("[ELFCONV TEST ERROR]: popen failed with std::string cmd (%s) at \"%s\".\n", cmd.c_str(),
           __func__);
    EXPECT_NE(1, 1);
  }

  while (NULL != fgets(buf, sizeof(buf), pipe)) {
    stdout_res += buf;
    memset(buf, 0, sizeof(buf));
  }

  status = pclose(pipe);
  EXPECT_NE(status, -1);
  return stdout_res;
}

void unit_test_wasi_runtime(const char *program, const char *expected, WASI_RUNTIME wasi_runtime) {
  // binary lifting
  binary_lifting(("../../../examples/" + std::string(program) + "/a_stripped.aarch64").c_str());
  // generate wasm
  gen_wasm_for_wasi_runtimes();
  // execute wasm
  auto stdout_res = exec_wasm(wasi_runtime);
  // test
  EXPECT_STREQ(expected, stdout_res.c_str());
}

TEST(TestWasm1, IntegrationExamplesTest) {
  unit_test_wasi_runtime("hello/c", "Hello, World!\n", WASMEDGE);
}

int main(int argc, char **argv) {
  InitGoogleTest(&argc, argv);

  ::testing::AddGlobalTestEnvironment(new TestEnvironment);
  return RUN_ALL_TESTS();
}