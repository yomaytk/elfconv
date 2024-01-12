#include "../../front/Util.h"

#include <gtest/gtest.h>
#include <gtest/internal/gtest-port.h>
#include <stdio.h>
#include <stdlib.h>

using ::testing::InitGoogleTest;
using ::testing::Test;
using ::testing::TestInfo;
using ::testing::UnitTest;

#define ECV_PATH(path) "../../../" #path
#define EMCC_SERVER_CMD(ident) \
  "emcc -O0 -DELFCONV_SERVER_ENV=1 -I../../../backend/remill/include -o " #ident ".test.wasm.o " \
  "-c ../../../front/" #ident ".cpp"
#define EMCC_WASM_O(bc_ident) \
  "emcc -c " bc_ident ".bc" \
  " -o " bc_ident ".wasm.o"
#define FRONT_OBJS \
  "Entry.test.wasm.o Memory.test.wasm.o Syscall.test.wasm.o VmIntrinsics.test.wasm.o Util.test.wasm.o elfconv.test.wasm.o"

enum WASI_RUNTIME : uint8_t { WASMTIME, WASMEDGE };

void compile_fronts_emscripten();
void clean_up();

class TestEnvironment : public ::testing::Environment {
 public:
  ~TestEnvironment() override {}
  void SetUp() override {
    compile_fronts_emscripten();
  }
  void TearDown() override {
    clean_up();
  }
};

// compile `elfconv/front`
void compile_fronts_emscripten() {
  std::string cmds[] = {EMCC_SERVER_CMD(Entry),   EMCC_SERVER_CMD(Memory),
                        EMCC_SERVER_CMD(Syscall), EMCC_SERVER_CMD(VmIntrinsics),
                        EMCC_SERVER_CMD(Util),    EMCC_SERVER_CMD(elfconv)};
  for (auto &cmd : cmds) {
    FILE *pipe = popen(cmd.c_str(), "r");
    if (!pipe)
      elfconv_runtime_error(
          "[ELFCONV TEST ERROR]: popen failed with std::string cmd (%s) at \"%s\".\n", cmd.c_str(),
          __func__);
    auto status = pclose(pipe);
    EXPECT_NE(status, -1);
  }
}

// rm generated obj
void clean_up() {
  system("rm *.o *.bc *.wasm");
}

// binary lifting
std::string binary_lifting(const char *elf_path) {
  std::string stdout_res = "";
  std::string cmds[] = {
      "../../../build/front/elflift --arch aarch64 --bc_out lift.bc --target_elf " +
      std::string(elf_path)};
  for (auto &cmd : cmds) {
    auto *pipe = popen(cmd.c_str(), "r");
    if (!pipe)
      elfconv_runtime_error(
          "[ELFCONV TEST ERROR]: popen failed with std::string cmd (%s) at \"%s\".\n", cmd.c_str(),
          __func__);
    char buf[256] = {0};
    while (NULL != fgets(buf, sizeof(buf), pipe)) {
      stdout_res += buf;
      memset(buf, 0, sizeof(buf));
    }
    auto status = pclose(pipe);
    if (-1 == status)
      elfconv_runtime_error(
          "[ELFCONV TEST ERROR] The command \"%s\" return status (%d) is invalid: ", cmd.c_str(),
          status);
    EXPECT_NE(status, -1);
  }
  return stdout_res;
}

void gen_wasm_for_wasi_runtimes() {
  std::string cmds[] = {// generate lift.wasm.o
                        "emcc -c lift.bc -o lift.wasm.o",
                        // generate wasm
                        "emcc -o exe.wasm lift.wasm.o " FRONT_OBJS};
  for (auto &cmd : cmds) {
    FILE *pipe = popen(cmd.c_str(), "r");
    if (!pipe)
      elfconv_runtime_error(
          "[ELFCONV TEST ERROR]: popen failed with std::string cmd (%s) at \"%s\".\n", cmd.c_str(),
          __func__);
    auto status = pclose(pipe);
    EXPECT_NE(status, -1);
  }
}

std::string exec_wasm(WASI_RUNTIME wasi_runtime) {
  std::string cmd;
  switch (wasi_runtime) {
    case WASMTIME: cmd = "wasmtime exe.wasm"; break;
    case WASMEDGE: cmd = "wasmedge exe.wasm"; break;
    default: elfconv_runtime_error("invaild wasi runtime.\n");
  }
  std::string stdout_res = "";
  FILE *pipe = popen(cmd.c_str(), "r");
  if (!pipe)
    elfconv_runtime_error(
        "[ELFCONV TEST ERROR]: popen failed with std::string cmd (%s) at \"%s\".\n", cmd.c_str(),
        __func__);
  char buf[1000];
  while (NULL != fgets(buf, sizeof(buf), pipe)) {
    stdout_res += buf;
    memset(buf, 0, sizeof(buf));
  }
  auto status = pclose(pipe);
  EXPECT_NE(status, -1);
  return stdout_res;
}

void unit_test_wasi_runtime(const char *program, const char *expected, WASI_RUNTIME wasi_runtime) {
  // binary lifting
  binary_lifting(("../../../examples/" + std::string(program) + "/a.out").c_str());
  // generate wasm
  gen_wasm_for_wasi_runtimes();
  // execute wasm
  auto stdout_res = exec_wasm(wasi_runtime);
  // test
  EXPECT_STREQ(expected, stdout_res.c_str());
}

TEST(TestWasmtime, IntegrationExamplesTest) {
  unit_test_wasi_runtime("print_hello", "Hello, World!\n", WASMTIME);
  unit_test_wasi_runtime(
      "eratosthenes_sieve",
      "2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,509,521,523,541\n",
      WASMTIME);
  // unit_test_wasi_runtime("hello", "Hello, World!\n", WASMTIME); (ERROR)
}

TEST(TestWasmedge, IntegrationExamplesTest) {
  unit_test_wasi_runtime("print_hello", "Hello, World!\n", WASMEDGE);
  unit_test_wasi_runtime(
      "eratosthenes_sieve",
      "2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,509,521,523,541\n",
      WASMEDGE);
  // unit_test_wasi_runtime("hello", "Hello, World!\n", WASMTIME); (ERROR)
}

int main(int argc, char **argv) {
  InitGoogleTest(&argc, argv);

  ::testing::AddGlobalTestEnvironment(new TestEnvironment);
  return RUN_ALL_TESTS();
}