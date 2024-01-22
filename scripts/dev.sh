#!/usr/bin/env bash

ROOT_DIR=${HOME}/workspace/compiler/elfconv
FRONT_DIR=${ROOT_DIR}/front
AARCH64_TEST_DIR=${ROOT_DIR}/tests/aarch64
BUILD_DIR=${ROOT_DIR}/build
BUILD_FRONT_DIR=${BUILD_DIR}/front
BUILD_TESTS_AARCH64_DIR=${BUILD_DIR}/tests/aarch64
CXX=clang++-16
OPTFLAGS="-O3"
CLANGFLAGS="${OPTFLAGS} -static -I${ROOT_DIR}/backend/remill/include -I${ROOT_DIR}"
CXXX64=x86_64-linux-gnu-g++-11
CROSS_COMPILE_FLAGS_X64="-static --target=x86-64-linux-gnu nostdin_linpack.c -fuse-ld=lld -pthread;"
X64CLANGFLAGS="${OPTFLAGS} -static -I${ROOT_DIR}/backend/remill/include"
EMCC=emcc
EMCCFLAGS="${OPTFLAGS} -I${ROOT_DIR}/backend/remill/include"
WASISDK_CXX=${HOME}/wasi-sdk/build/install/opt/wasi-sdk/bin/clang++
WASISDKFLAGS="${OPTFLAGS} --sysroot=${WASI_SDK_PATH}/share/wasi-sysroot -I${ROOT_DIR}/backend/remill/include"
ELFCONV_MACROS="-DELFCONV_BROWSER_ENV=1"
ELFCONV_DEBUG_MACROS=

if [ -n "$SERVER" ]; then
  ELFCONV_MACROS="-DELFCONV_SERVER_ENV=1"
fi

if [ -n "$DEBUG" ]; then
  ELFCONV_DEBUG_MACROS="-DELFCONV_SYSCALL_DEBUG=1"
fi

# aarch64 lifting test
if [ -n "$AARCH64_TEST" ]; then
  echo "[INFO] AArch64 Test Lifting Start."
  cd ${BUILD_TESTS_AARCH64_DIR} && \
    ./aarch64_test_lift \
    --arch aarch64 \
    --bc_out ./aarch64_test.bc
  echo "[INFO] Generate aarch64_lift.bc"
  llvm-dis aarch64_test.bc -o aarch64_test.ll
  echo "[INFO] Generate aarch64_lift.ll"
  ${CXX} ${CLANGFLAGS} ${ELFCONV_MACROS} ${ELFCONV_DEBUG_MACROS} -o Test.aarch64.o -c ${AARCH64_TEST_DIR}/Test.cpp && \
  ${CXX} ${CLANGFLAGS} ${ELFCONV_MACROS} ${ELFCONV_DEBUG_MACROS} -o TestHelper.aarch64.o -c ${AARCH64_TEST_DIR}/TestHelper.cpp && \
  ${CXX} ${CLANGFLAGS} ${ELFCONV_MACROS} ${ELFCONV_DEBUG_MACROS} -o TestInstructions.aarch64.o -c ${AARCH64_TEST_DIR}/TestInstructions.cpp && \
  ${CXX} ${CLANGFLAGS} ${ELFCONV_MACROS} ${ELFCONV_DEBUG_MACROS} -o Memory.aarch64.o -c ${FRONT_DIR}/Memory.cpp && \
  ${CXX} ${CLANGFLAGS} ${ELFCONV_MACROS} ${ELFCONV_DEBUG_MACROS} -o Syscall.aarch64.o -c ${FRONT_DIR}/Syscall.cpp && \
  ${CXX} ${CLANGFLAGS} ${ELFCONV_MACROS} ${ELFCONV_DEBUG_MACROS} -o VmIntrinsics.aarch64.o -c ${FRONT_DIR}/VmIntrinsics.cpp && \
  ${CXX} ${CLANGFLAGS} ${ELFCONV_MACROS} ${ELFCONV_DEBUG_MACROS} -o Util.aarch64.o -c ${FRONT_DIR}/Util.cpp && \
  ${CXX} ${CLANGFLAGS} ${ELFCONV_MACROS} ${ELFCONV_DEBUG_MACROS} -o elfconv.aarch64.o -c ${FRONT_DIR}/elfconv.cpp && \
  ${CXX} ${CLANGFLAGS} -c aarch64_test.ll -o aarch64_test.o && \
  ${CXX} ${CLANGFLAGS} -o lift_test.aarch64 aarch64_test.o Test.aarch64.o TestHelper.aarch64.o TestInstructions.aarch64.o \
                          Memory.aarch64.o Syscall.aarch64.o VmIntrinsics.aarch64.o Util.aarch64.o elfconv.aarch64.o
  exit
fi

# $1 : path to target ELF
if [ -z "$NOT_LIFTED" ]; then
  echo "[INFO] ELF Converting Start."
    elf_path=$( realpath "$1" )
    cd ${BUILD_FRONT_DIR} && \
      ./elflift \
      --arch aarch64 \
      --bc_out ./lift.bc \
      --target_elf "$elf_path" \
      --dbg_fun_cfg "$2" && \
      llvm-dis lift.bc -o lift.ll
  echo "[INFO] Generate lift.bc."
fi

# aarch64
if [ -n "$AARCH64" ]; then
  cd ${BUILD_FRONT_DIR} && \
    ${CXX} ${CLANGFLAGS} -o exe.aarch64 lift.ll ${FRONT_DIR}/Entry.cpp ${FRONT_DIR}/Memory.cpp ${FRONT_DIR}/Syscall.cpp ${FRONT_DIR}/VmIntrinsics.cpp ${FRONT_DIR}/Util.cpp ${FRONT_DIR}/elfconv.cpp
fi

# wasm ( browser )
if [[ -n "$WASM" && -z "$SERVER" ]]; then
  cd "${BUILD_FRONT_DIR}" && \
    ${EMCC} ${EMCCFLAGS} ${ELFCONV_MACROS} ${ELFCONV_DEBUG_MACROS} -o Entry.wasm.o -c ${FRONT_DIR}/Entry.cpp && \
    ${EMCC} ${EMCCFLAGS} ${ELFCONV_MACROS} ${ELFCONV_DEBUG_MACROS} -o Memory.wasm.o -c ${FRONT_DIR}/Memory.cpp && \
    ${EMCC} ${EMCCFLAGS} ${ELFCONV_MACROS} ${ELFCONV_DEBUG_MACROS} -o Syscall.wasm.o -c ${FRONT_DIR}/Syscall.cpp && \
    ${EMCC} ${EMCCFLAGS} ${ELFCONV_MACROS} ${ELFCONV_DEBUG_MACROS} -o VmIntrinsics.wasm.o -c ${FRONT_DIR}/VmIntrinsics.cpp && \
    ${EMCC} ${EMCCFLAGS} ${ELFCONV_MACROS} ${ELFCONV_DEBUG_MACROS} -o Util.wasm.o -c ${FRONT_DIR}/Util.cpp && \
    ${EMCC} ${EMCCFLAGS} ${ELFCONV_MACROS} ${ELFCONV_DEBUG_MACROS} -o elfconv.wasm.o -c ${FRONT_DIR}/elfconv.cpp && \
    ${EMCC} ${EMCCFLAGS} -c lift.ll -o lift.wasm.o
    ${EMCC} ${EMCCFLAGS} -o exe.wasm.html -sWASM -sALLOW_MEMORY_GROWTH lift.wasm.o Entry.wasm.o Memory.wasm.o Syscall.wasm.o \
                            VmIntrinsics.wasm.o Util.wasm.o elfconv.wasm.o
  # delete obj
  cd "${BUILD_FRONT_DIR}" && rm *.o
fi

# wasm ( server )
if [[ -n "$WASM" && -n "$SERVER" ]]; then
  cd "${BUILD_FRONT_DIR}" && \
    ${EMCC} ${EMCCFLAGS} ${ELFCONV_MACROS} ${ELFCONV_DEBUG_MACROS} -o Entry.wasm.o -c ${FRONT_DIR}/Entry.cpp && \
    ${EMCC} ${EMCCFLAGS} ${ELFCONV_MACROS} ${ELFCONV_DEBUG_MACROS} -o Memory.wasm.o -c ${FRONT_DIR}/Memory.cpp && \
    ${EMCC} ${EMCCFLAGS} ${ELFCONV_MACROS} ${ELFCONV_DEBUG_MACROS} -o Syscall.wasm.o -c ${FRONT_DIR}/Syscall.cpp && \
    ${EMCC} ${EMCCFLAGS} ${ELFCONV_MACROS} ${ELFCONV_DEBUG_MACROS} -o VmIntrinsics.wasm.o -c ${FRONT_DIR}/VmIntrinsics.cpp && \
    ${EMCC} ${EMCCFLAGS} ${ELFCONV_MACROS} ${ELFCONV_DEBUG_MACROS} -o Util.wasm.o -c ${FRONT_DIR}/Util.cpp && \
    ${EMCC} ${EMCCFLAGS} ${ELFCONV_MACROS} ${ELFCONV_DEBUG_MACROS} -o elfconv.wasm.o -c ${FRONT_DIR}/elfconv.cpp && \
    ${EMCC} ${EMCCFLAGS} -c lift.ll -o lift.wasm.o
    ${EMCC} ${EMCCFLAGS} -o exe.wasm lift.wasm.o Entry.wasm.o Memory.wasm.o Syscall.wasm.o VmIntrinsics.wasm.o Util.wasm.o elfconv.wasm.o
  # delete obj
  cd "${BUILD_FRONT_DIR}" && rm *.o
fi
