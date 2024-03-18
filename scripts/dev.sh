#!/usr/bin/env bash

LLVM_VERSION=16
ROOT_DIR=${HOME}/workspace/compiler/elfconv

setting() {

  if [ -n "$NEW_ROOT" ]; then
    ROOT_DIR="$NEW_ROOT"
  fi

  RUNTIME_DIR=${ROOT_DIR}/runtime
  UTILS_DIR=${ROOT_DIR}/utils
  AARCH64_TEST_DIR=${ROOT_DIR}/tests/aarch64
  BUILD_DIR=${ROOT_DIR}/build
  BUILD_LIFTER_DIR=${BUILD_DIR}/lifter
  BUILD_TESTS_AARCH64_DIR=${BUILD_DIR}/tests/aarch64
  CXX=clang++-16
  OPTFLAGS="-O3"
  CLANGFLAGS="${OPTFLAGS} -static -I${ROOT_DIR}/backend/remill/include -I${ROOT_DIR}"
  EMCC=emcc
  EMCCFLAGS="${OPTFLAGS} -I${ROOT_DIR}/backend/remill/include -I${ROOT_DIR}"
  WASISDK_CXX=${HOME}/wasi-sdk/build/install/opt/wasi-sdk/bin/clang++
  WASISDKFLAGS="${OPTFLAGS} --sysroot=${WASI_SDK_PATH}/share/wasi-sysroot -I${ROOT_DIR}/backend/remill/include -I${ROOT_DIR}"
  ELFCONV_MACROS="-DELFCONV_BROWSER_ENV=1"
  ELFCONV_DEBUG_MACROS=
  WASMCC=$EMCC
  WASMCCFLAGS=$EMCCFLAGS

  if [ -n "$DEBUG" ]; then
    ELFCONV_DEBUG_MACROS="-DELFC_RUNTIME_SYSCALL_DEBUG=1 -DELFC_RUNTIME_MULSECTIONS_WARNING=1 "
  fi

}

aarch64_test() {

  # generate LLVM bc
  echo -e "[\033[32mINFO\033[0m] AArch64 Test Lifting Start."
  cd "${BUILD_TESTS_AARCH64_DIR}" && \
    ./aarch64_test_lift \
    --arch aarch64 \
    --bc_out ./aarch64_test.bc
  echo -e "[\033[32mINFO\033[0m] Generate aarch64_lift.bc"
  llvm-dis-${LLVM_VERSION} aarch64_test.bc -o aarch64_test.ll
  echo -e "[\033[32mINFO\033[0m] Generate aarch64_lift.ll"  

  # generate execute file (lift_test.aarch64)
  ${CXX} "${CLANGFLAGS}" $ELFCONV_MACROS "$ELFCONV_DEBUG_MACROS" -o lift_test.aarch64 aarch64_test.ll "${AARCH64_TEST_DIR}"/Test.cpp "${AARCH64_TEST_DIR}"/TestHelper.cpp \
  "${AARCH64_TEST_DIR}"/TestInstructions.cpp "${RUNTIME_DIR}"/Memory.cpp "${RUNTIME_DIR}"/Syscall.cpp "${RUNTIME_DIR}"/VmIntrinsics.cpp "${UTILS_DIR}"/Util.cpp "${UTILS_DIR}"/elfconv.cpp
  echo -e "[\033[32mINFO\033[0m] Generate lift_test.aarch64"

}

lifting() {

  # ELF -> LLVM bc
  echo -e "[\033[32mINFO\033[0m] ELF Converting Start."
  elf_path=$( realpath "$1" )
  cd ${BUILD_LIFTER_DIR} && \
    ./elflift \
    --arch aarch64 \
    --bc_out ./lift.bc \
    --target_elf "$elf_path" \
    --dbg_fun_cfg "$2" && \
    llvm-dis-${LLVM_VERSION} lift.bc -o lift.ll
  echo -e "[\033[32mINFO\033[0m] Generate lift.bc."

}

main() {

  # environment variable settings
  setting

  # aarch64 lifting test
  if [ -n "$AARCH64_TEST" ]; then
    aarch64_test
    return 0
  fi

  # ELF -> LLVM bc
  if [ -z "$NOT_LIFTED" ]; then
    lifting "$1" "$2"
  fi

  # LLVM bc -> target file
  case "${TARGET}" in
    native)
      cd ${BUILD_LIFTER_DIR} && \
      ${CXX} ${CLANGFLAGS} -o exe.aarch64 lift.ll ${RUNTIME_DIR}/Entry.cpp ${RUNTIME_DIR}/Memory.cpp ${RUNTIME_DIR}/Syscall.cpp ${RUNTIME_DIR}/VmIntrinsics.cpp ${UTILS_DIR}/Util.cpp ${UTILS_DIR}/elfconv.cpp
      echo -e "[\033[32mINFO\033[0m] Generate native binary."
      return 0
    ;;
    wasm-browser)
      cd "${BUILD_LIFTER_DIR}" && \
      $WASMCC $WASMCCFLAGS $ELFCONV_MACROS $ELFCONV_DEBUG_MACROS -o Entry.wasm.o -c ${RUNTIME_DIR}/Entry.cpp && \
      $WASMCC $WASMCCFLAGS $ELFCONV_MACROS $ELFCONV_DEBUG_MACROS -o Memory.wasm.o -c ${RUNTIME_DIR}/Memory.cpp && \
      $WASMCC $WASMCCFLAGS $ELFCONV_MACROS $ELFCONV_DEBUG_MACROS -o Syscall.wasm.o -c ${RUNTIME_DIR}/Syscall.cpp && \
      $WASMCC $WASMCCFLAGS $ELFCONV_MACROS $ELFCONV_DEBUG_MACROS -o VmIntrinsics.wasm.o -c ${RUNTIME_DIR}/VmIntrinsics.cpp && \
      $WASMCC $WASMCCFLAGS $ELFCONV_MACROS $ELFCONV_DEBUG_MACROS -o Util.wasm.o -c ${UTILS_DIR}/Util.cpp && \
      $WASMCC $WASMCCFLAGS $ELFCONV_MACROS $ELFCONV_DEBUG_MACROS -o elfconv.wasm.o -c ${UTILS_DIR}/elfconv.cpp && \
      $WASMCC $WASMCCFLAGS -c lift.ll -o lift.wasm.o
      $WASMCC $WASMCCFLAGS -o exe.wasm.html -sWASM -sALLOW_MEMORY_GROWTH lift.wasm.o Entry.wasm.o Memory.wasm.o Syscall.wasm.o \
                              VmIntrinsics.wasm.o Util.wasm.o elfconv.wasm.o
      echo -e "[\033[32mINFO\033[0m] Generate WASM binary."
      # delete obj
      cd "${BUILD_LIFTER_DIR}" && rm *.o
      return 0
    ;;
    wasm-host)
      ELFCONV_MACROS="-DELFC_WASI_ENV=1"
      if [ -n "$WASISDK" ]; then
        WASMCC=$WASISDK_CXX
        WASMCCFLAGS=$WASISDKFLAGS
        ELFCONV_MACROS="${ELFCONV_MACROS} -DWASI_ENV=1 -fno-exceptions"
      fi
      cd "${BUILD_LIFTER_DIR}" && \
      $WASMCC $WASMCCFLAGS $ELFCONV_MACROS $ELFCONV_DEBUG_MACROS -o Entry.wasm.o -c ${RUNTIME_DIR}/Entry.cpp && \
      $WASMCC $WASMCCFLAGS $ELFCONV_MACROS $ELFCONV_DEBUG_MACROS -o Memory.wasm.o -c ${RUNTIME_DIR}/Memory.cpp && \
      $WASMCC $WASMCCFLAGS $ELFCONV_MACROS $ELFCONV_DEBUG_MACROS -o Syscall.wasm.o -c ${RUNTIME_DIR}/Syscall.cpp && \
      $WASMCC $WASMCCFLAGS $ELFCONV_MACROS $ELFCONV_DEBUG_MACROS -o VmIntrinsics.wasm.o -c ${RUNTIME_DIR}/VmIntrinsics.cpp && \
      $WASMCC $WASMCCFLAGS $ELFCONV_MACROS $ELFCONV_DEBUG_MACROS -o Util.wasm.o -c ${UTILS_DIR}/Util.cpp && \
      $WASMCC $WASMCCFLAGS $ELFCONV_MACROS $ELFCONV_DEBUG_MACROS -o elfconv.wasm.o -c ${UTILS_DIR}/elfconv.cpp && \
      $WASMCC -c lift.ll -o lift.wasm.o
      $WASMCC -o exe.wasm lift.wasm.o Entry.wasm.o Memory.wasm.o Syscall.wasm.o VmIntrinsics.wasm.o Util.wasm.o elfconv.wasm.o
      echo -e "[\033[32mINFO\033[0m] Generate WASM binary."
      # delete obj
      cd "${BUILD_LIFTER_DIR}" && rm *.o
      return 0
    ;;
  esac  
}

main "$@"
