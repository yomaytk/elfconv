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
  WASISDKCC="${WASI_SDK_PATH}/bin/clang++"
  WASISDKFLAGS="${OPTFLAGS} --sysroot=${WASI_SDK_PATH}/share/wasi-sysroot -D_WASI_EMULATED_PROCESS_CLOCKS -I${ROOT_DIR}/backend/remill/include -I${ROOT_DIR} -fno-exceptions"
  WASISDK_LINKFLAGS="-lwasi-emulated-process-clocks"
  ELFCONV_MACROS=
  ELFCONV_DEBUG_MACROS=
  ELFCONV_SHARED_RUNTIMES="${RUNTIME_DIR}/Entry.cpp ${RUNTIME_DIR}/Runtime.cpp ${RUNTIME_DIR}/Memory.cpp ${RUNTIME_DIR}/VmIntrinsics.cpp ${UTILS_DIR}/Util.cpp ${UTILS_DIR}/elfconv.cpp"
  WASMEDGE_COMPILE_OPT="wasmedge compile --optimize 3"
  HOST_CPU=$(uname -p)

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
  "${AARCH64_TEST_DIR}"/TestInstructions.cpp $ELFCONV_SHARED_RUNTIMES ${RUNTIME_DIR}/syscalls/SyscallNative.cpp
  echo -e "[\033[32mINFO\033[0m] Generate lift_test.aarch64"

}

lifting() {

  # ELF -> LLVM bc
  echo -e "[\033[32mINFO\033[0m] ELF -> LLVM bitcode..."
  elf_path=$( realpath "$1" )
  
  wasi32_target_arch=''
  if [ "${TARGET}" == "Wasi" ]; then
    wasi32_target_arch='wasi32'
  fi
  
  cd ${BUILD_LIFTER_DIR} && \
    ./elflift \
    --arch aarch64 \
    --bc_out ./lift.bc \
    --target_elf "$elf_path" \
    --dbg_fun_cfg "$2" \
    --bitcode_path "$3" \
    --target_arch "$wasi32_target_arch" && \
    llvm-dis-${LLVM_VERSION} lift.bc -o lift.ll
  echo -e "[\033[32mINFO\033[0m] lift.bc was generated."

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
    Native)
      echo -e "[\033[32mINFO\033[0m] Compiling to Native binary (for $HOST_CPU)... "
      ${CXX} ${CLANGFLAGS} -o "exe.${HOST_CPU}" lift.ll $ELFCONV_SHARED_RUNTIMES ${RUNTIME_DIR}/syscalls/SyscallNative.cpp
      echo -e " [\033[32mINFO\033[0m] exe.${HOST_CPU} was generated."
      return 0
    ;;
    Browser)
      ELFCONV_MACROS="-DELFC_BROWSER_ENV=1"
      echo -e "[\033[32mINFO\033[0m] Compiling to Wasm and Js (for Browser)... "
      $EMCC $EMCCFLAGS $ELFCONV_MACROS $ELFCONV_DEBUG_MACROS -o exe.js -sALLOW_MEMORY_GROWTH -sASYNCIFY -sEXPORT_ES6 -sENVIRONMENT=web --js-library ${ROOT_DIR}/xterm-pty/emscripten-pty.js \
                              lift.ll $ELFCONV_SHARED_RUNTIMES ${RUNTIME_DIR}/syscalls/SyscallBrowser.cpp
      echo -e "[\033[32mINFO\033[0m] exe.wasm and exe.js were generated."
      cp exe.js ${ROOT_DIR}/examples/browser
      cp exe.wasm ${ROOT_DIR}/examples/browser
      return 0
    ;;
    Wasi)
      ELFCONV_MACROS="-DELFC_WASI_ENV=1"
      cd ${BUILD_DIR}
      echo -e "[\033[32mINFO\033[0m] Compiling to Wasm (for WASI)... "
      $WASISDKCC $WASISDKFLAGS $WASISDK_LINKFLAGS $ELFCONV_MACROS $ELFCONV_DEBUG_MACROS -o exe.wasm ${BUILD_LIFTER_DIR}/lift.ll $ELFCONV_SHARED_RUNTIMES ${RUNTIME_DIR}/syscalls/SyscallWasi.cpp
      echo -e "[\033[32mINFO\033[0m] exe.wasm was generated."
      $WASMEDGE_COMPILE_OPT exe.wasm exe_o3.wasm
      echo -e "[\033[32mINFO\033[0m] Universal compile optimization was done. (exe_o3.wasm)"
      return 0
    ;;
  esac  
}

main "$@"