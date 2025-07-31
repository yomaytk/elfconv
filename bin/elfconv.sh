#!/usr/bin/env bash

GREEN="\033[32m"
RED="\033[31m"
NC="\033[0m"

setting() {

  BIN_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
  ROOT_DIR=${BIN_DIR}/../
  RUNTIME_DIR=${ROOT_DIR}/runtime
  UTILS_DIR=${ROOT_DIR}/utils
  BUILD_DIR=${ROOT_DIR}/build
  BUILD_LIFTER_DIR=${BUILD_DIR}/lifter
  OPTFLAGS="-O3"
  CXX=clang++-16
  CLANGFLAGS="${OPTFLAGS} -std=c++20 -static -I${ROOT_DIR}/backend/remill/include -I${ROOT_DIR}"
  EMCC=emcc
  EMCCFLAGS="${OPTFLAGS} -I${ROOT_DIR}/backend/remill/include -I${ROOT_DIR}"
  WASISDKCC=${WASI_SDK_PATH}/bin/clang++
  WASISDKFLAGS="${OPTFLAGS} --sysroot=${WASI_SDK_PATH}/share/wasi-sysroot -D_WASI_EMULATED_SIGNAL -D_WASI_EMULATED_PROCESS_CLOCKS -D_WASI_EMULATED_MMAN -I${ROOT_DIR}/backend/remill/include -I${ROOT_DIR} -fno-exceptions"
  WASISDK_LINKFLAGS="-lwasi-emulated-process-clocks -lwasi-emulated-mman -lwasi-emulated-signal"
  RUNTIME_MACRO=''
  ELFPATH=$( realpath "$1" )
  HOST_CPU=$(uname -p)
  ELFCONV_SHARED_RUNTIMES="${RUNTIME_DIR}/Entry.cpp ${RUNTIME_DIR}/Memory.cpp ${RUNTIME_DIR}/VmIntrinsics.cpp ${UTILS_DIR}/Util.cpp ${UTILS_DIR}/elfconv.cpp"
  FLOAT_STATUS_FLAG='off'

}

main() {

  setting "$1"

  if [ $# -eq 0 ]; then
    echo "[${RED}ERROR${NC}] target ELF binary is not specified."
    echo $#
    exit 1
  fi

  # Setting for WASI
  target_arch=$HOST_CPU
  if [ "$TARGET" = "*-wasi32" ]; then
    target_arch='wasi32'
  fi

  # floating-point exception
  if [ -n "$FLOAT_STATUS" ]; then
    FLOAT_STATUS_FLAG='on'
  fi

  # input ELF CPU architecture
  arch_name=${TARGET%%-*}

  # `elflift` is generated in ${BUILD_LIFTER_DIR} so copy it in ${BIN_DIR}.
  cp -p "${BUILD_LIFTER_DIR}/elflift" "${BIN_DIR}/"

  # Set some environment variables depending on CPU architecture.
  case "$TARGET" in
    aarch64-*)
      RUNTIME_MACRO="$RUNTIME_MACRO -DELF_IS_AARCH64"
      ;;
    amd64-*)
      RUNTIME_MACRO="$RUNTIME_MACRO -DELF_IS_AMD64"
      ;;
    *)
      echo -e "Unsupported architecture of ELF: $TARGET."
      ;;
  esac
  
  # ELF -> LLVM bitcode
  # --arch: CPU architecture of the input ELF binary. elfconv supports only aarch64 (x86-64 is in progress).
  # --bc_out: generated LLVM bitcode file path.
  # --target_elf: input ELF binary path.
  # --dbg_fun_cfg: used to show the detail of the lifted function (for Debug).
  # --target_arch: conversion target architecture
  echo -e "[${GREEN}INFO${NC}] ELF -> LLVM bitcode..."
    cd "${BIN_DIR}" || { echo "cd Failure"; exit 1; }
    ./elflift \
    --arch $arch_name \
    --bc_out lift.bc \
    --target_elf "$ELFPATH" \
    --dbg_fun_cfg "$2" \
    --target_arch "$target_arch" \
    --float_exception "$FLOAT_STATUS_FLAG"
  echo -e "[${GREEN}INFO${NC}] LLVM bitcode (lift.bc) was generated."

  # LLVM bc -> target file
  case "$TARGET" in
    *-native)
      echo -e "[${GREEN}INFO${NC}] Compiling to Native binary (for $HOST_CPU)... "
      $CXX $CLANGFLAGS $RUNTIME_MACRO -o "exe.${HOST_CPU}" lift.bc $ELFCONV_SHARED_RUNTIMES ${RUNTIME_DIR}/syscalls/SyscallNative.cpp
      echo -e " [${GREEN}INFO${NC}] exe.${HOST_CPU} was generated."
      return 0
    ;;
    *-wasm)
      RUNTIME_MACRO="$RUNTIME_MACRO -DTARGET_IS_BROWSER=1"
      echo -e "[${GREEN}INFO${NC}] Compiling to Wasm and Js (for Browser)... "
      # We use https://github.com/mame/xterm-pty for the console on the browser.
      cd "${BIN_DIR}" || { echo "cd Failure"; exit 1; }
        $EMCC $EMCCFLAGS $RUNTIME_MACRO -sALLOW_MEMORY_GROWTH -sASYNCIFY -sEXPORT_ES6 -sENVIRONMENT=web $PRELOAD --js-library ${ROOT_DIR}/xterm-pty/emscripten-pty.js \
            -o exe.js lift.bc $ELFCONV_SHARED_RUNTIMES ${RUNTIME_DIR}/syscalls/SyscallBrowser.cpp
      echo -e "[${GREEN}INFO${NC}] exe.wasm and exe.js were generated."
    ;;
    *-wasi32)
      echo -e "[${GREEN}INFO${NC}] Compiling to Wasm (for WASI)... "
      RUNTIME_MACRO="$RUNTIME_MACRO -DTARGET_IS_WASI=1"
      cd "${BIN_DIR}" || { echo "cd Failure"; exit 1; }
      $WASISDKCC $WASISDKFLAGS $WASISDK_LINKFLAGS $RUNTIME_MACRO -o exe.wasm lift.bc $ELFCONV_SHARED_RUNTIMES ${RUNTIME_DIR}/syscalls/SyscallWasi.cpp
      echo -e "[${GREEN}INFO${NC}] exe.wasm was generated."
    ;;
  esac

  rm ${BIN_DIR}/lift.bc
  return 0

}

main "$@"