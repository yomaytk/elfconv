#!/usr/bin/env bash

setting() {

  BIN_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
  ROOT_DIR=${BIN_DIR}/../
  RUNTIME_DIR=${ROOT_DIR}/runtime
  UTILS_DIR=${ROOT_DIR}/utils
  BUILD_DIR=${ROOT_DIR}/build
  BUILD_LIFTER_DIR=${BUILD_DIR}/lifter
  OPTFLAGS="-O3"
  EMCC=emcc
  EMCCFLAGS="${OPTFLAGS} -I${ROOT_DIR}/backend/remill/include -I${ROOT_DIR}"
  WASISDKCC=${WASI_SDK_PATH}/bin/clang++
  WASISDKFLAGS="${OPTFLAGS} --sysroot=${WASI_SDK_PATH}/share/wasi-sysroot -D_WASI_EMULATED_PROCESS_CLOCKS -I${ROOT_DIR}/backend/remill/include -I${ROOT_DIR} -fno-exceptions"
  WASISDK_LINKFLAGS="-lwasi-emulated-process-clocks"
  ELFCONV_MACROS="-DTARGET_IS_BROWSER=1"
  ELFPATH=$( realpath "$1" )

}

main() {

  setting "$1"

  if [ $# -eq 0 ]; then
    echo "[ERROR] target ELF binary is not specified (lift.sh)."
    echo $#
    exit 1
  fi

  # setting for WASI
  wasi32_target_arch=''
  if [ "$TARGET" = "Wasi" ]; then
    wasi32_target_arch='wasi32'
  fi

  # ELF -> LLVM bitcode
  cp -p "${BUILD_LIFTER_DIR}/elflift" "${BIN_DIR}/"
  echo -e "[\033[32mINFO\033[0m] ELF -> LLVM bitcode..."
    cd "${BIN_DIR}" || { echo "cd Failure"; exit 1; }
    ./elflift \
    --arch aarch64 \
    --bc_out lift.bc \
    --target_elf "$ELFPATH" \
    --dbg_fun_cfg "$2" \
    --target_arch "$wasi32_target_arch"
  echo -e "[\033[32mINFO\033[0m] LLVM bitcode (lift.bc) was generated."

  # LLVM bc -> target file
  case "$TARGET" in
    Browser)
      # We use https://github.com/mame/xterm-pty for the console on the browser.
      ELFCONV_MACROS="-DTARGET_IS_BROWSER=1 -DELF_IS_AARCH64"
      echo -e "[\033[32mINFO\033[0m] Compiling to Wasm and Js (for Browser)... "
      cd "${BIN_DIR}" || { echo "cd Failure"; exit 1; }
        $EMCC $EMCCFLAGS $ELFCONV_MACROS -sALLOW_MEMORY_GROWTH -sASYNCIFY -sEXPORT_ES6 -sENVIRONMENT=web --js-library ${ROOT_DIR}/xterm-pty/emscripten-pty.js \
            -o exe.js lift.bc ${RUNTIME_DIR}/Entry.cpp ${RUNTIME_DIR}/Memory.cpp ${RUNTIME_DIR}/VmIntrinsics.cpp ${RUNTIME_DIR}/syscalls/SyscallBrowser.cpp \
            ${UTILS_DIR}/elfconv.cpp ${UTILS_DIR}/Util.cpp
      echo -e "[\033[32mINFO\033[0m] exe.wasm and exe.js were generated."
    ;;
    Wasi)
      echo -e "[\033[32mINFO\033[0m] Compiling to Wasm (for WASI)... "
      ELFCONV_MACROS="-DTARGET_IS_WASI=1 -DELF_IS_AARCH64"
      cd "${BIN_DIR}" || { echo "cd Failure"; exit 1; }
      $WASISDKCC $WASISDKFLAGS $WASISDK_LINKFLAGS $ELFCONV_MACROS -o exe.wasm lift.bc ${RUNTIME_DIR}/Entry.cpp ${RUNTIME_DIR}/Memory.cpp ${RUNTIME_DIR}/VmIntrinsics.cpp ${RUNTIME_DIR}/syscalls/SyscallWasi.cpp \
          ${UTILS_DIR}/elfconv.cpp ${UTILS_DIR}/Util.cpp
      echo -e "[\033[32mINFO\033[0m] exe.wasm was generated."
    ;;
  esac

  rm ${BIN_DIR}/lift.bc
  return 0

}

main "$@"