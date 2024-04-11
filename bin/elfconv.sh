#!/usr/bin/env bash

setting() {

  BIN_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
  ROOT_DIR=${BIN_DIR}/../
  RUNTIME_DIR=${ROOT_DIR}/runtime
  UTILS_DIR=${ROOT_DIR}/utils
  BUILD_DIR=${ROOT_DIR}/build
  BUILD_LIFTER_DIR=${BUILD_DIR}/lifter
  EMCC=emcc
  EMAR=emar
  OPTFLAGS="-O3"
  EMCCFLAGS="${OPTFLAGS} -I${ROOT_DIR}/backend/remill/include -I${ROOT_DIR}"
  ELFCONV_MACROS="-DELFC_BROWSER_ENV=1"
  ELFCONV_DEBUG_MACROS=
  ELFPATH=$( realpath "$1" )
  WASMCC=$EMCC
  WASMCCFLAGS=$EMCCFLAGS
  WASMAR=$EMAR
  WASISDKCXX=${WASI_SDK_PATH}/bin/clang++
  WASISDKAR=${WASI_SDK_PATH}/bin/ar
  WASISDKFLAGS="${OPTFLAGS} --sysroot=${WASI_SDK_PATH}/share/wasi-sysroot -I${ROOT_DIR}/backend/remill/include -I${ROOT_DIR} -fno-exceptions"

  if [ "$TARGET" = "wasm-host" ]; then
    ELFCONV_MACROS="-DELFC_WASI_ENV=1"
  fi

}

main() {

  setting "$1"

  if [ $# -eq 0 ]; then
    echo "[ERROR] target ELF binary is not specified (lift.sh)."
    echo $#
    exit 1
  fi

  # build runtime
  SYSCALLCPP="syscalls/SyscallBrowser.cpp"
  echo -e "[\033[32mINFO\033[0m] Building elfconv-Runtime ..."
  if [ "$TARGET" = "wasm-host" ]; then
    WASMCC=$WASISDKCXX
    WASMCCFLAGS=$WASISDKFLAGS
    WASMAR=$WASISDKAR
    SYSCALLCPP="syscalls/SyscallWasi.cpp"
  fi
  cd "${RUNTIME_DIR}" || { echo "cd Failure"; exit 1; }
    # shellcheck disable=SC2086
    $WASMCC $WASMCCFLAGS $ELFCONV_MACROS $ELFCONV_DEBUG_MACROS -o Entry.o -c Entry.cpp && \
    $WASMCC $WASMCCFLAGS $ELFCONV_MACROS $ELFCONV_DEBUG_MACROS -o Memory.o -c Memory.cpp && \
    $WASMCC $WASMCCFLAGS $ELFCONV_MACROS $ELFCONV_DEBUG_MACROS -o Syscall.o -c $SYSCALLCPP && \
    $WASMCC $WASMCCFLAGS $ELFCONV_MACROS $ELFCONV_DEBUG_MACROS -o VmIntrinsics.o -c VmIntrinsics.cpp && \
    $WASMCC $WASMCCFLAGS $ELFCONV_MACROS $ELFCONV_DEBUG_MACROS -o Util.o -c "${UTILS_DIR}"/Util.cpp && \
    $WASMCC $WASMCCFLAGS $ELFCONV_MACROS $ELFCONV_DEBUG_MACROS -o elfconv.o -c "${UTILS_DIR}"/elfconv.cpp && \
    $WASMAR rcs libelfconv.a Entry.o Memory.o Syscall.o VmIntrinsics.o Util.o elfconv.o
    mv libelfconv.a "${BIN_DIR}/"
		rm *.o
  echo -e "[\033[32mINFO\033[0m] Generate libelfconv.a."

  # ELF -> LLVM bc
  cp -p "${BUILD_LIFTER_DIR}/elflift" "${BIN_DIR}/"
  echo -e "[\033[32mINFO\033[0m] Converting ELF to LLVM bitcode ..."
    cd "${BIN_DIR}" || { echo "cd Failure"; exit 1; }
    ./elflift \
    --arch aarch64 \
    --bc_out lift.bc \
    --target_elf "$ELFPATH" \
    --dbg_fun_cfg "$2"
  echo -e "[\033[32mINFO\033[0m] Generate lift.bc."

  # LLVM bc -> target file
  case "$TARGET" in
    wasm-browser)
      echo -e "[\033[32mINFO\033[0m] Converting LLVM bitcode to WASM binary (for browser) ..."
      cd "${BIN_DIR}" || { echo "cd Failure"; exit 1; }
        $WASMCC -c lift.bc -o lift.o && \
        $WASMCC -o exe.wasm.html -L"./" -sWASM -sALLOW_MEMORY_GROWTH lift.o -lelfconv
      echo -e "[\033[32mINFO\033[0m] Generate WASM binary."
      return 0
    ;;
    wasm-host)
      echo -e "[\033[32mINFO\033[0m] Converting LLVM bitcode to WASM binary (for server) ..."
      cd "${BIN_DIR}" || { echo "cd Failure"; exit 1; }
        $WASMCC -c lift.bc -o lift.o && \
        $WASMCC -o exe.wasm -L"./" lift.o -lelfconv
      echo -e "[\033[32mINFO\033[0m] Generate WASM binary."
      return 0
    ;;
  esac

}

main "$@"