#!/usr/bin/env bash

setting() {

  BIN_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
  ROOT_DIR=${BIN_DIR}/../
  FRONT_DIR=${ROOT_DIR}/front
  BUILD_DIR=${ROOT_DIR}/build
  BUILD_FRONT_DIR=${BUILD_DIR}/front
  EMCC=emcc
  EMAR=emar
  EMCCFLAGS="-O0 -I${ROOT_DIR}/backend/remill/include"
  ELFCONV_MACROS="-DELFCONV_BROWSER_ENV=1"
  ELFCONV_DEBUG_MACROS=
  ELFPATH=$( realpath "$1" )

  if [ -n "$DEBUG" ]; then
    ELFCONV_DEBUG_MACROS="-DSYSCALL_DEBUG=1"
  fi

  if [ -n "$SERVER" ]; then
    ELFCONV_MACROS="-DELFCONV_SERVER_ENV=1"
  fi

}

main() {

  setting "$1"

  if [ $# -eq 0 ]; then
    echo "[ERROR] target ELF binary is not specified (lift.sh)."
    echo $#
    exit 1
  fi

  # build front
  echo "[INFO] Building libelfconv.a ..."
  cd "${FRONT_DIR}"
    $EMCC $EMCCFLAGS $ELFCONV_MACROS $ELFCONV_DEBUG_MACROS -o Entry.o -c Entry.cpp && \
    $EMCC $EMCCFLAGS $ELFCONV_MACROS $ELFCONV_DEBUG_MACROS -o Memory.o -c Memory.cpp && \
    $EMCC $EMCCFLAGS $ELFCONV_MACROS $ELFCONV_DEBUG_MACROS -o Syscall.o -c Syscall.cpp && \
    $EMCC $EMCCFLAGS $ELFCONV_MACROS $ELFCONV_DEBUG_MACROS -o VmIntrinsics.o -c VmIntrinsics.cpp && \
    $EMCC $EMCCFLAGS $ELFCONV_MACROS $ELFCONV_DEBUG_MACROS -o Util.o -c Util.cpp && \
    $EMCC $EMCCFLAGS $ELFCONV_MACROS $ELFCONV_DEBUG_MACROS -o elfconv.o -c elfconv.cpp && \
    $EMAR rcs libelfconv.a Entry.o Memory.o Syscall.o VmIntrinsics.o Util.o elfconv.o
    mv libelfconv.a "${BIN_DIR}/"
		rm *.o
  echo "[INFO] Generate libelfconv.a."

  # ELF -> LLVM bc
  cp -p "${BUILD_FRONT_DIR}/elflift" "${BIN_DIR}/"
  echo "[INFO] Converting ELF to LLVM bitcode ..."
    cd "${BIN_DIR}"
    ./elflift \
    --arch aarch64 \
    --bc_out lift.bc \
    --target_elf "$ELFPATH" \
    --dbg_fun_cfg "$2"
  echo "[INFO] Generate lift.bc."

  # LLVM bc -> target file
  case "$TARGET" in
    wasm-browser)
      echo "[INFO] Converting LLVM bitcode to WASM binary and glue code (for browser) ..."
      cd "${BIN_DIR}"
        $EMCC $EMCCFLAGS -c lift.bc -o lift.o && \
        $EMCC $EMCCFLAGS -o exe.wasm.html -L"./" -sWASM -sALLOW_MEMORY_GROWTH lift.o -lelfconv
      echo "[INFO] Generate WASM binary."
      return 0
    ;;
    wasm-host)
      echo "[INFO] Converting LLVM bitcode to WASM binary (for server) ..."
      cd "${BIN_DIR}"
        $EMCC $EMCCFLAGS -c lift.bc -o lift.o && \
        $EMCC $EMCCFLAGS -o exe.wasm -L"./" lift.o -lelfconv
      echo "[INFO] Generate WASM binary."
      return 0
    ;;
  esac

}

main "$@"