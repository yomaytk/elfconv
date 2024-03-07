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
  EMCCFLAGS="-O3 -I${ROOT_DIR}/backend/remill/include -I${ROOT_DIR}"
  ELFCONV_MACROS="-DELFCONV_BROWSER_ENV=1"
  ELFCONV_DEBUG_MACROS=
  ELFPATH=$( realpath "$1" )
  WASMCC=$EMCC
  WASMCCFLAGS=$EMCCFLAGS
  WASMAR=$EMAR
  WASISDKCXX=${WASI_SDK_PATH}/bin/clang++
  WASISDKAR=${WASI_SDK_PATH}/bin/ar
  WASISDKFLAGS="${OPTFLAGS} --sysroot=${WASI_SDK_PATH}/share/wasi-sysroot -I${ROOT_DIR}/backend/remill/include -I${ROOT_DIR}"

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
  echo "[INFO] Building elfconv-Runtime ..."
  if [ "$TARGET" = "wasm-host" ]; then
    WASMCC=$WASISDKCXX
    WASMCCFLAGS=$WASISDKFLAGS
    WASMAR=$WASISDKAR
  fi
  cd "${RUNTIME_DIR}" || { echo "cd Failure"; exit 1; }
    $WASMCC "$WASMCCFLAGS" $ELFCONV_MACROS "$ELFCONV_DEBUG_MACROS" -o Entry.o -c Entry.cpp && \
    $WASMCC "$WASMCCFLAGS" $ELFCONV_MACROS "$ELFCONV_DEBUG_MACROS" -o Memory.o -c Memory.cpp && \
    $WASMCC "$WASMCCFLAGS" $ELFCONV_MACROS "$ELFCONV_DEBUG_MACROS" -o Syscall.o -c Syscall.cpp && \
    $WASMCC "$WASMCCFLAGS" $ELFCONV_MACROS "$ELFCONV_DEBUG_MACROS" -o VmIntrinsics.o -c VmIntrinsics.cpp && \
    $WASMCC "$WASMCCFLAGS" $ELFCONV_MACROS "$ELFCONV_DEBUG_MACROS" -o Util.o -c "${UTILS_DIR}"/Util.cpp && \
    $WASMCC "$WASMCCFLAGS" $ELFCONV_MACROS "$ELFCONV_DEBUG_MACROS" -o elfconv.o -c "${UTILS_DIR}"/elfconv.cpp && \
    $WASMAR rcs libelfconv.a Entry.o Memory.o Syscall.o VmIntrinsics.o Util.o elfconv.o
    mv libelfconv.a "${BIN_DIR}/"
		rm *.o
  echo "[INFO] Generate libelfconv.a."

  # ELF -> LLVM bc
  cp -p "${BUILD_LIFTER_DIR}/elflift" "${BIN_DIR}/"
  echo "[INFO] Converting ELF to LLVM bitcode ..."
    cd "${BIN_DIR}" || { echo "cd Failure"; exit 1; }
    ./elflift \
    --arch aarch64 \
    --bc_out lift.bc \
    --target_elf "$ELFPATH" \
    --dbg_fun_cfg "$2"
  echo "[INFO] Generate lift.bc."

  # LLVM bc -> target file
  case "$TARGET" in
    wasm-browser)
      echo "[INFO] Converting LLVM bitcode to WASM binary (for browser) ..."
      cd "${BIN_DIR}" || { echo "cd Failure"; exit 1; }
        $WASMCC -c lift.bc -o lift.o && \
        $WASMCC -o exe.wasm.html -L"./" -sWASM -sALLOW_MEMORY_GROWTH lift.o -lelfconv
      echo "[INFO] Generate WASM binary."
      return 0
    ;;
    wasm-host)
      echo "[INFO] Converting LLVM bitcode to WASM binary (for server) ..."
      cd "${BIN_DIR}" || { echo "cd Failure"; exit 1; }
        $WASMCC -c lift.bc -o lift.o && \
        $WASMCC -o exe.wasm -L"./" lift.o -lelfconv
      echo "[INFO] Generate WASM binary."
      return 0
    ;;
  esac

}

main "$@"