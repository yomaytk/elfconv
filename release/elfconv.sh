#!/usr/bin/env bash

setting() {

  WASMCC=emcc
  WASISDKCXX=${WASI_SDK_PATH}/bin/clang++
  OPTFLAGS="-O3"
  ELFCONV_MACROS="-DTARGET_IS_BROWSER=1"
  ELFPATH=$( realpath "$1" )
  BITCODEPATH=$( realpath "$2" )

  if [ "$TARGET" = "wasm-host" ]; then
    ELFCONV_MACROS="-DTARGET_IS_WASI=1"
  fi

}

main() {

  setting "$1" "$2"

  if [ $# -eq 0 ]; then
    echo "[ERROR] target ELF binary is not specified (lift.sh)."
    echo $#
    exit 1
  fi

  # ELF -> LLVM bc
  echo -e "[\033[32mINFO\033[0m] Converting ELF to LLVM bitcode ..."
    ./bin/elflift \
    --arch aarch64 \
    --bc_out lift.bc \
    --target_elf "$ELFPATH" \
    --bitcode_path "$BITCODEPATH" && \
  echo -e "[\033[32mINFO\033[0m] Generate lift.bc."

  # LLVM bc -> target file
  case "$TARGET" in
    wasm-browser)
      echo -e "[\033[32mINFO\033[0m] Converting LLVM bitcode to WASM binary (for browser) ..."
        $WASMCC -c lift.bc -o lift.o && \
        $WASMCC -o exe.wasm.html -L"./lib" -sWASM -sALLOW_MEMORY_GROWTH lift.o -lelfconvbrowser
      echo -e "[\033[32mINFO\033[0m] Generate WASM binary."
      return 0
    ;;
    wasm-host)
      WASMCC=$WASISDKCXX
      echo -e "[\033[32mINFO\033[0m] Converting LLVM bitcode to WASM binary (for server) ..."
        $WASMCC -c lift.bc -o lift.o && \
        $WASMCC -o exe.wasm -L"./lib" lift.o -lelfconvwasi
      echo -e "[\033[32mINFO\033[0m] Generate WASM binary."
      return 0
    ;;
  esac

}

main "$@"