#!/usr/bin/env bash

GREEN="\033[32m"
ORANGE="\033[33m"
RED="\033[31m"
NC="\033[0m"

setting() {

  EMCC=emcc
  WASISDKCXX=${WASI_SDK_PATH}/bin/clang++
  ELFPATH=$( realpath "$1" )
  RT_OP="-O3"
  OUT="out"
  PRELOAD=
  WASISDK_COMPILEFLAGS="--sysroot=${WASI_SDK_PATH}/share/wasi-sysroot -D_WASI_EMULATED_SIGNAL -D_WASI_EMULATED_PROCESS_CLOCKS -D_WASI_EMULATED_MMAN -fno-exceptions"
  WASISDK_LINKFLAGS="-lwasi-emulated-process-clocks -lwasi-emulated-mman -lwasi-emulated-signal"
  WASMEDGE_COMPILE_OPT="wasmedge compile --optimize 3"

}

main() {

  setting "$1" "$2"

  mkdir -p out

  if [ $# -eq 0 ]; then
    echo "[${RED}ERROR${NC}] target ELF binary is not specified."
    echo $#
    exit 1
  fi

  # only ELF/aarch64 is supported at current release.
  case "$TARGET" in
    aarch64-*)
      RT_OP="$RT_OP -DELF_IS_AARCH64"
      ;;
    *)
      echo -e "Unsupported architecture of ELF: $TARGET."
      exit 1
      ;;
  esac

  # ELF -> LLVM bc
  echo -e "[${GREEN}INFO${NC}] Converting ELF to LLVM bitcode ..."
    ./bin/elflift \
    --arch aarch64 \
    --bc_out ${OUT}/lift.bc \
    --target_elf "$ELFPATH" \
    --bitcode_path ./bitcode && \
  echo -e "[${GREEN}INFO${NC}] Generate lift.bc."

  # LLVM bc -> target file
  case "$TARGET" in
    *-wasm)
      RT_OP="$RT_OP -DTARGET_IS_BROWSER=1"
      if [ -n "$MOUNTDIR" ]; then
        PRELOAD="--preload-file ${MOUNTDIR}"
      fi
      echo -e "[${GREEN}INFO${NC}] Converting LLVM bitcode to WASM binary (for browser) ..."
        $EMCC $RT_OP -o ${OUT}/exe.js ${OUT}/lift.bc -L"./lib" -sWASM -sALLOW_MEMORY_GROWTH -sASYNCIFY -sEXPORT_ES6 -sENVIRONMENT=web $PRELOAD --js-library "./lib/emscripten-pty.js" -lelfconvbrowser
        rm ${OUT}/lift.*
      echo -e "[${GREEN}INFO${NC}] Generate WASM binary."
      
      # specify the binary name
      if [ -n "$OUT_EXE" ]; then
        cp ${OUT}/exe.wasm ${OUT}/${OUT_EXE}
        sed -i "s/exe\.wasm/${OUT_EXE}/g" ${OUT}/exe.js
        sed -i "s/this\.program/${OUT_EXE}/g" ${OUT}/exe.js
      fi

      # move exe.data to the current directory
      if [ -e "${OUT}/exe.data" ]; then
        mv "${OUT}/exe.data" .
      fi

      return 0
    ;;
    *-wasi32)
      RT_OP="$RT_OP -DTARGET_IS_WASI=1 ${WASISDK_COMPILEFLAGS} ${WASISDK_LINKFLAGS}"
      echo -e "[${GREEN}INFO${NC}] Converting LLVM bitcode to WASM binary (for server) ..."
        $WASISDKCXX $RT_OP -o ${OUT}/exe.wasm -L"./lib" ${OUT}/lift.bc -lelfconvwasi
        rm ${OUT}/lift.*
      echo -e "[${GREEN}INFO${NC}] Generate WASM binary."
        $WASMEDGE_COMPILE_OPT ${OUT}/exe.wasm ${OUT}/exe_o3.wasm
      echo -e "[${GREEN}INFO${NC}] WasmEdge optimization was done. (exe_o3.wasm)"
      
      return 0
    ;;
  esac

}

main "$@"