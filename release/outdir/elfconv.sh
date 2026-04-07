#!/usr/bin/env bash

set -e

GREEN="\033[32m"
ORANGE="\033[33m"
RED="\033[31m"
NC="\033[0m"

setting() {

  EMCC=em++
  WASISDKCXX=${WASI_SDK_PATH}/bin/clang++
  ELFPATH=$( realpath "$1" )
  ELFNAME=$( basename "$ELFPATH" )
  RT_OP="-O3"
  OUT="out"
  BROWSER_DIR="./browser"
  EMCC_OPTION="-sASYNCIFY=0 -sINITIAL_MEMORY=536870912 -sSTACK_SIZE=16MB -sPTHREAD_POOL_SIZE=0 -pthread -sALLOW_MEMORY_GROWTH -sEXPORT_ES6 -sENVIRONMENT=web,worker"
  WASISDK_COMPILEFLAGS="--sysroot=${WASI_SDK_PATH}/share/wasi-sysroot -D_WASI_EMULATED_SIGNAL -D_WASI_EMULATED_PROCESS_CLOCKS -D_WASI_EMULATED_MMAN -fno-exceptions"
  WASISDK_LINKFLAGS="-lwasi-emulated-process-clocks -lwasi-emulated-mman -lwasi-emulated-signal"
  WASMEDGE_COMPILE_OPT="wasmedge compile --optimize 3"

}

prepare_js() {

  MAINGENJS="${OUT}/${ELFNAME}.generated.js"
  MAINGENWASM="${OUT}/${ELFNAME}.generated.wasm"
  OUTWASM="${OUT}/${ELFNAME}.wasm"
  OUTJS="${OUT}/${ELFNAME}.js"
  OUTHTML="${OUT}/main.html"

  cp -p "${BROWSER_DIR}/process.js" "${OUT}"
  cp -p "${BROWSER_DIR}/coi-serviceworker.js" "${OUT}"

  cp ${MAINGENWASM} ${OUTWASM}
  cp ${OUT}/process.js ${OUTJS}
  me_forked_val=$(sed -n 's/.*Module\["_me_forked"\][[:space:]]*=[[:space:]]*\([0-9]\+\).*/\1/p' ${MAINGENJS})
  sed -i "s/\(var[[:space:]]\+meForkedP[[:space:]]*=[[:space:]]*\).*/\1${me_forked_val};/" ${OUTJS}
  me_execved_val=$(sed -n 's/.*Module\["_me_execved"\][[:space:]]*=[[:space:]]*\([0-9]\+\).*/\1/p' ${MAINGENJS})
  sed -i "s/\(var[[:space:]]\+meExecvedP[[:space:]]*=[[:space:]]*\).*/\1${me_execved_val};/" ${OUTJS}

  if [[ -n "${INITWASM}" ]]; then
    cp -p "${BROWSER_DIR}/js-kernel.js" "${OUT}"
    cp -p "${BROWSER_DIR}/main.html" "${OUTHTML}"
    sed -i "s/initProgram: '[^']*\.wasm'/initProgram: '${ELFNAME}.wasm'/" "${OUTHTML}"
  fi
  if [[ -f "${OUTHTML}" ]]; then
    sed -i "s/var binList = \[\(.*[^ ]\)\]/var binList = [\1, \"${ELFNAME}\"]/;
      s/var binList = \[\]/var binList = [\"${ELFNAME}\"]/" "${OUTHTML}"
  else
    echo "${OUTHTML} is not found. Please prepare init Wasm program."
    exit 1
  fi

  if [[ -f "${OUT}/preload-manifest.json" ]]; then
    echo -e "[${GREEN}INFO${NC}] Preload manifest found, copying data files."
  fi

  rm "${OUT}/process.js"
}

main() {

  setting "$1"

  if [ $# -eq 0 ]; then
    echo -e "[${RED}ERROR${NC}] target ELF binary is not specified."
    exit 1
  fi

  mkdir -p ${OUT}

  if [[ -n "${READYJS}" ]]; then
    prepare_js
    exit 0
  fi

  case "$TARGET" in
    aarch64-*)
      RT_OP="$RT_OP -DELF_IS_AARCH64"
      ;;
    *)
      echo -e "Unsupported architecture of ELF: $TARGET."
      exit 1
      ;;
  esac

  FORK_EMULATION="0"
  case "${TARGET}" in
    *-wasm)
      FORK_EMULATION="1"
      ;;
  esac

  echo -e "[${GREEN}INFO${NC}] Converting ELF to LLVM bitcode ..."
  export LD_LIBRARY_PATH="./lib:${LD_LIBRARY_PATH}"
  ./bin/elflift \
    --arch aarch64 \
    --bc_out ${OUT}/lift.bc \
    --target_elf "$ELFPATH" \
    --bitcode_path ./bitcode \
    --target_arch "$(uname -p)" \
    --float_exception "0" \
    --norm_mode "1" \
    --fork_emulation "${FORK_EMULATION}"
  echo -e "[${GREEN}INFO${NC}] Generate lift.bc."

  case "$TARGET" in
    *-wasm)
      RT_OP="$RT_OP -DTARGET_IS_BROWSER=1 -DELFNAME=\"${ELFNAME}\""
      echo -e "[${GREEN}INFO${NC}] Converting LLVM bitcode to WASM binary (for browser) ..."
      $EMCC $RT_OP ${EMCC_OPTION} -o ${OUT}/${ELFNAME}.generated.js ${OUT}/lift.bc -L"./lib" -lelfconvbrowser

      if [[ -n "${MOUNT_SETTING}" ]]; then
        echo -e "[${GREEN}INFO${NC}] Packing preload data for: ${MOUNT_SETTING}"
        python3 ./scripts/pack-preload.py ${MOUNT_SETTING} -o "${OUT}"
      fi

      echo -e "[${GREEN}INFO${NC}] built ${ELFNAME}.wasm and ${ELFNAME}.js."

      prepare_js

      rm ${OUT}/lift.*
      return 0
    ;;
    *-wasi32)
      RT_OP="$RT_OP -DTARGET_IS_WASI=1 -DELFNAME=\"${ELFNAME}\" ${WASISDK_COMPILEFLAGS}"
      echo -e "[${GREEN}INFO${NC}] Converting LLVM bitcode to WASM binary (for server) ..."
      $WASISDKCXX $RT_OP ${WASISDK_LINKFLAGS} -o ${OUT}/exe.wasm -L"./lib" ${OUT}/lift.bc -lelfconvwasi
      rm ${OUT}/lift.*
      echo -e "[${GREEN}INFO${NC}] Generate WASM binary."
      $WASMEDGE_COMPILE_OPT ${OUT}/exe.wasm ${OUT}/exe_o3.wasm
      echo -e "[${GREEN}INFO${NC}] WasmEdge optimization was done. (exe_o3.wasm)"

      return 0
    ;;
  esac

}

main "$@"
