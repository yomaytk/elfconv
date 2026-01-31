#!/usr/bin/env bash

LLVM_VERSION=16

GREEN="\033[32m"
RED="\033[31m"
NC="\033[0m"

set -e

# $1: path/to/elf
# $2: path/to/outdir
setting() {

  ROOT_DIR=$( dirname "${PWD}" )

  if [[ $( basename "${ROOT_DIR}" ) != "elfconv" ]]; then
    echo "[${RED}ERROR${NC}]: This script must be executed at 'path/to/elfconv/build' or 'path/to/elfconv/bin'."
    exit 1
  fi

  # elf
  ELFPATH=$( realpath "$1" )
  ELFNAME=$( basename "$ELFPATH" )
  # dir
  CUR_DIR="${PWD}"
  RUNTIME_DIR=${ROOT_DIR}/runtime
  UTILS_DIR=${ROOT_DIR}/utils
  BROWSER_DIR=${ROOT_DIR}/browser
  # common settings
  ELFCONV_COMMON_RUNTIMES="${RUNTIME_DIR}/Entry.cpp ${RUNTIME_DIR}/Memory.cpp ${RUNTIME_DIR}/Runtime.cpp ${RUNTIME_DIR}/VmIntrinsics.cpp ${UTILS_DIR}/Util.cpp ${UTILS_DIR}/elfconv.cpp"
  HOST_CPU=$(uname -p)
  RUNTIME_MACRO=
  FLOAT_STATUS_FLAG='0'
  MAINIR=
  MAINOBJ=
  OPTFLAGS="-O3"
  # native
  CXX=clang++-16
  CLANGFLAGS="${OPTFLAGS} -std=c++20 -static -I${ROOT_DIR}/backend/remill/include -I${ROOT_DIR}"
  # emscripten
  EMCC=em++
  EMCC_OPTION="-sASYNCIFY=0 -sINITIAL_MEMORY=536870912 -sSTACK_SIZE=16MB -sPTHREAD_POOL_SIZE=0 -pthread -sALLOW_MEMORY_GROWTH -sEXPORT_ES6 -sENVIRONMENT=web,worker $PRELOAD"
  EMCCFLAGS="${OPTFLAGS} -I${ROOT_DIR}/backend/remill/include -I${ROOT_DIR}"
  # wasi
  WASISDKCC="${WASI_SDK_PATH}/bin/clang++"
  WASISDKFLAGS="${OPTFLAGS} --sysroot=${WASI_SDK_PATH}/share/wasi-sysroot -D_WASI_EMULATED_SIGNAL -D_WASI_EMULATED_PROCESS_CLOCKS -D_WASI_EMULATED_MMAN -I${ROOT_DIR}/backend/remill/include -I${ROOT_DIR} -fno-exceptions"
  WASISDK_LINKFLAGS="-lwasi-emulated-process-clocks -lwasi-emulated-mman -lwasi-emulated-signal"
  WASMEDGE_COMPILE_OPT="wasmedge compile --optimize 3"

  if [[ -n "$DEBUG" ]]; then
    RUNTIME_MACRO="${RUNTIME_MACRO} -DELFC_RUNTIME_SYSCALL_DEBUG=1 -DELFC_RUNTIME_MULSECTIONS_WARNING=1 "
  fi

}

lifting() {

  # ELF -> LLVM bc
  echo -e "[${GREEN}INFO${NC}] ELF -> LLVM bitcode..."
  
  TARGET_ARCH=${HOST_CPU}
  if [[ "${TARGET}" = "*-wasi32" ]]; then
    TARGET_ARCH='wasi32'
  fi

  NORM_MODE="0"
  if [[ "${NORM_MODE}" == "1" ]]; then
    NORM_MODE="1"
  fi

  # fork emulation is enabled if targetgin wasm on browser.
  FORK_EMULATION=
  case "${TARGET}" in
    *-wasm)
      NORM_MODE="1"
      FORK_EMULATION="1"
      ;;
    *)
      FORK_EMULATION="0"
      ;;
  esac

  # copy `elflift` into current directory.
  cp -p ${ROOT_DIR}/build/lifter/elflift ${CUR_DIR}
  
  dbg_fun_vma=0
  if [[ -n "${DEBUG_FUNC_ADDR}" ]]; then
    dbg_fun_vma=${DEBUG_FUNC_ADDR}
  fi

  ${CUR_DIR}/elflift \
  --arch "$2" \
  --bc_out "${CUR_DIR}/${ELFNAME}.bc" \
  --target_elf "${ELFPATH}" \
  --dbg_fun_vma "${dbg_fun_vma}" \
  --bitcode_path "$4" \
  --target_arch "${TARGET_ARCH}" \
  --float_exception "${FLOAT_STATUS_FLAG}" \
  --norm_mode "1" \
  --fork_emulation "${FORK_EMULATION}"
 
  echo -e "[${GREEN}INFO${NC}] built ${ELFNAME}.bc"

  MAINIR="${CUR_DIR}/${ELFNAME}.bc"
  
  # TEXTIR creates the .ll file
  if [[ -n "${TEXTIR}" ]]; then
    MAINIR="${CUR_DIR}/${ELFNAME}.ll"
    if [[ -f "${CUR_DIR}/${ELFNAME}.bc" ]]; then
      llvm-dis-${LLVM_VERSION} "${CUR_DIR}/${ELFNAME}.bc" -o "${ELFNAME}.ll"
      rm "${CUR_DIR}/${ELFNAME}.bc"
    fi
    echo -e "[${GREEN}INFO${NC}] built ${ELFNAME}.ll "
  fi

}

prepare_js() {

  MAINGENJS="${CUR_DIR}/${ELFNAME}.generated.js"
  MAINGENWASM="${CUR_DIR}/${ELFNAME}.generated.wasm"
  OUTWASM="${CUR_DIR}/${ELFNAME}.wasm"
  OUTJS="${CUR_DIR}/${ELFNAME}.js"
  OUTHTML="${CUR_DIR}/main.html"

  # copy `process.js` and `coi-serviceworker.js`
  cp -p "${BROWSER_DIR}/process.js" "${CUR_DIR}"
  cp -p "${BROWSER_DIR}/coi-serviceworker.js" "${CUR_DIR}"

  # prepares js and Wasm
  cp ${MAINGENWASM} ${OUTWASM}
  cp ${CUR_DIR}/process.js ${OUTJS}
  # copy `_me_forked`.
  me_forked_val=$(sed -n 's/.*Module\["_me_forked"\][[:space:]]*=[[:space:]]*\([0-9]\+\).*/\1/p' ${MAINGENJS})
  sed -i "s/\(var[[:space:]]\+meForkedP[[:space:]]*=[[:space:]]*\).*/\1${me_forked_val};/" ${OUTJS}
  # copy `_me_execved`.
  me_execved_val=$(sed -n 's/.*Module\["_me_execved"\][[:space:]]*=[[:space:]]*\([0-9]\+\).*/\1/p' ${MAINGENJS})
  sed -i "s/\(var[[:space:]]\+meExecvedP[[:space:]]*=[[:space:]]*\).*/\1${me_execved_val};/" ${OUTJS}
  
  # prepare html file and set entry Wasm program.
  if [[ -n "${INITWASM}" ]]; then
    # copy `js-kernel.js` and `main.html`
    cp -p "${BROWSER_DIR}/js-kernel.js" "${CUR_DIR}"
    cp -p "${BROWSER_DIR}/main.html" "${OUTHTML}"
    sed -i "s/initProgram: '[^']*\.wasm'/initProgram: '${ELFNAME}.wasm'/" "${OUTHTML}"
  fi
  if [[ -f "${OUTHTML}" ]]; then
    # add the target ELF name to the `/usr/bin/`
    sed -i "s/var binList = \[\(.*[^ ]\)\]/var binList = [\1, \"${ELFNAME}\"]/;
      s/var binList = \[\]/var binList = [\"${ELFNAME}\"]/" "${OUTHTML}"
  else
    echo "${OUTHTML} is not found. Please prepare init Wams program."
    exit 1
  fi
  
  # --preload-file generates the mapped data file `exe.data`.
  if [[ -f "exe.data" ]]; then
    cp -p exe.data ${BROWSER_DIR}
  fi

  rm "${CUR_DIR}/process.js"
}

# $1: path to ELF
# $2: (optional) debug target function name
# $3: (optional) path to can be linked LLVM bitcode of semantics functions
main() {

  # environment variable settings
  setting "$1"

  if [[ -n "${READYJS}" ]]; then
    prepare_js
    exit 0
  fi
  
  # floating-point exception
  if [[ -n "${FLOAT_STATUS}" ]]; then
    FLOAT_STATUS_FLAG='1'
  fi

  # ELF -> LLVM bc
  if [[ -n "${NO_LIFTED}" ]]; then
    # skip lifting or compiling to wasm (used for development)
    echo -e "[${GREEN}INFO${NC}] NO_LIFTED is ON."
    for ext in ll bc; do
      llvmbcfile="${CUR_DIR}/${ELFNAME}.${ext}"
      if [[ -f "${llvmbcfile}" ]]; then
        MAINIR="${llvmbcfile}"
        break
      fi
    done
    if [[ -z "${MAINIR}" ]]; then
      echo "LLVM bitcode file is not found."
      exit 1
    fi
  else
    arch_name=${TARGET%%-*}
    lifting "$1" "${arch_name}" "$2" "$3"
  fi

  case "${TARGET}" in
    aarch64-*)
      RUNTIME_MACRO="${RUNTIME_MACRO} -DELF_IS_AARCH64"
      ;;
    amd64-*)
      RUNTIME_MACRO="${RUNTIME_MACRO} -DELF_IS_AMD64"
      ;;
    *)
      echo -e "Unsupported architecture of ELF: ${TARGET}."
      ;;
  esac

  # LLVM bc -> target file
  case "${TARGET}" in
    *-native)
      echo -e "[${GREEN}INFO${NC}] Compiling to Native binary (for ${HOST_CPU})... "
      RUNTIME_MACRO="${RUNTIME_MACRO} -DELFNAME=\"${ELFNAME}\""
      MAINOBJ="${ELFNAME}.o"

      if [[ -z "${NO_COMPILED}" ]]; then
        ${CXX} ${CLANGFLAGS} ${RUNTIME_MACRO} -c ${MAINIR} -o ${MAINOBJ}
      fi

      ${CXX} ${CLANGFLAGS} ${RUNTIME_MACRO} -o "${ELFNAME}.${HOST_CPU}" ${MAINOBJ} ${ELFCONV_COMMON_RUNTIMES} ${RUNTIME_DIR}/syscalls/SyscallNative.cpp
      echo -e " [${GREEN}INFO${NC}] built ${ELFNAME}.${HOST_CPU}"
      if [[ -n "${OUT_EXE}" ]]; then
        mv "${ELFNAME}.${HOST_CPU}" "${OUT_EXE}"
      fi
      return 0
    ;;
    *-wasm)
      RUNTIME_MACRO="${RUNTIME_MACRO} -DTARGET_IS_BROWSER=1 -DELFNAME=\"${ELFNAME}\""
      MAINOBJ="${CUR_DIR}/${ELFNAME}.wasm.o"
      PRELOAD=
      MAINGENJS="${CUR_DIR}/${ELFNAME}.generated.js"
      
      if [[ -n "${MOUNT_SETTING}" ]]; then
        PRELOAD="--preload-file ${MOUNT_SETTING}"
      fi
      
      if [[ -z "${NO_COMPILED}" ]]; then
        ${EMCC} ${EMCCFLAGS} ${RUNTIME_MACRO} -c ${MAINIR} -o ${MAINOBJ}
        echo -e "[${GREEN}INFO${NC}] built ${MAINOBJ}"
      else
        echo -e "[${GREEN}INFO${NC}] NO_COPMILED is ON."
      fi

      # creates wasm
      ${EMCC} ${EMCCFLAGS} ${RUNTIME_MACRO} ${EMCC_OPTION} ${PRELOAD} -o ${MAINGENJS} ${MAINOBJ} ${ELFCONV_COMMON_RUNTIMES} ${RUNTIME_DIR}/syscalls/SyscallBrowser.cpp
      echo -e "[${GREEN}INFO${NC}] built ${ELFNAME}.wasm and ${ELFNAME}.js and ${ELFNAME}.html."
      
      # prepare Js and Wasm
      prepare_js

      return 0
    ;;
    *-wasi32)
      RUNTIME_MACRO="${RUNTIME_MACRO} -DTARGET_IS_WASI=1 -DELFNAME=\"${ELFNAME}\""
      MAINOBJ="${ELFNAME}.wasi.o"

      if [[ -z "${NO_COMPILED}" ]]; then
        ${WASISDKCC} ${WASISDKFLAGS} ${RUNTIME_MACRO} -c ${MAINIR} -o ${MAINOBJ}
      fi

      echo -e "[${GREEN}INFO${NC}] Compiling to Wasm (for WASI)... "
      ${WASISDKCC} ${WASISDKFLAGS} ${WASISDK_LINKFLAGS} ${RUNTIME_MACRO} -o "${ELFNAME}.wasm" ${MAINOBJ} ${ELFCONV_COMMON_RUNTIMES} ${RUNTIME_DIR}/syscalls/SyscallWasi.cpp
      echo -e "[${GREEN}INFO${NC}] built ${ELFNAME}.wasm"
      $WASMEDGE_COMPILE_OPT "${ELFNAME}.wasm" "${ELFNAME}_o3.wasm"
      echo -e "[${GREEN}INFO${NC}] built ${ELFNAME}_o3.wasm"
      return 0
    ;;
  esac  
}
