#!/usr/bin/env bash

LLVM_VERSION=16

GREEN="\033[32m"
RED="\033[31m"
NC="\033[0m"

set -e

setting() {

  ROOT_DIR=$( dirname "$PWD" )

  if [[ $( basename "$ROOT_DIR" ) != "elfconv" ]]; then
    echo "[${RED}ERROR${NC}]: This script must be executed at path/to/elfconv/build."
    exit 1
  fi

  # elf
  ELFPATH=$( realpath "$1" )
  ELFNAME=$( basename "$ELFPATH" )
  # dir
  RUNTIME_DIR=${ROOT_DIR}/runtime
  UTILS_DIR=${ROOT_DIR}/utils
  AARCH64_TEST_DIR=${ROOT_DIR}/tests/aarch64
  BUILD_DIR=${ROOT_DIR}/build
  BUILD_LIFTER_DIR=${BUILD_DIR}/lifter
  BUILD_TESTS_AARCH64_DIR=${BUILD_DIR}/tests/aarch64
  BROWSER_DIR=${ROOT_DIR}/examples/browser
  # common settings
  ELFCONV_COMMON_RUNTIMES="${RUNTIME_DIR}/Entry.cpp ${RUNTIME_DIR}/Memory.cpp ${RUNTIME_DIR}/Runtime.cpp ${RUNTIME_DIR}/VmIntrinsics.cpp ${UTILS_DIR}/Util.cpp ${UTILS_DIR}/elfconv.cpp"
  HOST_CPU=$(uname -p)
  RUNTIME_MACRO=
  FLOAT_STATUS_FLAG='0'
  MAINIR="$ELFNAME.bc"
  MAINOBJ=
  # native
  CXX=clang++-16
  OPTFLAGS="-O3"
  CLANGFLAGS="${OPTFLAGS} -std=c++20 -static -I${ROOT_DIR}/backend/remill/include -I${ROOT_DIR}"
  # emscripten
  EMCC=emcc
  EMCC_OPTION="-sASYNCIFY=0 -sPTHREAD_POOL_SIZE=0 -pthread -sALLOW_MEMORY_GROWTH -sEXPORT_ES6 -sENVIRONMENT=web,worker $PRELOAD"
  EMCCFLAGS="${OPTFLAGS} -I${ROOT_DIR}/backend/remill/include -I${ROOT_DIR}"
  # wasi
  WASISDKCC="${WASI_SDK_PATH}/bin/clang++"
  WASISDKFLAGS="${OPTFLAGS} --sysroot=${WASI_SDK_PATH}/share/wasi-sysroot -D_WASI_EMULATED_SIGNAL -D_WASI_EMULATED_PROCESS_CLOCKS -D_WASI_EMULATED_MMAN -I${ROOT_DIR}/backend/remill/include -I${ROOT_DIR} -fno-exceptions"
  WASISDK_LINKFLAGS="-lwasi-emulated-process-clocks -lwasi-emulated-mman -lwasi-emulated-signal"
  WASMEDGE_COMPILE_OPT="wasmedge compile --optimize 3"

  if [ -n "$DEBUG" ]; then
    RUNTIME_MACRO="${RUNTIME_MACRO} -DELFC_RUNTIME_SYSCALL_DEBUG=1 -DELFC_RUNTIME_MULSECTIONS_WARNING=1 "
  fi

}

lifting() {

  # ELF -> LLVM bc
  echo -e "[${GREEN}INFO${NC}] ELF -> LLVM bitcode..."
  
  TARGET_ARCH=$HOST_CPU
  if [ "$TARGET" = "*-wasi32" ]; then
    TARGET_ARCH='wasi32'
  fi

  NORM_MODE="0"
  if [ "$TEST_MODE" = "1" ]; then
    NORM_MODE="1"
  fi

  # fork emulation is enabled if targetgin wasm on browser.
  FORK_EMULATION=
  case "$TARGET" in
    *-wasm)
      NORM_MODE="1"
      FORK_EMULATION="1"
      ;;
    *)
      FORK_EMULATION="0"
      ;;
  esac
  
  ${BUILD_LIFTER_DIR}/elflift \
  --arch "$2" \
  --bc_out "$ELFNAME.bc" \
  --target_elf "$ELFPATH" \
  --dbg_fun_cfg "$3" \
  --bitcode_path "$4" \
  --target_arch "$TARGET_ARCH" \
  --float_exception "$FLOAT_STATUS_FLAG" \
  --norm_mode "$NORM_MODE" \
  --fork_emulation "$FORK_EMULATION"
 
  echo -e "[${GREEN}INFO${NC}] built $ELFNAME.bc"
  
  # TEXTIR creates the .ll file
  if [ -n "$TEXTIR" ]; then
    MAINIR="$ELFNAME.ll"
    llvm-dis-${LLVM_VERSION} "$ELFNAME.bc" -o "$ELFNAME.ll"
    echo -e "[${GREEN}INFO${NC}] built $ELFNAME.ll "
  fi

}

prepare_js() {

  MAINGENJS="${BUILD_DIR}/$ELFNAME.generated.js"
  MAINGENWASM="${BUILD_DIR}/$ELFNAME.generated.wasm"
  OUTWASM="${BROWSER_DIR}/$ELFNAME.wasm"
  OUTJS="${BROWSER_DIR}/$ELFNAME.js"

  # prepares js and Wasm
  cp $MAINGENWASM $OUTWASM
  cp ${BROWSER_DIR}/process.js $OUTJS
  # copy `_me_forked`.
  me_forked_val=$(sed -n 's/.*Module\["_me_forked"\]=\([0-9]*\).*/\1/p' $MAINGENJS)
  sed -i "s/\(var[[:space:]]\+meForkedP[[:space:]]*=[[:space:]]*\).*/\1$me_forked_val;/" $OUTJS
  # copy `_me_execved`.
  me_execved_val=$(sed -n 's/.*Module\["_me_execved"\]=\([0-9]*\).*/\1/p' $MAINGENJS)
  sed -i "s/\(var[[:space:]]\+meExecvedP[[:space:]]*=[[:space:]]*\).*/\1$me_execved_val;/" $OUTJS
  
  # set entry Wasm program.
  if [ -n "$INITWASM" ]; then
    sed -i "s/initProgram: '[^']*\.wasm'/initProgram: '$ELFNAME.wasm'/" ${BROWSER_DIR}/exe.html
  fi
  
  # --preload-file generates the mapped data file `exe.data`.
  if [ -f "exe.data" ]; then
    cp exe.data ${ROOT_DIR}/examples/browser
  fi
}

# $1: path to ELF
# $2: (optional) debug target function name
# $3: (optional) path to can be linked LLVM bitcode of semantics functions
main() {

  # environment variable settings
  setting "$1"

  if [ -n "$READYJS" ]; then
    prepare_js
    exit 0
  fi
  
  cd $BUILD_DIR

  # floating-point exception
  if [ -n "$FLOAT_STATUS" ]; then
    FLOAT_STATUS_FLAG='1'
  fi

  # ELF -> LLVM bc
  if [ -n "$NO_LIFTED" ]; then
    echo -e "[${GREEN}INFO${NC}] NO_LIFTED is ON."
  fi

  # skip lifting or compiling to wasm (used for development)
  if [ -n "$NO_LIFTED" ]; then
    MAINIR="$ELFNAME.ll"
  else
    arch_name=${TARGET%%-*}
    lifting "$1" "$arch_name" "$2" "$3"
  fi

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

  # LLVM bc -> target file
  case "$TARGET" in
    *-native)
      echo -e "[${GREEN}INFO${NC}] Compiling to Native binary (for $HOST_CPU)... "
      MAINOBJ="$ELFNAME.o"
      
      if [ -z "$NO_COMPILED" ]; then
        $CXX $CLANGFLAGS $RUNTIME_MACRO -c $MAINIR -o $MAINOBJ
      fi
      
      $CXX $CLANGFLAGS $RUNTIME_MACRO -o "exe.${HOST_CPU}" $MAINOBJ $ELFCONV_COMMON_RUNTIMES ${RUNTIME_DIR}/syscalls/SyscallNative.cpp
      echo -e " [${GREEN}INFO${NC}] built exe.${HOST_CPU}"
      if [ -n "$OUT_EXE" ]; then
        mv "exe.${HOST_CPU}" "$OUT_EXE"
      fi
      return 0
    ;;
    *-wasm)
      RUNTIME_MACRO="$RUNTIME_MACRO -DTARGET_IS_BROWSER=1"
      MAINOBJ="${BUILD_DIR}/$ELFNAME.wasm.o"
      PRELOAD=
      MAINGENJS="${BUILD_DIR}/$ELFNAME.generated.js"
      
      if [ -n "$MOUNT_DIR" ]; then
        PRELOAD="--preload-file ${MOUNT_DIR}"
      fi
      
      if [ -z "$NO_COMPILED" ]; then
        $EMCC $EMCCFLAGS $RUNTIME_MACRO -c $MAINIR -o $MAINOBJ
        echo -e "[${GREEN}INFO${NC}] built lift.wasm.o"
      else
        echo -e "[${GREEN}INFO${NC}] NO_COPMILED is ON."
      fi

      # compiles wasm
      $EMCC $EMCCFLAGS $RUNTIME_MACRO $EMCC_OPTION -o $MAINGENJS $MAINOBJ $ELFCONV_COMMON_RUNTIMES ${RUNTIME_DIR}/syscalls/SyscallBrowser.cpp
      echo -e "[${GREEN}INFO${NC}] built exe.wasm and exe.js"
      
      # prepare Js and Wasm
      prepare_js

      return 0
    ;;
    *-wasi32)
      RUNTIME_MACRO="$RUNTIME_MACRO -DTARGET_IS_WASI=1"
      MAINOBJ=lift.wasi.o

      if [ -z "$NO_COMPILED" ]; then
        $WASISDKCC $WASISDKFLAGS $RUNTIME_MACRO -c lift.ll -o lift.wasi.o
      fi
      
      echo -e "[${GREEN}INFO${NC}] Compiling to Wasm (for WASI)... "
      $WASISDKCC $WASISDKFLAGS $WASISDK_LINKFLAGS $RUNTIME_MACRO -o exe.wasm $MAINOBJ $ELFCONV_COMMON_RUNTIMES ${RUNTIME_DIR}/syscalls/SyscallWasi.cpp
      echo -e "[${GREEN}INFO${NC}] built exe.wasm"
      $WASMEDGE_COMPILE_OPT exe.wasm exe_o3.wasm
      echo -e "[${GREEN}INFO${NC}] built exe_opt.wasm"
      return 0
    ;;
  esac  
}

main "$@"