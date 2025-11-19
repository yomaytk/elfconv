#!/usr/bin/env bash

LLVM_VERSION=16
ROOT_DIR=${HOME}/workspace/compiler/elfconv

GREEN="\033[32m"
NC="\033[0m"

set -e

setting() {

  if [ -n "$NEW_ROOT" ]; then
    ROOT_DIR="$NEW_ROOT"
  fi

  RUNTIME_DIR=${ROOT_DIR}/runtime
  UTILS_DIR=${ROOT_DIR}/utils
  AARCH64_TEST_DIR=${ROOT_DIR}/tests/aarch64
  BUILD_DIR=${ROOT_DIR}/build
  BUILD_LIFTER_DIR=${BUILD_DIR}/lifter
  BUILD_TESTS_AARCH64_DIR=${BUILD_DIR}/tests/aarch64
  CXX=clang++-16
  OPTFLAGS="-O3"
  CLANGFLAGS="${OPTFLAGS} -std=c++20 -static -I${ROOT_DIR}/backend/remill/include -I${ROOT_DIR}"
  EMCC=emcc
  EMCCFLAGS="${OPTFLAGS} -I${ROOT_DIR}/backend/remill/include -I${ROOT_DIR}"
  WASISDKCC="${WASI_SDK_PATH}/bin/clang++"
  WASISDKFLAGS="${OPTFLAGS} --sysroot=${WASI_SDK_PATH}/share/wasi-sysroot -D_WASI_EMULATED_SIGNAL -D_WASI_EMULATED_PROCESS_CLOCKS -D_WASI_EMULATED_MMAN -I${ROOT_DIR}/backend/remill/include -I${ROOT_DIR} -fno-exceptions"
  WASISDK_LINKFLAGS="-lwasi-emulated-process-clocks -lwasi-emulated-mman -lwasi-emulated-signal"
  ELFCONV_COMMON_RUNTIMES="${RUNTIME_DIR}/Entry.cpp ${RUNTIME_DIR}/Memory.cpp ${RUNTIME_DIR}/Runtime.cpp ${RUNTIME_DIR}/VmIntrinsics.cpp ${UTILS_DIR}/Util.cpp ${UTILS_DIR}/elfconv.cpp"
  WASMEDGE_COMPILE_OPT="wasmedge compile --optimize 3"
  HOST_CPU=$(uname -p)
  RUNTIME_MACRO=''
  FLOAT_STATUS_FLAG='0'
  EMCC_ALL_OPTION=

  if [ -n "$DEBUG" ]; then
    RUNTIME_MACRO="${RUNTIME_MACRO} -DELFC_RUNTIME_SYSCALL_DEBUG=1 -DELFC_RUNTIME_MULSECTIONS_WARNING=1 "
  fi

}

aarch64_test() {

  # generate LLVM bc
  echo -e "[${GREEN}INFO${NC}] AArch64 Test Lifting Start."
  cd "${BUILD_TESTS_AARCH64_DIR}" && \
    ./aarch64_test_lift \
    --arch aarch64 \
    --bc_out ./aarch64_test.bc
  echo -e "[${GREEN}INFO${NC}] built aarch64_lift.bc"
  llvm-dis-${LLVM_VERSION} aarch64_test.bc -o aarch64_test.ll
  echo -e "[${GREEN}INFO${NC}] built aarch64_lift.ll"  

  RUNTIME_MACRO="${RUNTIME_MACRO} -DELF_IS_AARCH64"
  # generate execute file (lift_test.aarch64)
  $CXX $CLANGFLAGS $RUNTIME_MACRO -o lift_test.aarch64 aarch64_test.ll ${AARCH64_TEST_DIR}/Test.cpp ${AARCH64_TEST_DIR}/TestHelper.cpp \
  ${AARCH64_TEST_DIR}/TestInstructions.cpp $ELFCONV_COMMON_RUNTIMES ${RUNTIME_DIR}/syscalls/SyscallNative.cpp
  echo -e "[${GREEN}INFO${NC}] built lift_test.aarch64"

}

lifting() {

  # ELF -> LLVM bc
  echo -e "[${GREEN}INFO${NC}] ELF -> LLVM bitcode..."
  elf_path=$( realpath "$1" )
  
  target_arch=$HOST_CPU
  if [ "$TARGET" = "*-wasi32" ]; then
    target_arch='wasi32'
  fi

  norm_mode="0"
  if [ "$TEST_MODE" = "1" ] || [ "$DEBUG_QEMU" = "on" ]; then
    norm_mode="1"
  fi

  fork_emulation="0"
  if [ "$FORK_EMULATION" = "1" ]; then
    echo -e "[${GREEN}INFO${NC}] FORK emulation (on emscripten browser) is enabled."
    fork_emulation="1"
  fi
  
  ${BUILD_LIFTER_DIR}/elflift \
  --arch "$2" \
  --bc_out ./lift.bc \
  --target_elf "$elf_path" \
  --dbg_fun_cfg "$3" \
  --bitcode_path "$4" \
  --target_arch "$target_arch" \
  --float_exception "$FLOAT_STATUS_FLAG" \
  --norm_mode "$norm_mode" \
  --fork_emulation "$fork_emulation"
 
  echo -e "[${GREEN}INFO${NC}] built lift.bc"
  
  # (optional) for debug
  llvm-dis-${LLVM_VERSION} lift.bc -o lift.ll
  echo -e "[${GREEN}INFO${NC}] built lift.ll "

}

# $1: path to ELF
# $2: (optional) debug target function name
# $3: (optional) path to can be linked LLVM bitcode of semantics functions
main() {

  # environment variable settings
  setting

  cd $BUILD_DIR

  # aarch64 lifting test
  if [ -n "$AARCH64_TEST" ]; then
    aarch64_test
    return 0
  fi

  # floating-point exception
  if [ -n "$FLOAT_STATUS" ]; then
    FLOAT_STATUS_FLAG='1'
  fi

  # ELF -> LLVM bc
  if [ -n "$NO_LIFTED" ]; then
    echo -e "[${GREEN}INFO${NC}] NO_LIFTED is ON."
  fi

  if [ -z "$NO_LIFTED" ] && [ -z "$NO_COMPILED" ]; then
    arch_name=${TARGET%%-*}
    lifting "$1" "$arch_name" "$2" "$3"
  fi

  if [ -n "$DEBUG_QEMU" ]; then
    ELFCONV_COMMON_RUNTIMES="$ELFCONV_COMMON_RUNTIMES ${ROOT_DIR}/debugs/generated/qemulog2c.c"
    RUNTIME_MACRO="$RUNTIME_MACRO -DDEBUG_WITH_QEMU=1"
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

  if [ -n "$NOSYS_EXIT" ]; then
    RUNTIME_MACRO="$RUNTIME_MACRO -DNOSYS_EXIT"
  fi

  TARGET_PRG=
  # LLVM bc -> target file
  case "$TARGET" in
    *-native)
      echo -e "[${GREEN}INFO${NC}] Compiling to Native binary (for $HOST_CPU)... "
      TARGET_PRG=lift.o
      
      if [ -z "$NO_COMPILED" ]; then
        $CXX $CLANGFLAGS $RUNTIME_MACRO -c lift.ll -o lift.o
      fi
      
      $CXX $CLANGFLAGS $RUNTIME_MACRO -o "exe.${HOST_CPU}" $TARGET_PRG $ELFCONV_COMMON_RUNTIMES ${RUNTIME_DIR}/syscalls/SyscallNative.cpp
      echo -e " [${GREEN}INFO${NC}] built exe.${HOST_CPU}"
      if [ -n "$OUT_EXE" ]; then
        mv "exe.${HOST_CPU}" "$OUT_EXE"
      fi
      return 0
    ;;
    *-wasm)
      RUNTIME_MACRO="$RUNTIME_MACRO -DTARGET_IS_BROWSER=1"
      TARGET_PRG=lift.wasm.o
      
      PRELOAD=
      if [ -n "$MOUNT_DIR" ]; then
        PRELOAD="--preload-file ${MOUNT_DIR}"
      fi
      
      if [ -z "$NO_COMPILED" ]; then
        $EMCC $EMCCFLAGS $RUNTIME_MACRO -c lift.ll -o lift.wasm.o
        echo -e "[${GREEN}INFO${NC}] built lift.wasm.o"
      else
        echo -e "[${GREEN}INFO${NC}] NO_COPMILED is ON."
      fi

      EMCC_ASYNC_OPTION="-sPTHREAD_POOL_SIZE=2 -pthread -sPROXY_TO_PTHREAD"
      
      if [ -n "$FORK_EMULATION" ]; then
        EMCC_ASYNC_OPTION="-sASYNCIFY=0 -sPTHREAD_POOL_SIZE=0 -pthread"
        RUNTIME_MACRO="$RUNTIME_MACRO -D_FORK_EMULATION_"
      fi

      if [ -n "$INDEPENDENT_WASM" ]; then
        EMCC_ALL_OPTION="$EMCC_ASYNC_OPTION -sALLOW_MEMORY_GROWTH -sEXPORT_ES6 -sENVIRONMENT=web,worker"
      else
        EMCC_ALL_OPTION="$EMCC_ASYNC_OPTION -sALLOW_MEMORY_GROWTH -sEXPORT_ES6 -sENVIRONMENT=web,worker $PRELOAD --js-library ${ROOT_DIR}/xterm-pty/emscripten-pty.js"
      fi

      $EMCC $EMCCFLAGS $RUNTIME_MACRO -o exe.js $EMCC_ALL_OPTION $TARGET_PRG $ELFCONV_COMMON_RUNTIMES ${RUNTIME_DIR}/syscalls/SyscallBrowser.cpp
      echo -e "[${GREEN}INFO${NC}] built exe.wasm and exe.js"
      
      # move generated files to `examples/browser`

      out_js="exe.js"
      
      if [ -n "$OUT_JS" ]; then
        out_js="$OUT_JS"
        cp exe.js $out_js
      fi

      if [ -n "$OUT_WASM" ]; then
        cp exe.wasm ${ROOT_DIR}/examples/browser/${OUT_WASM}
        sed -i "s/exe\.wasm/${OUT_WASM}/g" $out_js
        sed -i "s/this\.program/${OUT_WASM}/g" $out_js
        cp $out_js ${ROOT_DIR}/examples/browser
      else
        cp $out_js ${ROOT_DIR}/examples/browser
        cp exe.wasm ${ROOT_DIR}/examples/browser
      fi
      
      # --preload-file generates the mapped data file `exe.data`.
      if [ -f "exe.data" ]; then
        cp exe.data ${ROOT_DIR}/examples/browser
      fi
      
      return 0
    ;;
    *-wasi32)
      RUNTIME_MACRO="$RUNTIME_MACRO -DTARGET_IS_WASI=1"
      TARGET_PRG=lift.wasi.o

      if [ -z "$NO_COMPILED" ]; then
        $WASISDKCC $WASISDKFLAGS $RUNTIME_MACRO -c lift.ll -o lift.wasi.o
      fi
      
      echo -e "[${GREEN}INFO${NC}] Compiling to Wasm (for WASI)... "
      $WASISDKCC $WASISDKFLAGS $WASISDK_LINKFLAGS $RUNTIME_MACRO -o exe.wasm $TARGET_PRG $ELFCONV_COMMON_RUNTIMES ${RUNTIME_DIR}/syscalls/SyscallWasi.cpp
      echo -e "[${GREEN}INFO${NC}] built exe.wasm"
      $WASMEDGE_COMPILE_OPT exe.wasm exe_o3.wasm
      echo -e "[${GREEN}INFO${NC}] built exe_opt.wasm"
      return 0
    ;;
  esac  
}

main "$@"