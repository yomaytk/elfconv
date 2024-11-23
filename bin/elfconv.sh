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
  OPTFLAGS="-O0"
  EMCCFLAGS="${OPTFLAGS} -I${ROOT_DIR}/backend/remill/include -I${ROOT_DIR}"
  ELFCONV_MACROS="-DELFC_BROWSER_ENV=1"
  ELFPATH=$( realpath "$1" )
  WASMCC=$EMCC
  WASMCCFLAGS=$EMCCFLAGS
  WASMAR=$EMAR
  WASISDKCXX=${WASI_SDK_PATH}/bin/clang++
  WASISDKAR=${WASI_SDK_PATH}/bin/ar
  WASISDKFLAGS="${OPTFLAGS} --sysroot=${WASI_SDK_PATH}/share/wasi-sysroot -D_WASI_EMULATED_PROCESS_CLOCKS -I${ROOT_DIR}/backend/remill/include -I${ROOT_DIR} -fno-exceptions"

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
    WASMCC=$WASISDKCXX
    WASMCCFLAGS=$WASISDKFLAGS
    WASMAR=$WASISDKAR
    ELFCONV_MACROS="-DELFC_WASI_ENV=1"
    wasi32_target_arch='wasi32'
  fi

  # build runtime
  echo -e "[\033[32mINFO\033[0m] Building elfconv-Runtime ..."
  # build runtime/*.cpp
  for cpp_file in ${RUNTIME_DIR}/*.cpp; do
    $WASMCC $WASMCCFLAGS $ELFCONV_MACROS -c "$cpp_file" -o "${cpp_file%.cpp}".wasm.o
  done
  # build utils/*.cpp
  for cpp_file in ${UTILS_DIR}/*.cpp; do
    $WASMCC $WASMCCFLAGS $ELFCONV_MACROS -c "$cpp_file" -o "${cpp_file%.cpp}".wasm.o
  done
  # build runtime/syscalls/Syscall${TARGET}.cpp
  $WASMCC $WASMCCFLAGS $ELFCONV_MACROS -c "${RUNTIME_DIR}/syscalls/Syscall${TARGET}.cpp" -o "Syscall${TARGET}.wasm.o"
  $WASMAR rcs libelfconv.a *.wasm.o
  mv libelfconv.a "${BIN_DIR}/"
  rm *.wasm.o
  echo -e "[\033[32mINFO\033[0m] libelfconv.a was generated."

  # ELF -> LLVM bitcode
  cp -p "${BUILD_LIFTER_DIR}/elflift" "${BIN_DIR}/"
  echo -e "[\033[32mINFO\033[0m] ELF -> LLVM bitcode..."
    cd "${BIN_DIR}" || { echo "cd Failure"; exit 1; }
    ./elflift \
    --arch aarch64 \
    --bc_out lift.bc \
    --target_elf "$ELFPATH" \
    --dbg_fun_cfg "$2" \
    --target_arch "$wasm32_target_arch"
  echo -e "[\033[32mINFO\033[0m] Generate lift.bc."

  # LLVM bc -> target file
  case "$TARGET" in
    Browser)
      # We use https://github.com/mame/xterm-pty for the console on the browser.
      echo -e "[\033[32mINFO\033[0m] Compiling to Wasm and Js (for Browser)... "
      cd "${BIN_DIR}" || { echo "cd Failure"; exit 1; }
        $WASMCC $OPTFLAGS -sALLOW_MEMORY_GROWTH -sASYNCIFY -sEXPORT_ES6 -sENVIRONMENT=web --js-library ${ROOT_DIR}/xterm-pty/emscripten-pty.js \
            -o exe.js -L"./" lift.bc -lelfconv
      echo -e "[\033[32mINFO\033[0m] exe.wasm and exe.js were generated."
      return 0
    ;;
    Wasi)
      echo -e "[\033[32mINFO\033[0m] Compiling to Wasm (for WASI)... "
      cd "${BIN_DIR}" || { echo "cd Failure"; exit 1; }
        $WASMCC $OPTFLAGS -o exe.wasm -L"./" lift.bc -lelfconv
      echo -e "[\033[32mINFO\033[0m] exe.wasm was generated."
      return 0
    ;;
  esac

}

main "$@"