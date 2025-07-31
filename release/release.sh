#!/usr/bin/env bash

setting() {

  RELEASE_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
  ELFCONV_DIR=${RELEASE_DIR}/../
  BUILD_DIR=${ELFCONV_DIR}/build
  ELFCONV_ARCH_DIR=${BUILD_DIR}/backend/remill/lib/Arch
  RUNTIME_DIR=${ELFCONV_DIR}/runtime
  UTILS_DIR=${ELFCONV_DIR}/utils
  OUTDIR=${RELEASE_DIR}/outdir
  BINDIR=${OUTDIR}/bin
  BITCODEDIR=${OUTDIR}/bitcode
  LIBDIR=${OUTDIR}/lib

  # shared compiler options
  OPTFLAGS="-O3"
  
  # emscripten
  EMCXX=emcc
  EMAR=emar
  EMCCFLAGS="${OPTFLAGS} -I${ELFCONV_DIR}/backend/remill/include -I${ELFCONV_DIR}"
  EMCC_ELFCONV_MACROS=" -DELF_IS_AARCH64 -DTARGET_IS_BROWSER=1"
  
  # wasi-sdk
  WASISDKCXX=${WASI_SDK_PATH}/bin/clang++
  WASISDKAR=${WASI_SDK_PATH}/bin/ar
  WASISDKFLAGS="${OPTFLAGS} --sysroot=${WASI_SDK_PATH}/share/wasi-sysroot -I${ELFCONV_DIR}/backend/remill/include -I${ELFCONV_DIR} -D_WASI_EMULATED_SIGNAL -D_WASI_EMULATED_PROCESS_CLOCKS -D_WASI_EMULATED_MMAN -fno-exceptions"
  WASI_ELFCONV_MACROS="-DELF_IS_AARCH64 -DTARGET_IS_WASI=1"

}

main() {
  
  setting

  # clean existing outdir/
  if [ "$1" = "clean" ]; then
    rm -rf $OUTDIR *.tar.gz
    exit 0
  fi

  # set elflift
  mkdir -p $BINDIR
  cd "${BUILD_DIR}" && ninja
  if file "${BUILD_DIR}/lifter/elflift" | grep -q "dynamically linked"; then
    echo -e "[\033[33mWARNING\033[0m] elflift is dynamically linked file."
  fi
  
  if cp ${BUILD_DIR}/lifter/elflift $BINDIR; then
    echo -e "[\033[32mINFO\033[0m] Set elflift."
  else
    echo -e "[\033[31mERROR\033[0m] Faild to set elflift."
    exit 1
  fi

  # set semantics *.bc file
  mkdir -p $BITCODEDIR
  if cp ${ELFCONV_ARCH_DIR}/AArch64/Runtime/aarch64.bc bitcode && cp ${ELFCONV_ARCH_DIR}/X86/Runtime/amd64.bc bitcode && cp ${ELFCONV_ARCH_DIR}/X86/Runtime/x86.bc bitcode ; then
    echo -e "[\033[32mINFO\033[0m] Set semantics *.bc."
  else
    echo -e "[\033[31mERROR\033[0m] Failed to set semantics *.bc."
    exit 1
  fi
  
  # prepare elfconv-runtime program.
  mkdir -p $LIBDIR
  base_rt=(
    Entry.cpp
    Memory.cpp
    VmIntrinsics.cpp
    "${UTILS_DIR}/Util.cpp"
    "${UTILS_DIR}/elfconv.cpp"
  )
  
  # for browser
  cd "${RUNTIME_DIR}" || { echo "cd Failure"; exit 1; }

  browser_rt_flags=( $EMCCFLAGS $EMCC_ELFCONV_MACROS )

  browser_rt_objects=()
  browser_rt=( "${base_rt[@]}" "syscalls/SyscallBrowser.cpp" )

  for src in "${browser_rt[@]}"; do
    base=$(basename "$src" .cpp)
    obj="${base}.o"
    "$EMCXX" -O3 "${browser_rt_flags[@]}" -o "$obj" -c "$src"
    browser_rt_objects+=("$obj")
  done

  "$EMAR" rcs libelfconvbrowser.a "${browser_rt_objects[@]}"

  if mv libelfconvbrowser.a "${LIBDIR}"; then
    echo -e "[\033[32mINFO\033[0m] Set libelfconvbrowser.a."
  else
    echo -e "[\033[31mERROR\033[0m] Failed to set libelfconvbrowser.a."
    exit 1
  fi

  rm *.o

  # for WASI
  cd "${RUNTIME_DIR}" || { echo "cd Failure"; exit 1; }

  wasi_rt_flags=( $WASISDKFLAGS $WASI_ELFCONV_MACROS )

  wasi_rt_objects=()
  wasi_rt=( "${base_rt[@]}" "syscalls/SyscallWasi.cpp" )

  for src in "${wasi_rt[@]}"; do
    base=$(basename "$src" .cpp)
    obj="${base}.o"
    "$WASISDKCXX" "${wasi_rt_flags[@]}" -o "$obj" -c "$src"
    wasi_rt_objects+=("$obj")
  done

  "$WASISDKAR" rcs libelfconvwasi.a "${wasi_rt_objects[@]}"

  if mv libelfconvwasi.a "${LIBDIR}"; then
    echo -e "[\033[32mINFO\033[0m] Set libelfconvwasi.a."
  else
    echo -e "[\033[31mERROR\033[0m] Failed to set libelfconvwasi.a."
    exit 1
  fi
		
  rm *.o

  # library of xterm-pty
  cp ${ELFCONV_DIR}/xterm-pty/emscripten-pty.js $LIBDIR

}

main "$@"