#!/usr/bin/env bash

WASI_SDK_PATH=/root/wasi-sdk-21.0

setting() {

  RELEASE_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
  ELFCONV_DIR=${RELEASE_DIR}/../
  BUILD_DIR=${ELFCONV_DIR}/build
  ELFCONV_ARCH_DIR=${BUILD_DIR}/backend/remill/lib/Arch
  RUNTIME_DIR=${ELFCONV_DIR}/runtime
  UTILS_DIR=${ELFCONV_DIR}/utils

  # shared compiler options
  OPTFLAGS="-O3"
  
  # emscripten
  EMCXX=emcc
  EMAR=emar
  EMCCFLAGS="${OPTFLAGS} -I${ELFCONV_DIR}/backend/remill/include -I${ELFCONV_DIR}"
  EMCC_ELFCONV_MACROS="-DELFC_BROWSER_ENV=1"
  
  # wasi-sdk
  WASISDKCXX=${WASI_SDK_PATH}/bin/clang++
  WASISDKAR=${WASI_SDK_PATH}/bin/ar
  WASISDKFLAGS="${OPTFLAGS} --sysroot=${WASI_SDK_PATH}/share/wasi-sysroot -I${ELFCONV_DIR}/backend/remill/include -I${ELFCONV_DIR} -fno-exceptions"
  WASI_ELFCONV_MACROS="-DELFC_WASI_ENV=1"

}

main() {
  
  setting

  # clear cache
  rm -rf bin bitcode lib

  # set elflift
  mkdir -p bin
  cd "${BUILD_DIR}" && ninja
  if file "./lifter/elflift" | grep -q "dynamically linked"; then
    echo -e "[\033[33mWARNING\033[0m] elflift is dynamically linked file."
  fi
  cd "${RELEASE_DIR}"
  if cp ${BUILD_DIR}/lifter/elflift bin; then
    echo -e "[\033[32mINFO\033[0m] Set elflift."
  else
    echo -e "[\033[31mERROR\033[0m] Faild to set elflift."
    exit 1
  fi

  # set semantics *.bc file
  mkdir -p bitcode
  if cp ${ELFCONV_ARCH_DIR}/AArch64/Runtime/aarch64.bc bitcode && cp ${ELFCONV_ARCH_DIR}/X86/Runtime/amd64.bc bitcode && cp ${ELFCONV_ARCH_DIR}/X86/Runtime/x86.bc bitcode ; then
    echo -e "[\033[32mINFO\033[0m] Set semantics *.bc."
  else
    echo -e "[\033[31mERROR\033[0m] Failed to set semantics *.bc."
    exit 1
  fi
  
  # set elfconv-runtime archive (libelfconvbrowser.a)
  mkdir -p lib
  # cd "${RUNTIME_DIR}" || { echo "cd Failure"; exit 1; }
  #   # shellcheck disable=SC2086
  #   $EMCXX $EMCCFLAGS $EMCC_ELFCONV_MACROS -o Entry.o -c Entry.cpp && \
  #   $EMCXX $EMCCFLAGS $EMCC_ELFCONV_MACROS -o Memory.o -c Memory.cpp && \
  #   $EMCXX $EMCCFLAGS $EMCC_ELFCONV_MACROS -o Syscall.o -c syscalls/SyscallBrowser.cpp && \
  #   $EMCXX $EMCCFLAGS $EMCC_ELFCONV_MACROS -o VmIntrinsics.o -c VmIntrinsics.cpp && \
  #   $EMCXX $EMCCFLAGS $EMCC_ELFCONV_MACROS -o Util.o -c "${UTILS_DIR}"/Util.cpp && \
  #   $EMCXX $EMCCFLAGS $EMCC_ELFCONV_MACROS -o elfconv.o -c "${UTILS_DIR}"/elfconv.cpp && \
  #   $EMAR rcs libelfconvbrowser.a Entry.o Memory.o Syscall.o VmIntrinsics.o Util.o elfconv.o
  #   if mv libelfconvbrowser.a ${RELEASE_DIR}/lib; then
  #     echo -e "[\033[32mINFO\033[0m] Set libelfconvbrowser.a."
  #   else
  #     echo -e "[\033[31mERROR\033[0m] Failed to set libelfconvbrowser.a."
  #     exit 1
  #   fi
	# 	rm *.o

  # set elfconv-runtime archive (libelfconvwasi.a)
  cd "${RUNTIME_DIR}" || { echo "cd Failure"; exit 1; }
    # shellcheck disable=SC2086
    $WASISDKCXX $WASISDKFLAGS $WASI_ELFCONV_MACROS -o Entry.o -c Entry.cpp && \
    $WASISDKCXX $WASISDKFLAGS $WASI_ELFCONV_MACROS -o Memory.o -c Memory.cpp && \
    $WASISDKCXX $WASISDKFLAGS $WASI_ELFCONV_MACROS -o Syscall.o -c syscalls/SyscallWasi.cpp && \
    $WASISDKCXX $WASISDKFLAGS $WASI_ELFCONV_MACROS -o VmIntrinsics.o -c VmIntrinsics.cpp && \
    $WASISDKCXX $WASISDKFLAGS $WASI_ELFCONV_MACROS -o Util.o -c "${UTILS_DIR}"/Util.cpp && \
    $WASISDKCXX $WASISDKFLAGS $WASI_ELFCONV_MACROS -o elfconv.o -c "${UTILS_DIR}"/elfconv.cpp && \
    $WASISDKAR rcs libelfconvwasi.a Entry.o Memory.o Syscall.o VmIntrinsics.o Util.o elfconv.o
    if mv libelfconvwasi.a ${RELEASE_DIR}/lib; then
      echo -e "[\033[32mINFO\033[0m] Set libelfconvwasi.a."
    else
      echo -e "[\033[31mERROR\033[0m] Failed to set libelfconvwasi.a."
      exit 1
    fi
		rm *.o

}

main