#!/usr/bin/env bash
#
# Usage:
#   VERSION=v0.3.0 bash release.sh
#
# Environment variables:
#   VERSION  (required) Release version string (e.g. v0.3.0).
#            Used for the output tarball name: elfconv-<VERSION>-linux-<arch>.tar.gz
#
# Examples:
#   VERSION=v0.3.0 bash release.sh        # build release package and create tarball
#   bash release.sh clean                  # remove built artifacts
#

set -e

GREEN="\033[32m"
ORANGE="\033[33m"
RED="\033[31m"
NC="\033[0m"

setting() {

  RELEASE_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
  ELFCONV_DIR=${RELEASE_DIR}/../
  BUILD_DIR=${ELFCONV_DIR}/build
  ELFCONV_ARCH_DIR=${BUILD_DIR}/backend/remill/lib/Arch
  RUNTIME_DIR=${ELFCONV_DIR}/runtime
  UTILS_DIR=${ELFCONV_DIR}/utils
  BROWSER_DIR=${ELFCONV_DIR}/browser
  SCRIPTS_DIR=${ELFCONV_DIR}/scripts
  OUTDIR=${RELEASE_DIR}/outdir
  BINDIR=${OUTDIR}/bin
  BITCODEDIR=${OUTDIR}/bitcode
  LIBDIR=${OUTDIR}/lib
  OUTOUTDIR=${OUTDIR}/out

  HOST_ARCH=$(uname -m)
  case "${HOST_ARCH}" in
    x86_64)  ARCH_LABEL="amd64" ;;
    aarch64) ARCH_LABEL="aarch64" ;;
    *)       ARCH_LABEL="${HOST_ARCH}" ;;
  esac

  # shared compiler options
  OPTFLAGS="-O3"
  
  # emscripten
  EMCXX=em++
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

  if [ ! -d "$OUTDIR" ]; then
    mkdir "$OUTDIR"
    echo "[${GREEN}INFO${NC}] outdir was generated."
  fi

  # clean existing outdir/
  if [ "$1" = "clean" ]; then
    rm -rf $BINDIR $BITCODEDIR $LIBDIR $OUTOUTDIR ${OUTDIR}/browser ${OUTDIR}/scripts *.tar.gz
    exit 0
  fi

  # set elflift
  mkdir -p $BINDIR
  cd "${BUILD_DIR}" && ninja
  if file "${BUILD_DIR}/lifter/elflift" | grep -q "dynamically linked"; then
    echo -e "[${ORANGE}WARNING${NC}] elflift is dynamically linked file."
  fi
  
  if cp ${BUILD_DIR}/lifter/elflift $BINDIR; then
    echo -e "[${GREEN}INFO${NC}] Set elflift."
  else
    echo -e "[${RED}ERROR${NC}] Faild to set elflift."
    exit 1
  fi

  while IFS= read -r so_path; do
    if [[ -n "${so_path}" && -f "${so_path}" ]]; then
      cp -L "${so_path}" "${LIBDIR}/"
      echo -e "[${GREEN}INFO${NC}] Bundled $(basename ${so_path})."
    fi
  done < <(ldd "${BUILD_DIR}/lifter/elflift" \
    | grep -vE 'linux-vdso|ld-linux|libc\.so|libm\.so|libgcc_s|libstdc\+\+|libpthread|libdl\.so|librt\.so' \
    | awk '{print $3}' \
    | grep -v '^$')

  # set semantics *.bc file
  mkdir -p $BITCODEDIR
  case "${ARCH_LABEL}" in
    aarch64)
      cp ${ELFCONV_ARCH_DIR}/AArch64/Runtime/aarch64.bc $BITCODEDIR
      echo -e "[${GREEN}INFO${NC}] Set semantics aarch64.bc."
      ;;
    amd64)
      cp ${ELFCONV_ARCH_DIR}/X86/Runtime/amd64.bc $BITCODEDIR
      cp ${ELFCONV_ARCH_DIR}/X86/Runtime/x86.bc $BITCODEDIR
      echo -e "[${GREEN}INFO${NC}] Set semantics amd64.bc, x86.bc."
      ;;
    *)
      echo -e "[${RED}ERROR${NC}] Unsupported architecture: ${HOST_ARCH}"
      exit 1
      ;;
  esac
  
  # prepare elfconv-runtime program.
  mkdir -p $LIBDIR
  base_rt=(
    Entry.cpp
    Memory.cpp
    VmIntrinsics.cpp
    Runtime.cpp
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
    echo -e "[${GREEN}INFO${NC}] Set libelfconvbrowser.a."
  else
    echo -e "[${RED}ERROR${NC}] Failed to set libelfconvbrowser.a."
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
    echo -e "[${GREEN}INFO${NC}] Set libelfconvwasi.a."
  else
    echo -e "[${RED}ERROR${NC}] Failed to set libelfconvwasi.a."
    exit 1
  fi
		
  rm *.o

  # library of xterm-pty
  cp ${ELFCONV_DIR}/xterm-pty/emscripten-pty.js $LIBDIR

  BROWSEROUTDIR=${OUTDIR}/browser
  mkdir -p $BROWSEROUTDIR
  cp ${BROWSER_DIR}/* $BROWSEROUTDIR
  echo -e "[${GREEN}INFO${NC}] Set browser files."

  SCRIPTSOUTDIR=${OUTDIR}/scripts
  mkdir -p $SCRIPTSOUTDIR
  cp ${SCRIPTS_DIR}/pack-preload.py $SCRIPTSOUTDIR
  echo -e "[${GREEN}INFO${NC}] Set pack-preload.py."

  cp ${RELEASE_DIR}/README.md ${OUTDIR}/README.md
  echo -e "[${GREEN}INFO${NC}] Set README.md."

  if [[ -z "${VERSION}" ]]; then
    echo -e "[${RED}ERROR${NC}] VERSION is not set. Usage: VERSION=v0.3.0 bash release.sh"
    exit 1
  fi
  TARNAME="elfconv-${VERSION}-linux-${ARCH_LABEL}.tar.gz"
  cd "${RELEASE_DIR}"
  tar -czf "${TARNAME}" -C "${RELEASE_DIR}" outdir
  echo -e "[${GREEN}INFO${NC}] Created ${TARNAME}."

}

main "$@"