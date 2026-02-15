#!/usr/bin/env bash
# Copyright (c) 2019 Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ROOT_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )/../" && pwd )
REMILL_DIR=$( cd "$( realpath "${ROOT_DIR}/backend/remill" )" && pwd )
BUILD_DIR="${ROOT_DIR}/build"
BUILD_LIFTER_DIR="${BUILD_DIR}/lifter"
ELFCONV_INSTALL_DIR="${HOME}/.elfconv/bin"
BUILD_FLAGS=
LIFT_DEBUG_MACROS=
ELFCONV_AARCH64_BUILD=0
ELFCONV_X86_BUILD=0
DEPS_DIR="${ROOT_DIR}/dependencies"
DEPS_BUILD_DIR="${DEPS_DIR}/build"
DEPS_INSTALL_DIR="${DEPS_DIR}/install"

# Build dependencies via superbuild.
function BuildDependencies
{
  if [[ -d "${DEPS_INSTALL_DIR}" ]] && [[ -f "${DEPS_INSTALL_DIR}/lib/cmake/glog/glog-config.cmake" ]]; then
    echo "[-] Dependencies already built, skipping."
    return 0
  fi

  echo "[-] Building dependencies via superbuild..."

  (
    set -x
    cmake \
        -B "${DEPS_BUILD_DIR}" \
        -S "${DEPS_DIR}" \
        -DCMAKE_BUILD_TYPE=Release \
        -DUSE_EXTERNAL_LLVM=ON \
        -DCMAKE_C_COMPILER=clang \
        -DCMAKE_CXX_COMPILER=clang++ \
        -DCMAKE_PREFIX_PATH="/usr/lib/llvm-16" \
        -DCMAKE_INSTALL_PREFIX="${DEPS_INSTALL_DIR}" \
        -GNinja
  ) || return $?

  (
    set -x
    cmake --build "${DEPS_BUILD_DIR}"
  ) || return $?

  return 0
}

# Configure the build.
function Configure
{
  # $1: ELFCONV_AARCH64_BUILD
  # $2: ELFCONV_X86_BUILD
  (
    set -x
    cmake \
        -DCMAKE_INSTALL_PREFIX="${INSTALL_DIR}" \
        -DCMAKE_VERBOSE_MAKEFILE=False \
        -DCMAKE_PREFIX_PATH="${DEPS_INSTALL_DIR};/usr/lib/llvm-16" \
        -DREMILL_BUILD_SPARC32_RUNTIME=OFF \
        -DCMAKE_C_COMPILER=clang \
        -DCMAKE_CXX_COMPILER=clang++ \
        -DCMAKE_ELFLIFT_STATIC_LINK="${ELFCONV_RELEASE}" \
        ${BUILD_FLAGS} \
        ${LIFT_DEBUG_MACROS} \
        -DCMAKE_ELFCONV_AARCH64_BUILD=$1 \
        -DCMAKE_ELFCONV_X86_BUILD=$2 \
        -GNinja \
        "${ROOT_DIR}"
  ) || exit $?

  return $?
}

# Compile the code.
function Build
{
  # make debugs/generated for debugging.
  mkdir -p debugs/generated

  if [[ "$OSTYPE" == "darwin"* ]]; then
    NPROC=$( sysctl -n hw.ncpu )
  else
    NPROC=$( nproc )
  fi

  (
    set -x
    cmake --build . -- -j"${NPROC}"
  ) || return $?

  return $?
}

# make remill/generated directory.
function TestSetup
{
  ${REMILL_DIR}/scripts/aarch64/print_save_state_asm.sh

  return $?
}

function Help
{
  echo "Beginner build script to get started"
  echo ""
  echo "Options:"
  echo "  --prefix           Change the default (${INSTALL_DIR}) installation prefix."
  echo "  --build-dir        Change the default (${BUILD_DIR}) build directory."
  echo "  --debug            Build with Debug symbols."
  echo "  --extra-cmake-args Extra CMake arguments to build with."
  echo "  -h --help          Print help."
}

function main
{

  if [ -d "$BUILD_DIR" ]; then
    echo "Already build done! (at scripts/build.sh)"
    exit 0
  fi

  while [[ $# -gt 0 ]] ; do
    key="$1"

    case $key in

      -h)
        Help
        exit 0
      ;;

      --help)
        Help
        exit 0
      ;;

      # Change the default installation prefix.
      --prefix)
        INSTALL_DIR=$(python3 -c "import os; import sys; sys.stdout.write(os.path.abspath('${2}'))")
        echo "[+] New install directory is ${INSTALL_DIR}"
        shift # past argument
      ;;

      # Change the default build directory.
      --build-dir)
        BUILD_DIR=$(python3 -c "import os; import sys; sys.stdout.write(os.path.abspath('${2}'))")
        echo "[+] New build directory is ${BUILD_DIR}"
        shift # past argument
      ;;

      --extra-cmake-args)
        BUILD_FLAGS="${BUILD_FLAGS} ${2}"
        echo "[+] Will supply additional arguments to cmake: ${BUILD_FLAGS}"
        shift
      ;;

      *)
        # unknown option
        echo "[x] Unknown option: ${key}"
        return 1
      ;;
    esac

    shift # past argument or value
  done

  mkdir -p "${BUILD_DIR}"
  cd "${BUILD_DIR}" || exit 1

  if [ "$ELFCONV_AARCH64" = "1" ]; then
    ELFCONV_AARCH64_BUILD=1
  fi

  if [ "$ELFCONV_X86" = "1" ]; then
    ELFCONV_X86_BUILD=1
  fi

  if [ "$ELFCONV_AARCH64" = "1" ] && [ "$ELFCONV_X86" == 1 ]; then
    echo "[x] ELFCONV Target Architecture must be only one."
    exit 1
  fi

  if ! (BuildDependencies && TestSetup && Configure $ELFCONV_AARCH64_BUILD $ELFCONV_X86_BUILD && Build); then
    echo "[x] Build aborted."
    exit 1
  fi

  # install elflift
  mkdir -p "${ELFCONV_INSTALL_DIR}"
  cp -p "${BUILD_LIFTER_DIR}/elflift"  "${ELFCONV_INSTALL_DIR}"

  # for sample execution
  cp -p "${BUILD_LIFTER_DIR}/elflift"  "${ROOT_DIR}/bin"

  return $?
}

main "$@"
exit $?
