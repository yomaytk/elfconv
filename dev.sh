#!/usr/bin/env bash

ROOT_DIR=${HOME}/workspace/compiler/elfconv
FRONT_DIR=${ROOT_DIR}/front
BUILD_DIR=${ROOT_DIR}/build
BUILD_FRONT_DIR=${BUILD_DIR}/front
EMCC=emcc
EMCCFLAGS="-O3 -I${ROOT_DIR}/backend/remill/include"
CXX=clang++-16
CLANGFLAGS="-g -static -I${ROOT_DIR}/backend/remill/include"

if [ $# -eq 0 ]; then
    echo "[ERROR] target ELF binary is not specified (lift.sh)."
    echo $#
    exit 1
fi

# $1 : path to target ELF
echo "[INFO] ELF Converting Start."
  cd ${BUILD_FRONT_DIR} && \
    ./elflift \
    --arch aarch64 \
    --bc_out ./lift.bc \
    --target_elf "$1" \
    --dbg_fun_cfg "$2" && \
    llvm-dis lift.bc -o lift.ll
echo "[INFO] Generate lift.bc."

# aarch64
cd ${BUILD_FRONT_DIR} && \
  ${CXX} ${CLANGFLAGS} -o Entry.aarch64.o -c ${FRONT_DIR}/Entry.cpp && \
  ${CXX} ${CLANGFLAGS} -o Memory.aarch64.o -c ${FRONT_DIR}/Memory.cpp && \
  ${CXX} ${CLANGFLAGS} -o Syscall.aarch64.o -c ${FRONT_DIR}/Syscall.cpp && \
  ${CXX} ${CLANGFLAGS} -o VmIntrinsics.aarch64.o -c ${FRONT_DIR}/VmIntrinsics.cpp && \
  ${CXX} ${CLANGFLAGS} -c lift.bc -o lift.o && \
  ${CXX} ${CLANGFLAGS} -o exe.aarch64 lift.o Entry.aarch64.o Memory.aarch64.o Syscall.aarch64.o VmIntrinsics.aarch64.o

# wasm
cd "${BUILD_FRONT_DIR}" && \
    ${EMCC} ${EMCCFLAGS} -o Entry.wasm.o -c ${FRONT_DIR}/Entry.cpp && \
    ${EMCC} ${EMCCFLAGS} -o Memory.wasm.o -c ${FRONT_DIR}/Memory.cpp && \
    ${EMCC} ${EMCCFLAGS} -o Syscall.wasm.o -c ${FRONT_DIR}/Syscall.cpp && \
    ${EMCC} ${EMCCFLAGS} -o VmIntrinsics.wasm.o -c ${FRONT_DIR}/VmIntrinsics.cpp && \
    ${EMCC} ${EMCCFLAGS} -c lift.bc -o lift.o && \
    ${EMCC} ${EMCCFLAGS} -o exe.wasm lift.o Entry.wasm.o Memory.wasm.o Syscall.wasm.o VmIntrinsics.wasm.o

# delete obj
rm *.o
