#!/usr/bin/env bash

SOURCE_DIR=${HOME}/workspace/compiler/remill
SOURCE_LIFTING_DIR=${SOURCE_DIR}/tests/Lifting
BUILD_DIR=${SOURCE_DIR}/build
BUILD_LIFTING_DIR=${BUILD_DIR}/tests/Lifting
EMSCRIPTEN_BIN=${HOME}/emsdk/upstream/emscripten
EMCC=${EMSCRIPTEN_BIN}/emcc
CXX=clang++-16
CXX_X64=x86_64-linux-gnu-g++-11
EMCCFLAGS="-I${SOURCE_DIR}/include -O3"
CLANGFLAGS="-g -static -I${SOURCE_DIR}/include"
X64_GCC_FLAGS="-g -static -I${SOURCE_DIR}/include"


if [ $# -eq 0 ]; then
    echo "[ERROR] target ELF binary is not specified (lift.sh)."
    echo $#
    exit 1
fi

if [ -z "$NOT_LINKED" ]; then
    NOT_LINKED=0
fi

if [ -z "$NOT_LIFTED" ]; then
    NOT_LIFTED=0
fi

if [ -z "$FAST_BUILD" ]; then
    FAST_BUILD=0
fi

if [ -z "$GEN_AARCH64" ]; then
    GEN_AARCH64=0
fi

# build Lift.cpp
if [ "$NOT_LIFTED" -ne 1 ]; then
    echo "[INFO] Build Start."
    cd $BUILD_DIR && \
        ./tests/Lifting/lifting_target_aarch64 \
        --arch aarch64 \
        --bc_out ${BUILD_LIFTING_DIR}/lifting_target_aarch64.bc \
        --target_elf "$1" \
        --dbg_fun_cfg "$2" && \
        llvm-dis ${BUILD_LIFTING_DIR}/lifting_target_aarch64.bc -o ${BUILD_LIFTING_DIR}/lifting_target_aarch64.ll
    echo "[INFO] Generate lifting_target_aarch64.ll"
fi

# generate executable by clang (target: aarch64)
if [ "$GEN_AARCH64" -eq 1 ]; then
    cd $SOURCE_LIFTING_DIR && \
        $CXX $CLANGFLAGS -c Entry.cpp -o ${BUILD_LIFTING_DIR}/Entry.aarch64.o && \
        $CXX $CLANGFLAGS -c Syscall.cpp -o ${BUILD_LIFTING_DIR}/Syscall.aarch64.o && \
        $CXX $CLANGFLAGS -c VmIntrinsics.cpp -o ${BUILD_LIFTING_DIR}/VmIntrinsics.aarch64.o && \
        $CXX $CLANGFLAGS -c memory.cpp -o ${BUILD_LIFTING_DIR}/memory.aarch64.o && cd $BUILD_LIFTING_DIR && \
        $CXX $CLANGFLAGS -c lifting_target_aarch64.ll -o lifting_target_aarch64.o && \
        $CXX $CLANGFLAGS -o exe.aarch64 Entry.aarch64.o Syscall.aarch64.o VmIntrinsics.aarch64.o memory.aarch64.o lifting_target_aarch64.o
fi

# generate executable by emscripten (target: wasm)
if [ "$NOT_LINKED" -ne 1 ]; then
    cd $SOURCE_LIFTING_DIR && \
        $EMCC $EMCCFLAGS -c Entry.cpp -o ${BUILD_LIFTING_DIR}/Entry.o && \
        $EMCC $EMCCFLAGS -c Syscall.cpp -o ${BUILD_LIFTING_DIR}/Syscall.o && \
        $EMCC $EMCCFLAGS -c VmIntrinsics.cpp -o ${BUILD_LIFTING_DIR}/VmIntrinsics.o
        $EMCC $EMCCFLAGS -c memory.cpp -o ${BUILD_LIFTING_DIR}/memory.o
fi

if [ "$FAST_BUILD" -eq 1 ]; then
    cd $BUILD_LIFTING_DIR && \
        $EMCC $EMCCFLAGS -o exe.wasm Entry.o Syscall.o VmIntrinsics.o memory.o lifting_target_aarch64.o
else
    cd $BUILD_LIFTING_DIR && \
        $EMCC $EMCCFLAGS -c lifting_target_aarch64.ll -o lifting_target_aarch64.o && \
        $EMCC $EMCCFLAGS -o exe.wasm Entry.o Syscall.o VmIntrinsics.o memory.o lifting_target_aarch64.o
fi