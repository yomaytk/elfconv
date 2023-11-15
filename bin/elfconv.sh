#!/usr/bin/env bash

EMCC=${HOME}/emsdk/upstream/emscripten/emcc
EMCCFLAGS="-O3"
OBJPATH="./obj/"

if [ $# -eq 0 ]; then
    echo "[ERROR] target ELF binary is not specified (lift.sh)."
    echo $#
    exit 1
fi

# build Lift.cpp
# $1 : path to target ELF
echo "[INFO] ELF Converting Start."
    ./elflift \
    --arch aarch64 \
    --bc_out lift.bc \
    --target_elf "$1" \
    --dbg_fun_cfg "$2" && \
    llvm-dis lift.bc -o lift.ll
echo "[INFO] Generate lift.bc."

# generate executable by emscripten (target: wasm)
    $EMCC $EMCCFLAGS -c lift.ll -o lift.o && \
    $EMCC $EMCCFLAGS -o exe.wasm ${OBJPATH}/Entry.o ${OBJPATH}/Syscall.o ${OBJPATH}/VmIntrinsics.o ${OBJPATH}/Memory.o lift.o