#!/usr/bin/env bash

EMCC=emcc
EMCCFLAGS="-O0"

if [ $# -eq 0 ]; then
	echo "[ERROR] target ELF binary is not specified (lift.sh)."
	echo $#
	exit 1
fi

# $1 : path to target ELF
echo "[INFO] ELF Converting Start."
	./elflift \
	--arch aarch64 \
	--bc_out lift.bc \
	--target_elf "$1" \
	--dbg_fun_cfg "$2"
echo "[INFO] Generate lift.bc."

# generate executable by emscripten (target: wasm)
	$EMCC $EMCCFLAGS -c lift.bc -o lift.o && \
	$EMCC $EMCCFLAGS -o exe.wasm -L"./" lift.o -lelfconv

# generate glud code
	${EMCC} ${EMCCFLAGS} -o exe.wasm.html -L"./" -sWASM -sALLOW_MEMORY_GROWTH lift.o -lelfconv
