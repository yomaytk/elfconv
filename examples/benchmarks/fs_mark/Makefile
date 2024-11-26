#
# Simple makefile for file latency test program
#
# fs_mark.c is a modified version of Larry McVoy's lmbench program.
#
# Modifications include using fsync after wrting to flush to disk and changes to check return
# values from syscalls.
#
DIR1= /test/dir1
DIR2= /test/dir2

COBJS= fs_mark.o lib_timing.o

CC ?= gcc
EMCC ?= emcc
WASISDKCC ?= ${WASI_SDK_PATH}/bin/clang
CFLAGS ?= -O3
LDFLAGS ?=
CFLAGS += -Wall -D_FILE_OFFSET_BITS=64

all: fs_mark 

fs_mark: fs_mark.c lib_timing.c
	$(CC) $(CFLAGS) -static -o fs_mark.aarch64 fs_mark.c lib_timing.c $(LDFLAGS)

fs_mark_tmp: wasi_fs_mark.c lib_timing.c
	$(CC) $(CFLAGS) -static -o tmp_fs_mark.aarch64 wasi_fs_mark.c lib_timing.c $(LDFLAGS)

fs_mark_emcc: fs_mark.c lib_timing.c
	$(EMCC) -O3 -o fs_mark.html fs_mark.wasm.c lib_timing.wasm.c

fs_mark_wasi: fs_mark.c lib_timing.c
	$(WASISDKCC) -O3 wasi_fs_mark.c lib_timing.c -D_WASI_EMULATED_PROCESS_CLOCKS -D_WASI_EMULATED_GETPID \
		-lwasi-emulated-process-clocks -lwasi-emulated-getpid -o fs_mark_wasi.wasm

test: fs_mark
	./fs_mark -d ${DIR1} -d ${DIR2} -s 51200 -n 4096
	./fs_mark -d ${DIR1} -d ${DIR2} -s 51200 -n 4096 -r 
	./fs_mark -d ${DIR1} -d ${DIR2} -s 51200 -n 4096 -D 128
	./fs_mark -d ${DIR1} -d ${DIR2} -s 51200 -n 4096 -r -D 128

clean:
	rm -rf ${COBJS} fs_mark fs_log.txt *.wasm *.js *.html testdir1

