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
CFLAGS ?= -O3
LDFLAGS ?=
CFLAGS += -Wall -D_FILE_OFFSET_BITS=64

all: fs_mark 

fs_mark.o: fs_mark.c fs_mark.h

fs_mark: fs_mark.o lib_timing.o
	$(CC) $(CFLAGS) -static -o fs_mark.aarch64 fs_mark.o lib_timing.o $(LDFLAGS)

fs_mark_wasm: fs_mark.c lib_timing.c
	$(EMCC) -O3 -c fs_mark.c -o fs_mark.wasm.o
	$(EMCC) -O3 -c lib_timing.c -o lib_timing.wasm.o
	$(EMCC) -O3 -static -o fs_mark.html fs_mark.wasm.o lib_timing.wasm.o

test: fs_mark
	./fs_mark -d ${DIR1} -d ${DIR2} -s 51200 -n 4096
	./fs_mark -d ${DIR1} -d ${DIR2} -s 51200 -n 4096 -r 
	./fs_mark -d ${DIR1} -d ${DIR2} -s 51200 -n 4096 -D 128
	./fs_mark -d ${DIR1} -d ${DIR2} -s 51200 -n 4096 -r -D 128

clean:
	rm -rf ${COBJS} fs_mark fs_log.txt *.wasm *.js *.html testdir1

