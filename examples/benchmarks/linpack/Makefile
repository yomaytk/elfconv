CC=clang-16
GCC=gcc

linpack: nostdin_linpack.c
	@ARCH=$$(uname -m); \
	if [ "$$ARCH" = "x86_64" ]; then \
			$(CC) -o a.aarch64 -O3 -static --target=aarch64-linux-gnu --gcc-toolchain=/usr --sysroot=/usr/aarch64-linux-gnu nostdin_linpack.c -fuse-ld=lld -pthread; \
	elif [ "$$ARCH" = "aarch64" ]; then \
			$(GCC) -O3 -static nostdin_linpack.c -o a.aarch64; \
			strip a.aarch64 -o a_stripped.aarch64; \
	else \
			echo "Unknown architecture"; exit 1; \
	fi

clean:
	rm *.out
