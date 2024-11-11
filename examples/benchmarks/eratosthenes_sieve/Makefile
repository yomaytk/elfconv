CC=clang-18
GCC=gcc

eratosthenes_sieve: main.c
	@ARCH=$$(uname -m); \
	if [ "$$ARCH" = "x86_64" ]; then \
			$(CC) -static --target=aarch64-linux-gnu --gcc-toolchain=/usr --sysroot=/usr/aarch64-linux-gnu main.c -fuse-ld=lld -pthread; \
	elif [ "$$ARCH" = "aarch64" ]; then \
			$(GCC) -O3 -static main.c -o a_o3.aarch64; \
	else \
			echo "Unknown architecture"; exit 1; \
	fi

clean:
	rm *.out
