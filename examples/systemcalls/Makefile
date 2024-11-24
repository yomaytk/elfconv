CC=clang-16
GCC=gcc

fsync_unlink: fsync_unlink.c
	@ARCH=$$(uname -m); \
	if [ "$$ARCH" = "x86_64" ]; then \
			$(CC) -O3 -static --target=aarch64-linux-gnu --gcc-toolchain=/usr --sysroot=/usr/aarch64-linux-gnu fsync_unlink.c -o fsync_unlink.aarch64 -fuse-ld=lld -pthread; \
	elif [ "$$ARCH" = "aarch64" ]; then \
			$(GCC) -O3 -static fsync_unlink.c -o fsync_unlink_o3.aarch64; \
	else \
			echo "Unknown architecture"; exit 1; \
	fi

clean:
	rm *.out *.js *.wasm *.html
