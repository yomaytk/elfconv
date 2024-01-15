CC=clang-16

eratosthenes_sieve: start.s cal.c
	@ARCH=$$( uname -m ); \
	if [ "$$ARCH" = "x86_64" ]; then \
			$(CC) -nostdlib -static --target=aarch64-linux-gnu --gcc-toolchain=/usr --sysroot=/usr/aarch64-linux-gnu start.s cal.c -fuse-ld=lld -pthread; \
	elif [ "$$ARCH" = "aarch64" ]; then \
			$(CC) -nostdlib -static start.s cal.c; \
	else \
			echo "Unknown architecture"; exit 1; \
	fi

clean:
	rm a.out
