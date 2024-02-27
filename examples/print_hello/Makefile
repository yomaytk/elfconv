CC=clang-16

print_hello: print_hello.c start.s
	@ARCH=$$( uname -m ); \
	if [ "$$ARCH" = "x86_64" ]; then \
			$(CC) -O3 -nostdlib -static --target=aarch64-linux-gnu --gcc-toolchain=/usr --sysroot=/usr/aarch64-linux-gnu start.s print_hello.c -fuse-ld=lld -pthread; \
	elif [ "$$ARCH" = "aarch64" ]; then \
			$(CC) -O3 -nostdlib -static start.s print_hello.c; \
	else \
			echo "Unknown architecture"; exit 1; \
	fi

clean:
	rm a.out
