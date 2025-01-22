CC=clang-16

hello: hello.c
	@ARCH=$$( uname -m ); \
	if [ "$$ARCH" = "x86_64" ]; then \
			$(CC) -static --target=aarch64-linux-gnu --gcc-toolchain=/usr --sysroot=/usr/aarch64-linux-gnu hello.c -fuse-ld=lld -pthread; \
	elif [ "$$ARCH" = "aarch64" ]; then \
			$(CC) -static hello.c; \
	else \
			echo "Unknown architecture"; exit 1; \
	fi

clean:
	rm a.out

