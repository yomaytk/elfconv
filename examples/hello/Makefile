CC=clang-16

hello_aarch64: hello.c
	@ARCH=$$( uname -m ); \
	if [ "$$ARCH" = "x86_64" ]; then \
			$(CC) -static -o a.aarch64 --target=aarch64-linux-gnu --gcc-toolchain=/usr --sysroot=/usr/aarch64-linux-gnu hello.c; \
	elif [ "$$ARCH" = "aarch64" ]; then \
			$(CC) -static -o a.aarch64 hello.c; \
	else \
			echo "Unknown architecture"; exit 1; \
	fi

hello_amd64: hello.c
	@ARCH=$$( uname -m ); \
	if [ "$$ARCH" = "x86_64" ]; then \
			$(CC) -static -o a.amd64 hello.c; \
	elif [ "$$ARCH" = "aarch64" ]; then \
			$(CC) -static -o a.amd64 --target=x86_64-linux-gnu --gcc-toolchain=/usr --sysroot=/usr/x86_64-linux-gnu hello.c; \
	else \
			echo "Unknown architecture"; exit 1; \
	fi

clean:
	rm a.out
