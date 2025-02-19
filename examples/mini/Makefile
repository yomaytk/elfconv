CC=clang-16

simple_hello_world_aarch64: simple_hello_world_aarch64.s
	@ARCH=$$( uname -m ); \
	if [ "$$ARCH" = "x86_64" ]; then \
			$(CC) -nostdlib -static -o a.aarch64 --target=aarch64-linux-gnu --gcc-toolchain=/usr --sysroot=/usr/aarch64-linux-gnu simple_hello_world_aarch64.s; \
	elif [ "$$ARCH" = "aarch64" ]; then \
			$(CC) -nostdlib -static -o a.aarch64 simple_hello_world_aarch64.s; \
	else \
			echo "Unknown architecture"; exit 1; \
	fi

simple_hello_world_amd64: simple_hello_world_amd64.s
	@ARCH=$$( uname -m ); \
	if [ "$$ARCH" = "x86_64" ]; then \
			$(CC) -static -nostdlib simple_hello_world_amd64.s -o a.amd64; \
	elif [ "$$ARCH" = "aarch64" ]; then \
			$(CC) -nostdlib -static -o a.amd64 --target=x86_64-linux-gnu --gcc-toolchain=/usr --sysroot=/usr/x86_64-linux-gnu simple_hello_world_amd64.s -fuse-ld=lld; \
	else \
			echo "Unknown architecture"; exit 1; \
	fi

amd64_test: amd64_test.s
	@ARCH=$$( uname -m ); \
	if [ "$$ARCH" = "x86_64" ]; then \
			$(CC) -nostdlib -static amd64_test.s -o amd64_test.amd64; \
	elif [ "$$ARCH" = "aarch64" ]; then \
			$(CC) -nostdlib -static -o amd64_test.amd64 --target=x86_64-linux-gnu --gcc-toolchain=/usr --sysroot=/usr/x86_64-linux-gnu amd64_test.s; \
	else \
			echo "Unknown architecture"; exit 1; \
	fi

clean:
	rm a.out
