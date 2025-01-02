CC=clang-16

simple_hello_world_amd64: simple_hello_world_amd64.s
	@ARCH=$$( uname -m ); \
	if [ "$$ARCH" = "x86_64" ]; then \
			$(CC) -o simple_hello_world.amd64; \
	elif [ "$$ARCH" = "aarch64" ]; then \
			$(CC) -nostdlib -static -o simple_hello_world.amd64 --target=x86_64-linux-gnu --gcc-toolchain=/usr --sysroot=/usr/x86_64-linux-gnu simple_hello_world_amd64.s -fuse-ld=lld; \
	else \
			echo "Unknown architecture"; exit 1; \
	fi

clean:
	rm a.out
