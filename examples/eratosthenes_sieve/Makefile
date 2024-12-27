CC=clang-16

eratosthenes_sieve_arm64: start_arm64.s cal.c
	@ARCH=$$( uname -m ); \
	if [ "$$ARCH" = "x86_64" ]; then \
			$(CC) -nostdlib -static -o a.arm64 --target=aarch64-linux-gnu --gcc-toolchain=/usr --sysroot=/usr/aarch64-linux-gnu start_arm64.s cal.c -fuse-ld=lld -pthread; \
	elif [ "$$ARCH" = "aarch64" ]; then \
			$(CC) -nostdlib -static -o a.arm64 start_arm64.s cal.c; \
	else \
			echo "Unknown architecture"; exit 1; \
	fi

eratosthenes_sieve_amd64: start_amd64.s cal.c
	@ARCH=$$( uname -m ); \
	if [ "$$ARCH" = "x86_64" ]; then \
			$(CC) -nostdlib -static -o a.amd64 start_amd64.s cal.c ; \
	elif [ "$$ARCH" = "aarch64" ]; then \
			$(CC) -nostdlib -static -o a.amd64 --target=x86_64-linux-gnu --gcc-toolchain=/usr --sysroot=/usr/x86_64-linux-gnu start_amd64.s cal.c -fuse-ld=lld -pthread; \
	else \
			echo "Unknown architecture"; exit 1; \
	fi

clean:
	rm a.out
