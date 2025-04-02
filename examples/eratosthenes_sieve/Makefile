CC=clang-16

eratosthenes_sieve_aarch64: start_aarch64.s cal.c
	@ARCH=$$( uname -m ); \
	if [ "$$ARCH" = "x86_64" ]; then \
			$(CC) -nostdlib -static -o a.aarch64 --target=aarch64-linux-gnu --gcc-toolchain=/usr --sysroot=/usr/aarch64-linux-gnu start_aarch64.s cal.c; \
	elif [ "$$ARCH" = "aarch64" ]; then \
			$(CC) -nostdlib -static -o a.aarch64 start_aarch64.s cal.c; \
	else \
			echo "Unknown architecture"; exit 1; \
	fi

eratosthenes_sieve_amd64: start_amd64.s cal.c
	@ARCH=$$( uname -m ); \
	if [ "$$ARCH" = "x86_64" ]; then \
			$(CC) -nostdlib -static -o a.amd64 start_amd64.s cal.c ; \
	elif [ "$$ARCH" = "aarch64" ]; then \
			$(CC) -nostdlib -static -o a.amd64 --target=x86_64-linux-gnu --gcc-toolchain=/usr --sysroot=/usr/x86_64-linux-gnu start_amd64.s cal.c; \
	else \
			echo "Unknown architecture"; exit 1; \
	fi

clean:
	rm a.out
