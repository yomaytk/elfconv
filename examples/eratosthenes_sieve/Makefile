CC=clang-16

target_aarch64: start_aarch64.s cal.c
	@ARCH=$$( uname -m ); \
	if [ "$$ARCH" = "x86_64" ]; then \
			$(CC) -nostdlib -static -o a.aarch64 --target=aarch64-linux-gnu --gcc-toolchain=/usr --sysroot=/usr/aarch64-linux-gnu start_aarch64.s cal.c; \
	elif [ "$$ARCH" = "aarch64" ]; then \
			$(CC) -nostdlib -static -o a.aarch64 start_aarch64.s cal.c; \
	else \
			echo "Unknown architecture"; exit 1; \
	fi

target_benchmark_amd64: start_amd64.s benchmark_amd64.c
	@ARCH=$$( uname -m ); \
	if [ "$$ARCH" = "x86_64" ]; then \
			$(CC) -nostdlib -static -o a.amd64 start_amd64.s benchmark_amd64.c ; \
	elif [ "$$ARCH" = "aarch64" ]; then \
			$(CC) -nostdlib -static -o a.amd64 --target=x86_64-linux-gnu --gcc-toolchain=/usr --sysroot=/usr/x86_64-linux-gnu start_amd64.s benchmark_amd64.c; \
	else \
			echo "Unknown architecture"; exit 1; \
	fi

target_benchmark_amd64_libc: benchmark_amd64_libc.c
	@ARCH=$$( uname -m ); \
	if [ "$$ARCH" = "x86_64" ]; then \
			$(CC) -static -o a.amd64 benchmark_amd64_libc.c ; \
	elif [ "$$ARCH" = "aarch64" ]; then \
			$(CC) -static -o a.amd64 --target=x86_64-linux-gnu --gcc-toolchain=/usr --sysroot=/usr/x86_64-linux-gnu benchmark_amd64_libc.c; \
	else \
			echo "Unknown architecture"; exit 1; \
	fi

clean:
	rm a.out
