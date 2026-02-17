CC    := clang-16
GCC   := gcc

.PHONY: all clean

all: test_syscalls

define build
	@echo "Building $(2) on $$(uname -m)"
	@ARCH=$$(uname -m); \
	if [ "$$ARCH" = "x86_64" ]; then \
	  $(CC) -O3 -static --target=aarch64-linux-gnu --gcc-toolchain=/usr \
	    --sysroot=/usr/aarch64-linux-gnu $(1) -o $(2) -fuse-ld=lld -pthread; \
	elif [ "$$ARCH" = "aarch64" ]; then \
	  $(GCC) -O3 -static $(1) -o $(2); \
	else \
	  echo "Unknown architecture: $$ARCH" >&2; exit 1; \
	fi
endef

test_syscalls:
	$(call build,test_syscalls.c,test_syscalls.aarch64);

clean:
	rm -f *.aarch64 *.out *.js *.wasm *.html