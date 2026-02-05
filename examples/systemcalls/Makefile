CC    := clang-16
GCC   := gcc

.PHONY: all clean

all: fsync_unlink args fork fork-wait getrusage test_syscalls

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

fsync_unlink:
	$(call build,fsync_unlink.c,fsync_unlink.aarch64);

args:
	$(call build,args.c,args.aarch64);

fork:
	$(call build,fork.c,fork.aarch64);

fork-wait:
	$(call build,fork-wait.c,fork-wait.aarch64);

getrusage:
	$(call build,getrusage.c,getrusage.aarch64);

test_syscalls:
	$(call build,test_syscalls.c,test_syscalls.aarch64);

clean:
	rm -f *.aarch64 *.out *.js *.wasm *.html