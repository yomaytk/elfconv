CC    := clang-16
GCC   := gcc

.PHONY: all clean

all: parent child

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

parent:
	$(call build,parent.c,parent);

child:
	$(call build,child.c,child);

clean:
	rm parent child