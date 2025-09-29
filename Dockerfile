# Choose your LLVM version (16+)
ARG LLVM_VERSION=16
ARG UBUNTU_VERSION=22.04
ARG DISTRO_NAME=jammy
ARG ROOT_DIR=/root/elfconv
ARG ECV_AARCH64
ARG ECV_X86

# Run-time dependencies go here
FROM ubuntu:${UBUNTU_VERSION}
ARG LLVM_VERSION
ARG UBUNTU_VERSION
ARG DISTRO_NAME
ARG ROOT_DIR
ARG ECV_AARCH64
ARG ECV_X86

ENV ELFCONV_AARCH64=${ECV_AARCH64}
ENV ELFCONV_X86=${ECV_X86}

RUN if [ $(( ${ELFCONV_AARCH64:-0} ^ ${ELFCONV_X86:-0} )) -eq 0 ]; then \
      echo "Only one of 'ELFCONV_AARCH64' and 'ELFCONV_X86' should be set to 1."; \
      exit 1; \
    fi

RUN date

RUN apt-get update && apt-get install -qqy --no-install-recommends apt-transport-https software-properties-common gnupg ca-certificates wget && \
  apt-add-repository ppa:git-core/ppa --yes

# cmake install
RUN wget "https://github.com/Kitware/CMake/releases/download/v3.22.1/cmake-3.22.1-linux-$(uname -m).sh" && \
  /bin/bash cmake-*.sh --skip-license --prefix=/usr/local && rm cmake-*.sh

# set llvm package URL to sources.list
RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - && \
  echo "deb http://apt.llvm.org/${DISTRO_NAME}/ llvm-toolchain-${DISTRO_NAME}-${LLVM_VERSION} main" >> /etc/apt/sources.list && \
  echo "deb-src http://apt.llvm.org/${DISTRO_NAME}/ llvm-toolchain-${DISTRO_NAME}-${LLVM_VERSION} main" >> /etc/apt/sources.list

# several install
RUN apt-get update && apt-get install -qqy --no-install-recommends file libtinfo-dev libzstd-dev python3-pip python3-setuptools python-setuptools python3 build-essential \
  clang-${LLVM_VERSION} lld-${LLVM_VERSION} llvm-${LLVM_VERSION} ninja-build pixz xz-utils make rpm curl unzip tar git zip pkg-config vim openssh-client \
  libc6-dev liblzma-dev zlib1g-dev libselinux1-dev libbsd-dev ccache binutils-dev libelf-dev libiberty-dev qemu-user-binfmt libdwarf1 libdwarf-dev && \
  apt-get upgrade --yes && apt-get clean --yes && \
  rm -rf /var/lib/apt/lists/*

# cross compile library
RUN apt-get update && \
  if [ "$( uname -m )" = "x86_64" ]; then \
  dpkg --add-architecture i386 && apt-get update && apt-get install -qqy zlib1g-dev:i386 gcc-multilib g++-multilib && apt-get update && apt-get install -qqy g++-*-aarch64-linux-gnu; \
  elif [ "$( uname -m )" = "aarch64" ]; then \
  dpkg --add-architecture armhf && apt-get update && apt-get install -qqy libstdc++-*-dev-armhf-cross; \
  fi

# emscripten install
RUN cd /root && git clone https://github.com/emscripten-core/emsdk.git && cd emsdk && \
  git pull && ./emsdk install latest && ./emsdk activate latest && . ./emsdk_env.sh && echo 'source "/root/emsdk/emsdk_env.sh"' >> /root/.bash_profile

# wasi-sdk install
RUN \
  if [ "$( uname -m )" = "x86_64" ]; then \
  cd /root && export WASI_OS=linux && export WASI_ARCH=x86_64 && export WASI_VERSION=24 && export WASI_VERSION_FULL=${WASI_VERSION}.0 && \
  /bin/bash -c 'echo -e "export WASI_OS=linux\nexport WASI_ARCH=x86_64\nexport WASI_VERSION=24\nexport WASI_VERSION_FULL=${WASI_VERSION}.0\nexport WASI_SDK_PATH=/root/wasi-sdk-${WASI_VERSION_FULL}-${WASI_ARCH}-${WASI_OS}" >> /root/.bash_profile' && \
  wget https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${WASI_VERSION}/wasi-sdk-${WASI_VERSION_FULL}-${WASI_ARCH}-${WASI_OS}.tar.gz && tar xvf wasi-sdk-${WASI_VERSION_FULL}-${WASI_ARCH}-${WASI_OS}.tar.gz; \
  elif [ "$( uname -m )" = "aarch64" ]; then \
  cd /root && export WASI_OS=linux && export WASI_ARCH=arm64 && export WASI_VERSION=24 && export WASI_VERSION_FULL=${WASI_VERSION}.0 && \
  /bin/bash -c 'echo -e "export WASI_OS=linux\nexport WASI_ARCH=arm64\nexport WASI_VERSION=24\nexport WASI_VERSION_FULL=${WASI_VERSION}.0\nexport WASI_SDK_PATH=/root/wasi-sdk-${WASI_VERSION_FULL}-${WASI_ARCH}-${WASI_OS}" >> /root/.bash_profile' && \
  wget https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${WASI_VERSION}/wasi-sdk-${WASI_VERSION_FULL}-${WASI_ARCH}-${WASI_OS}.tar.gz && tar xvf wasi-sdk-${WASI_VERSION_FULL}-${WASI_ARCH}-${WASI_OS}.tar.gz; \
  fi

# WASI Runtimes install
RUN curl -sSf https://raw.githubusercontent.com/WasmEdge/WasmEdge/master/utils/install.sh | bash
RUN curl https://wasmtime.dev/install.sh -sSf | bash && echo 'export PATH=$PATH:/root/.wasmtime/bin' >> /root/.bash_profile

# git settings
RUN git config --global user.email "41898282+github-actions[bot]@users.noreply.github.com" && git config --global user.name "github-actions[bot]"

WORKDIR ${ROOT_DIR}
COPY ./ ./
RUN ./scripts/build.sh
RUN make -C  ~/elfconv/examples/hello/c
ENTRYPOINT ["/bin/bash", "--login", "-c"]
CMD ["/bin/bash"]
