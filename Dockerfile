# Choose your LLVM version (16+)
ARG LLVM_VERSION=16
ARG UBUNTU_VERSION=22.04
ARG DISTRO_NAME=jammy
ARG ROOT_DIR=/root/elfconv

# Run-time dependencies go here
FROM ubuntu:${UBUNTU_VERSION}
ARG LLVM_VERSION
ARG UBUNTU_VERSION
ARG DISTRO_NAME
ARG ROOT_DIR

RUN date
RUN apt update

RUN apt install -qqy --no-install-recommends apt-transport-https software-properties-common gnupg ca-certificates wget && \
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
    libc6-dev liblzma-dev zlib1g-dev libselinux1-dev libbsd-dev ccache binutils-dev libelf-dev libiberty-dev && \
    apt upgrade --yes && apt clean --yes && \
    rm -rf /var/lib/apt/lists/*

# cross compile library
RUN apt update && \
  if [ "$( uname -m )" = "x86_64" ]; then \
    dpkg --add-architecture i386 && apt update && apt install -qqy zlib1g-dev:i386 gcc-multilib g++-multilib && apt update && apt install -qqy g++-*-aarch64-linux-gnu; \
  elif [ "$( uname -m )" = "aarch64" ]; then \
    dpkg --add-architecture armhf && apt update && apt install -qqy libstdc++-*-dev-armhf-cross; \
  fi

# emscripten install
RUN cd /root && git clone https://github.com/emscripten-core/emsdk.git && cd emsdk && \
git pull && ./emsdk install latest && ./emsdk activate latest && . ./emsdk_env.sh && echo 'source "/root/emsdk/emsdk_env.sh"' >> /root/.bash_profile

# wasi-sdk install
# takes long times to build wasi-sdk in arm64 because wasi-sdk doesn't release arm64 packages.
RUN \
  if [ "$( uname -m )" = "x86_64" ]; then \
    cd /root && export WASI_VERSION=21 && export WASI_VERSION_FULL=${WASI_VERSION}.0 && ( echo "export WASI_VERSION=21"; echo "export WASI_VERSION_FULL=${WASI_VERSION}.0"; echo "export WASI_SDK_PATH=/root/wasi-sdk-${WASI_VERSION_FULL}" ) >> /root/.bash_profile && \
    wget https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${WASI_VERSION}/wasi-sdk-${WASI_VERSION_FULL}-linux.tar.gz && tar xvf wasi-sdk-${WASI_VERSION_FULL}-linux.tar.gz && rm wasi-sdk-${WASI_VERSION_FULL}-linux.tar.gz; \
  elif [ "$( uname -m )" = "aarch64" ]; then \
    cd /root && echo "export WASI_SDK_PATH=/root/wasi-sdk/build/install/opt/wasi-sdk" >> /root/.bash_profile && git clone --recursive https://github.com/WebAssembly/wasi-sdk.git; \
    cd wasi-sdk && NINJA_FLAGS=-v make package; \
  fi

# WASI Runtimes install
RUN curl -sSf https://raw.githubusercontent.com/WasmEdge/WasmEdge/master/utils/install.sh | bash
RUN curl https://wasmtime.dev/install.sh -sSf | bash && echo 'export PATH=$PATH:/root/.wasmtime/bin' >> /root/.bash_profile

# git settings
RUN git config --global user.email "41898282+github-actions[bot]@users.noreply.github.com" && git config --global user.name "github-actions[bot]"

WORKDIR ${ROOT_DIR}
COPY ./ ./
RUN [ -d "./build" ] && rm -rf ./build || true

RUN chmod +x scripts/container-entry-point.sh
ENTRYPOINT [ "./scripts/container-entry-point.sh" ]
