# Choose your LLVM version (16+)
ARG LLVM_VERSION=16
ARG ARCH=aarch64
ARG UBUNTU_VERSION=22.04
ARG DISTRO_BASE=ubuntu${UBUNTU_VERSION}
ARG BUILD_BASE=ubuntu:${UBUNTU_VERSION}
ARG DISTRO_NAME=jammy
ARG LIBRARIES=/opt/trailofbits
ARG ROOT_DIR=/root/elfconv

# Run-time dependencies go here
FROM ubuntu:22.04
ARG LLVM_VERSION
ARG ARCH
ARG UBUNTU_VERSION
ARG DISTRO_BASE
ARG BUILD_BASE
ARG DISTRO_NAME
ARG ROOT_DIR

RUN date
RUN dpkg --add-architecture armhf
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
RUN apt update
RUN apt install -qqy --no-install-recommends libtinfo-dev libzstd-dev python3-pip python3-setuptools python-setuptools python3 build-essential \
    clang-${LLVM_VERSION} lld-${LLVM_VERSION} libstdc++-*-dev-armhf-cross ninja-build pixz xz-utils make rpm curl unzip tar git zip pkg-config vim \
    libc6-dev liblzma-dev zlib1g-dev libselinux1-dev libbsd-dev ccache binutils-dev libelf-dev && \   
    apt upgrade --yes && apt clean --yes && \
    rm -rf /var/lib/apt/lists/*

# emscripten install
RUN cd /root && git clone https://github.com/emscripten-core/emsdk.git && cd emsdk && \
git pull && ./emsdk install latest && ./emsdk activate latest && . ./emsdk_env.sh && echo 'source "/root/emsdk/emsdk_env.sh"' >> /root/.bash_profile

# wasmedge install
RUN curl -sSf https://raw.githubusercontent.com/WasmEdge/WasmEdge/master/utils/install.sh | bash

# git settings
RUN git config --global user.email "41898282+github-actions[bot]@users.noreply.github.com" && git config --global user.name "github-actions[bot]"

WORKDIR ${ROOT_DIR}
COPY ./ ./
