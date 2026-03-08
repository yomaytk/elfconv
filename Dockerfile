# syntax=docker/dockerfile:1
ARG LLVM_VERSION=16
ARG EMCC_VERSION=4.0.9
ARG UBUNTU_VERSION=22.04
ARG DISTRO_NAME=jammy

# stage 1. System packages and toolchain installation
FROM ubuntu:${UBUNTU_VERSION}@sha256:3ba65aa20f86a0fad9df2b2c259c613df006b2e6d0bfcc8a146afb8c525a9751 AS toolchain
ARG LLVM_VERSION
ARG DISTRO_NAME

RUN apt-get update && \
    apt-get install -qqy --no-install-recommends \
      apt-transport-https software-properties-common gnupg ca-certificates wget && \
    apt-add-repository ppa:git-core/ppa --yes && \
    wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | gpg --dearmor -o /usr/share/keyrings/llvm-snapshot.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/llvm-snapshot.gpg] http://apt.llvm.org/${DISTRO_NAME}/ llvm-toolchain-${DISTRO_NAME}-${LLVM_VERSION} main" >> /etc/apt/sources.list && \
    echo "deb-src [signed-by=/usr/share/keyrings/llvm-snapshot.gpg] http://apt.llvm.org/${DISTRO_NAME}/ llvm-toolchain-${DISTRO_NAME}-${LLVM_VERSION} main" >> /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -qqy --no-install-recommends \
      build-essential python3 pkg-config \
      clang-${LLVM_VERSION} lld-${LLVM_VERSION} llvm-${LLVM_VERSION} llvm-${LLVM_VERSION}-dev libclang-${LLVM_VERSION}-dev \
      ninja-build \
      curl unzip tar git \
      libc6-dev liblzma-dev zlib1g-dev \
      binutils-dev libelf-dev libiberty-dev libdwarf-dev && \
    apt-get upgrade --yes && apt-get clean --yes && \
    rm -rf /var/lib/apt/lists/*

# cmake install
RUN wget "https://github.com/Kitware/CMake/releases/download/v3.22.1/cmake-3.22.1-linux-$(uname -m).sh" && \
    if [ "$(uname -m)" = "x86_64" ]; then \
      echo "808a712bcb039fd71f6960dca82a9befb977d8bdb074718218cf7646fd08bb7a  cmake-3.22.1-linux-x86_64.sh" | sha256sum -c -; \
    elif [ "$(uname -m)" = "aarch64" ]; then \
      echo "ff886c6c16be867229a6c1fe4bc963ff77ae24187d5a8d64ef72a06f84c1a25c  cmake-3.22.1-linux-aarch64.sh" | sha256sum -c -; \
    fi && \
    /bin/bash cmake-*.sh --skip-license --prefix=/usr/local && rm cmake-*.sh

# stage 2. SDK and WASI runtime installation
FROM toolchain AS sdks
ARG EMCC_VERSION
# emscripten install
RUN cd /root && git clone --branch ${EMCC_VERSION} --depth 1 https://github.com/emscripten-core/emsdk.git && cd emsdk && \
    ./emsdk install ${EMCC_VERSION} && ./emsdk activate ${EMCC_VERSION} && \
    . ./emsdk_env.sh && echo 'source "/root/emsdk/emsdk_env.sh"' >> /root/.bash_profile

# wasi-sdk install
RUN cd /root && \
    export WASI_VERSION=24 && \
    export WASI_VERSION_FULL=${WASI_VERSION}.0 && \
    if [ "$(uname -m)" = "x86_64" ]; then \
      export WASI_OS=linux WASI_ARCH=x86_64; \
    elif [ "$(uname -m)" = "aarch64" ]; then \
      export WASI_OS=linux WASI_ARCH=arm64; \
    fi && \
    printf 'export WASI_OS=%s\nexport WASI_ARCH=%s\nexport WASI_VERSION=%s\nexport WASI_VERSION_FULL=%s\nexport WASI_SDK_PATH=/root/wasi-sdk-%s-%s-%s\n' "${WASI_OS}" "${WASI_ARCH}" "${WASI_VERSION}" "${WASI_VERSION_FULL}" "${WASI_VERSION_FULL}" "${WASI_ARCH}" "${WASI_OS}" >> /root/.bash_profile && \
    wget https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${WASI_VERSION}/wasi-sdk-${WASI_VERSION_FULL}-${WASI_ARCH}-${WASI_OS}.tar.gz && \
    tar xvf wasi-sdk-${WASI_VERSION_FULL}-${WASI_ARCH}-${WASI_OS}.tar.gz && \
    rm -f wasi-sdk-*.tar.gz

# WasmEdge install
RUN curl -sSf https://raw.githubusercontent.com/WasmEdge/WasmEdge/master/utils/install.sh -o /tmp/wasmedge_install.sh && \
    bash /tmp/wasmedge_install.sh && \
    rm /tmp/wasmedge_install.sh

# Wasmtime install (latest release, no pipe to bash)
RUN curl -sSf https://wasmtime.dev/install.sh -o /tmp/wasmtime_install.sh && \
    bash /tmp/wasmtime_install.sh && \
    echo 'export PATH=$PATH:/root/.wasmtime/bin' >> /root/.bash_profile && \
    rm /tmp/wasmtime_install.sh

# stage 3. build elfconv
FROM sdks AS resimg
ARG ROOT_DIR=/root/elfconv
ARG ECV_AARCH64
ARG ECV_X86

ENV ELFCONV_AARCH64=${ECV_AARCH64}
ENV ELFCONV_X86=${ECV_X86}

RUN if [ $(( ${ELFCONV_AARCH64:-0} ^ ${ELFCONV_X86:-0} )) -eq 0 ]; then \
      echo "Only one of 'ELFCONV_AARCH64' and 'ELFCONV_X86' should be set to 1."; \
      exit 1; \
    fi

WORKDIR ${ROOT_DIR}
COPY ./ ./

RUN ./scripts/build.sh
RUN make -C  /root/elfconv/examples/hello/c hello
ENTRYPOINT ["/bin/bash", "--login", "-c"]
CMD ["/bin/bash"]
