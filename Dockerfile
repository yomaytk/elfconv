# syntax=docker/dockerfile:1

ARG TARGETARCH
ARG LLVM_VERSION=16
ARG BASE_IMAGE=ghcr.io/yomaytk/elfconv-base:${TARGETARCH}

FROM ${BASE_IMAGE}
ARG LLVM_VERSION=16
ARG ROOT_DIR=/root/elfconv
ARG ECV_AARCH64
ARG ECV_X86

ENV ELFCONV_AARCH64=${ECV_AARCH64}
ENV ELFCONV_X86=${ECV_X86}

RUN if [ $(( ${ELFCONV_AARCH64:-0} ^ ${ELFCONV_X86:-0} )) -eq 0 ]; then \
      echo "Only one of 'ELFCONV_AARCH64' and 'ELFCONV_X86' should be set to 1."; \
      exit 1; \
    fi

# git settings
RUN git config --global user.email "41898282+github-actions[bot]@users.noreply.github.com" && git config --global user.name "github-actions[bot]"

WORKDIR ${ROOT_DIR}
COPY ./ ./

RUN apt-get update && apt-get install -qqy --no-install-recommends \
      llvm-${LLVM_VERSION}-dev libclang-${LLVM_VERSION}-dev libcurl4-openssl-dev && \
    rm -rf /var/lib/apt/lists/*

RUN ./scripts/build.sh
RUN make -C  ~/elfconv/examples/hello/c
ENTRYPOINT ["/bin/bash", "--login", "-c"]
CMD ["/bin/bash"]
