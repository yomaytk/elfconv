# syntax=docker/dockerfile:1

ARG TARGETARCH
ARG BASE_IMAGE=ghcr.io/yomaytk/elfconv-base:${TARGETARCH}

FROM ${BASE_IMAGE}
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

RUN ./scripts/build.sh
RUN make -C  ~/elfconv/examples/hello/c
ENTRYPOINT ["/bin/bash", "--login", "-c"]
CMD ["/bin/bash"]
