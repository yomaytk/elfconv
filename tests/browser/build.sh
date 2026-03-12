#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PROJECT="${1:-all}"

build_hello() {
  local OUT_DIR="${SCRIPT_DIR}/wasm-out"
  mkdir -p "${OUT_DIR}"
  cd "${ROOT_DIR}/build"
  TARGET=aarch64-wasm INITWASM=1 ECV_OUT_DIR="${OUT_DIR}" \
    "${ROOT_DIR}/scripts/dev.sh" "${ROOT_DIR}/examples/hello/c/hello_stripped"
  echo "Browser Wasm artifacts built in ${OUT_DIR}"
}

build_bash() {
  local BASH_OUT_DIR="${SCRIPT_DIR}/wasm-out-bash"
  mkdir -p "${BASH_OUT_DIR}"
  cd "${ROOT_DIR}/build"
  TARGET=aarch64-wasm INITWASM=1 ECV_OUT_DIR="${BASH_OUT_DIR}" \
    "${ROOT_DIR}/scripts/dev.sh" /usr/bin/bash-static
  TARGET=aarch64-wasm ECV_OUT_DIR="${BASH_OUT_DIR}" \
    "${ROOT_DIR}/scripts/dev.sh" "${ROOT_DIR}/examples/examples-repos/busybox/busybox"
  echo "Browser Wasm artifacts (bash+busybox) built in ${BASH_OUT_DIR}"
}

case "${PROJECT}" in
  hello) build_hello ;;
  bash)  build_bash ;;
  all)   build_hello; build_bash ;;
  *)     echo "Usage: $0 {hello|bash|all}"; exit 1 ;;
esac
