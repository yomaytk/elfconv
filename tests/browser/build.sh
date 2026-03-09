#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OUT_DIR="${SCRIPT_DIR}/wasm-out"

mkdir -p "${OUT_DIR}"

cd "${ROOT_DIR}/build"
TARGET=aarch64-wasm INITWASM=1 ECV_OUT_DIR="${OUT_DIR}" \
  "${ROOT_DIR}/scripts/dev.sh" "${ROOT_DIR}/examples/hello/c/hello_stripped"

echo "Browser Wasm artifacts built in ${OUT_DIR}"
