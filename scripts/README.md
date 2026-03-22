# Usage

## Overview

elfconv supports three conversion targets from an AArch64 ELF binary:

| Target | `TARGET` value | Output | Runtime |
|---|---|---|---|
| Browser (Wasm) | `aarch64-wasm` | `.wasm` + `.js` + `.html` | Browser (Emscripten) |
| WASI (Wasm) | `aarch64-wasi32` | `.wasm` | WasmEdge etc. |
| Native | `aarch64-native` | Host ELF binary | Direct execution |

## Build Commands

### Browser (ELF → Wasm)

`INITWASM=1` generates `js-kernel.js` and `main.html`. This should be set only for the **init (main) program**. When building additional binaries for multi-process use (e.g., busybox for use from bash), omit `INITWASM`.

**1. Single binary:**
```bash
cd build
TARGET=aarch64-wasm INITWASM=1 ../scripts/dev.sh /path/to/elf
```

**2. Multi-process example (bash + busybox):**
```bash
cd build
# Build the init program (bash) with INITWASM=1
TARGET=aarch64-wasm INITWASM=1 ../scripts/dev.sh /path/to/bash-static
# Build additional binaries without INITWASM
TARGET=aarch64-wasm ../scripts/dev.sh /path/to/busybox
```

**3. With host directory mounting:**
```bash
TARGET=aarch64-wasm INITWASM=1 MOUNT_SETTING="/host/dir@/mount/point" ../scripts/dev.sh /path/to/elf
```

### WASI (ELF → Wasm)
```bash
cd build
TARGET=aarch64-wasi32 ../scripts/dev.sh /path/to/elf
```

### Native (ELF → ELF)
```bash
cd build
TARGET=aarch64-native ../scripts/dev.sh /path/to/elf
```

## Environment Variables

| Variable | Description |
|---|---|
| `TARGET` | **Required.** Conversion target: `aarch64-native`, `aarch64-wasm`, or `aarch64-wasi32` |
| `INITWASM` | Set to `1` to generate `js-kernel.js` and `main.html` (browser target, init program only) |
| `NO_LIFTED` | Skip ELF → LLVM IR lifting (reuse existing `.bc`/`.ll` file) |
| `NO_COMPILED` | Skip LLVM IR → object file compilation (reuse existing `.o` file) |
| `MOUNT_SETTING` | Mount host directories into browser MEMFS. Format: `<host_dir>@<mount_point>` (multiple specs supported, space-separated) |
| `DEBUG` | Enable runtime debug macros (syscall debug, multi-section warnings) |
| `TEXTIR` | Output `.ll` (human-readable LLVM IR) instead of `.bc` |
| `FLOAT_STATUS` | Enable floating-point exception tracking |
| `ECV_OUT_DIR` | Override output directory (default: current directory) |
