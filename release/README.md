# How to use release packages
This shows how to use the release packages.

Release Page: https://github.com/yomaytk/elfconv/releases

## Quick Start

### Prerequisites
- [Emscripten](https://github.com/emscripten-core/emscripten) (for browser target)
- [WASI-SDK](https://github.com/WebAssembly/wasi-sdk) (for WASI target)
- WASI runtimes (e.g., [WasmEdge](https://github.com/WasmEdge/WasmEdge), [wasmtime](https://github.com/bytecodealliance/wasmtime))

### Command
```bash
$ tar -zxvf elfconv-<VERSION>-linux-<arch>.tar.gz
$ cd outdir
$ TARGET=aarch64-wasm INITWASM=1 ./elfconv.sh /path/to/elf
```

For more build options (WASI target, multi-process, directory mounting, etc.), see [scripts/README.md](https://github.com/yomaytk/elfconv/blob/main/scripts/README.md).
