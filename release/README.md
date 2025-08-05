# How to use release packages
This shows how to use the release packages. 

Release Page: https://github.com/yomaytk/elfconv/releases

## Quick Start
You can translate the ELF binary to the WASM binary using `outdir` directory. 

### settings
You should prepare [Emscripten](https://github.com/emscripten-core/emscripten), [WASI-SDK](https://github.com/WebAssembly/wasi-sdk) and WASI runtimes (e.g., [WasmEdge](https://github.com/WasmEdge/WasmEdge), [wasmtime](https://github.com/bytecodealliance/wasmtime))
### command
After configuring the above settings, you can try translation by the command as follows.
```bash
$ tar -zxvf elfconv-v0.2.0-linux-amd64.tar.gz
$ cd outdir
$ TARGET=aarch64-wasm ./elfconv.sh </path/to/ELF> # generates out/exe.wasm
```
