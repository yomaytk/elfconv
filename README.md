# elfconv

elfconv is an experimental AOT compiler that translates a Linux/aarch64 ELF binary to WebAssembly (ELF -> LLVM IR -> WASM).

## Quick Start
`bin` directory contains all binary files needed for ELF conversion, and you can generate WASM binary `(exe.wasm)` executing `bin/elfconv.sh`.
elfconv uses [emscripten](https://github.com/emscripten-core/emscripten) to generate WASM binary, so you should set environment variable `EMCC` in the elfconv.sh to the path to `emcc` command.
And `examples` directory has some sample ELF binaries, so you can use those for experimental use (But `hello/a.out` cannot be executed now).
```bash
$ cd bin
$ bash elfconv.sh </path/to/ELF/> # ex.) ../examples/add/a.out
$ <WASM Runtime> exe.wasm # ex.) <WASM Runtime>: wasmtime, wasmedge ...
```
## Build
WIP
