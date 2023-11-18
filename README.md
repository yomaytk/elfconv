# elfconv

elfconv is an experimental AOT compiler that translates a Linux/aarch64 ELF binary to executable WebAssembly.
elfconv converts a original ELF binary to the LLVM bitcode using the library for lifting machine code to LLVM bitcode, [remill](https://github.com/lifting-bits/remill),
and it uses [emscripten](https://github.com/emscripten-core/emscripten) in order to generate the WASM binary from the LLVM bitcode file.

## Examples
`bin` directory contains all binary files needed for ELF conversion (those are Linux/aarch64 ELF binary files), and you can generate WASM binary `(exe.wasm)` executing `bin/elfconv.sh`.
elfconv uses emscripten, so you should set environment variable `EMCC` in the elfconv.sh to the path to `emcc` command.
And `examples` directory has some sample ELF binaries, so you can use those for experimental use (But `hello/a.out` cannot be executed now).
```bash
$ cd bin
$ ./elfconv.sh </path/to/ELF/> # ex.) ../examples/add/a.out
$ <WASM Runtime> exe.wasm # ex.) <WASM Runtime>: wasmedge, wasmtime ...
```
## Build
WIP

## Acknowledgement
elfconv uses or refers projects as following. Great thanks to its all developers!
- remill ([Apache Lisence 2.0](https://github.com/lifting-bits/remill/blob/master/LICENSE))
    - Original Source: https://github.com/lifting-bits/remill
    - elfconv uses remill in order to convert machine codes to LLVM IR instructions. the source code is contained in [`./backend/remill`](https://github.com/yomaytk/elfconv/tree/main/backend/remill) and is modified for using from front-end and supporting additional instructions.
- MyAOT ([Apache Lisence 2.0](https://github.com/AkihiroSuda/myaot/blob/master/LICENSE))
    - Original Source: https://github.com/AkihiroSuda/myaot
    - An experimental AOT-ish compiler (Linux/riscv32 ELF → Linux/x86_64 ELF, Mach-O, WASM, ...)
    - We refrenced the design of MyAOT for developing elfconv.
