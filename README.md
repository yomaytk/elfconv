# elfconv

elfconv is an experimental AOT compiler that translates a Linux/aarch64 ELF binary to executable WebAssembly.
elfconv converts a original ELF binary to the LLVM bitcode using the library for lifting machine code to LLVM bitcode, [remill](https://github.com/lifting-bits/remill),
and it uses [emscripten](https://github.com/emscripten-core/emscripten) in order to generate the WASM binary from the LLVM bitcode file.

## Quick Start
You can build elfconv using docker container (currently supported for only aarch64).Please execute the commands as following.
In default settings, both `elflift` (used for generating LLVM bitcode file) and `libelfconv.a` (used for executing generated LLVM bitcode) are installed to `~/.elfconv`.
```bash
$ git clone https://github.com/yomaytk/elfconv
$ cd elfconv
$ docker build . -t elfconv-img
$ docker run -it --name elfconv-sample-container elfconv-img bash
~/elfconv# source ~/.bash_profile
~/elfconv# ./build.sh
```
You can test elfconv using `bin/elfconv.sh` as following.
```bash
~/elfconv# cd bin
~/elfconv/bin# ./elfconv.sh /path/to/ELF # ex.) ../exmaples/print_hello/a.out
~/elfconv/bin# wasmedge exe.wasm # wasmedge is preinstalled
```
## Build
WIP

## Acknowledgement
elfconv uses or references some projects as following. Great thanks to its all developers!
- remill ([Apache Lisence 2.0](https://github.com/lifting-bits/remill/blob/master/LICENSE))
    - Original Source: https://github.com/lifting-bits/remill
    - elfconv uses remill in order to convert machine codes to LLVM IR instructions. the source code is contained in [`./backend/remill`](https://github.com/yomaytk/elfconv/tree/main/backend/remill) and is modified for using from front-end and supporting additional instructions.
- Sleigh Library ([Apache Lisence 2.0](https://github.com/lifting-bits/sleigh/blob/master/LICENSE))
    - Original Source: https://github.com/lifting-bits/sleigh
    - sleigh is a language to describe the semantics of instructions, and this library is part of the [Ghidra reverse engineering platform](https://github.com/NationalSecurityAgency/ghidra) and underpins its disassemler and decompilation engines.
- MyAOT ([Apache Lisence 2.0](https://github.com/AkihiroSuda/myaot/blob/master/LICENSE))
    - Original Source: https://github.com/AkihiroSuda/myaot
    - An experimental AOT-ish compiler (Linux/riscv32 ELF → Linux/x86_64 ELF, Mach-O, WASM, ...)
    - We refrenced the design of MyAOT for developing elfconv.
