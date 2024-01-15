# elfconv
elfconv is an experimental AOT compiler that translates a Linux/aarch64 ELF binary to executable WebAssembly.
elfconv converts a original ELF binary to the LLVM bitcode using [remill](https://github.com/lifting-bits/remill) (library for lifting machine code to LLVM bitcode)
and it uses [emscripten](https://github.com/emscripten-core/emscripten) in order to generate the WASM binary from the LLVM bitcode file.

"**elfconv is a work in progress**" and the test is insufficient, so you may fail to compile your ELF binary or execute the generated WASM binary. Particularly, There are many aarch64 instructions and Linux syscalls elfconv doesn't support now. 
## Quick Start
You can try elfconv using docker container (currently supported for only aarch64) executing the commands as follows.
In default settings, both `elflift` (used for generating LLVM bitcode file) and `libelfconv.a` (used for executing generated LLVM bitcode) are installed to `~/.elfconv`.
You can execute WASM application on the both browser and host environment (WASI runtimes).
### Browser
```bash
$ git clone https://github.com/yomaytk/elfconv
$ cd elfconv
$ docker build . -t elfconv-image
$ docker run -it --rm -p 8080:8080 --name elfconv-container elfconv-image
### ENTRYPOINT: elfconv/scripts/container-entry-point.sh
### running build and test ...
# You can test elfconv using `bin/elfconv.sh`
~/elfconv# cd bin
~/elfconv/bin# ./elfconv.sh /path/to/ELF # e.g. ../exmaples/eratosthenes_sieve/a.out
~/elfconv/bin# emrun --no_browser --port 8080 exe.wasm.html
Web server root directory: /root/elfconv/bin
Now listening at http://0.0.0.0:8080/
```
Now, the WASM application server has started, so that you can access it (e.g. http://localhost:8080/exe.wasm.html) from outside the container.
### Host (WASI runtimes)
The procedure is almost the same as the case of the browser environment, but you don't need to set up port forwarding and should set the environment variable `SERVER` to 1 to build for WASI runtimes.
```bash
$ git clone https://github.com/yomaytk/elfconv
$ cd elfconv
$ docker build . -t elfconv-image
$ docker run -it --name elfconv-container elfconv-image
### ENTRYPOINT: elfconv/scripts/container-entry-point.sh
### running build and test ...
# You can test elfconv using `bin/elfconv.sh`
~/elfconv# cd bin
~/elfconv/bin# SERVER=1 ./elfconv.sh /path/to/ELF # e.g. ../exmaples/eratosthenes_sieve/a.out
~/elfconv/bin# wasmedge exe.wasm # wasmedge is preinstalled
```
## Build
You can easily build and develop elfconv on the container. Thus, please see [Quick Start](#quick-start) and prepare the docker container if you have not done it.

After executing `./scripts/build.sh` (please see [Quick Start](#quick-start)) , `elfconv/build` directory is generated and you can build `build/front/elflift` with `ninja elflift`.
```shell
~/elfconv/build# ninja elflift
```
`elflift` is used to convert the target ELF binary to LLVM bitcode file. After generating `build/front/elflift`, you can compile the ELF binary to the WASM binary using `scripts/dev.sh` as follows.
```shell
### Browser
~/elfconv/build# WASM=1 ../scripts/dev.sh path/to/ELF # generate the WASM binary under the elfconv/build/front
~/elfconv/build# emrun --no_browser --port 8080 ./front/exe.wasm.html # execute the generated WASM binary with emscripten
------------------------
### Host (WASI Runtimes)
~/elfconv/build# WASM=1 SERVER=1 ../scripts/dev.sh path/to/ELF
~/elfconv/build# wasmedge ./front/exe.wasm
```
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
