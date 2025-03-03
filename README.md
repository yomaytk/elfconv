# elfconv
elfconv is an experimental AOT compiler that translates a Linux ELF binary to executable WebAssembly.
elfconv converts an original ELF binary to the LLVM bitcode using [remill](https://github.com/lifting-bits/remill) (library for lifting machine code to LLVM bitcode)
and elfconv uses [emscripten](https://github.com/emscripten-core/emscripten) (for browser) or [wasi-sdk](https://github.com/WebAssembly/wasi-sdk) (for WASI runtimes) to generate the WASM binary from the LLVM bitcode file.

## Status
> [!WARNING]
> "**elfconv is a work in progress**" and the test is insufficient, so you may fail to compile your ELF binary or execute the generated WASM binary. Current limitations are as follows.
- Only support of aarch64 ELF binary as an input binary
    - Furthermore, a part of aarch64 instructions are not supported. If your ELF binary's instruction is not supported, elfconv outputs the message (\[WARNING\] Unsupported instruction at 0x...)
- No support for stripped binaries
- No support for shared objects
- a lot of Linux system calls are unimplemented (ref: [`runtime/syscalls/`](https://github.com/yomaytk/elfconv/blob/main/runtime/syscalls))

## Benchmark
Existing projects similar to elfconv include [`container2wasm`](https://github.com/container2wasm/container2wasm) and [`v86`](https://github.com/copy/v86), which port CPU emulators to Wasm, allowing arbitrary Linux applications to run in a Wasm environment as-is. 
Below are the performance comparison results between elfconv and container2wasm for several ELF/aarch64 applications (v86 supports only 32-bit programs, so it has not been compared yet).

| ELF/aarch64      | container2wasm      | elfconv      | times |
|----------|----------|----------|----------|
| [`eratosthenes_sieve`](https://github.com/yomaytk/elfconv/tree/main/examples/benchmarks/eratosthenes_sieve) (↓ better) | 12.98 (s)  | **2.02** (s)  | **6.49** |
| [`LINPACK benchmark`](https://www.netlib.org/linpack/) (↑ better) | 19.3 (MFLOPS) | **164.9** (MFLOPS) | **8.54** |
| [`fs_mark benchmark`](https://openbenchmarking.org/test/pts/fs-mark&eval=23f3bcd2e402020a107b6b06bdafebb7943ca11a) (↑ better) | 171.0 (Files/s) | **1338.0** (Files/s)| **7.82** |

As shown in the table above, the AOT compilation approach of elfconv significantly outperforms CPU emulators in terms of performance. But does this mean that elfconv is superior to the projects based on CPU emulators above? Unfortunately not. **While container2wasm and v86 can run arbitrary Linux applications that can be executed by the CPU emulator, elfconv currently has limited support for Linux system call implementations and convertible machine code.** As a result, elfconv is inferior to those projects based on CPU emulators in terms of the diversity of applications it can execute.

## Quick Start
You can try elfconv using the docker container (amd64 and arm64) by executing the commands as follows and can execute the WASM application on the both browser and host environment (WASI runtimes).

### Browser
```bash
$ git clone --recursive https://github.com/yomaytk/elfconv
$ cd elfconv
elfconv/$ docker build . -t <image-name>
elfconv/$ docker run -it --rm -p 8080:8080 --name <container-name> <image-name>
### running build and test ...
# You can test elfconv using `bin/elfconv.sh`
~/elfconv# cd bin
~/elfconv/bin# TARGET=Browser ./elfconv.sh /path/to/ELF # e.g. ../examples/hello/a.out
# exe.js and exe.wasm should be generated.
~/elfconv/bin# emrun --no_browser --port 8080 exe.html
Web server root directory: /root/elfconv/bin
Now listening at http://0.0.0.0:8080/
```
Now, the WASM application server has started, so that you can access it (e.g. http://localhost:8080/exe.wasm.html) from outside the container.
### Host (WASI runtimes)
```bash
$ git clone --recursive https://github.com/yomaytk/elfconv
$ cd elfconv
$ docker build . -t <image-name>
$ docker run -it --name <container-name> <image-name>
### running build and test ...
# You can test elfconv using `bin/elfconv.sh`
~/elfconv# cd bin
~/elfconv/bin# TARGET=Wasi ./elfconv.sh /path/to/ELF # e.g. ../examples/hello/a.out
~/elfconv/bin# wasmtime exe.wasm # wasmtime is preinstalled
```
## Source code build
### 1. Dev Container
elfconv provides the Dev Container environment using the root [`Dockerfile`](https://github.com/yomaytk/elfconv/blob/main/Dockerfile) and [`.devcontainer.json`](https://github.com/yomaytk/elfconv/blob/main/.devcontainer.json), so you can develop without making the build environment if you can use Dev Container on your vscode (Please refer to the official website of vscode for basically using Dev Container).
### 2. Local Environment
#### Dependencies
The libraries required for the build are almost the same as those for remill, and the main libraries are as follows. The other required libraries are automatically installed using [cxx-common](https://github.com/lifting-bits/cxx-common).

| Name | Version |
| ---- | ------- |
| [Git](https://git-scm.com/) | Latest |
| [CMake](https://cmake.org/) | 3.14+ |
| [Google Flags](https://github.com/google/glog) | Latest |
| [Google Log](https://github.com/google/glog) | Latest |
| [Google Test](https://github.com/google/googletest) | Latest |
| [LLVM](http://llvm.org/) | 16 |
| [Clang](http://clang.llvm.org/) | 16+ |
| [Intel XED](https://software.intel.com/en-us/articles/xed-x86-encoder-decoder-software-library) | Latest |
| Unzip | Latest |
| [ccache](https://ccache.dev/) | Latest |

#### Build
If you prepare these libraries, you can easily build elfconv by executing [`scripts/build.sh`](https://github.com/yomaytk/elfconv/blob/main/scripts/build.sh) as follows.
```bash
$ git clone --recursive https://github.com/yomaytk/elfconv
$ cd elfconv
/elfconv$ ./scripts/build.sh
```
> [!NOTE]
> If you fail to build elfconv, please feel free to submit an issue!
### Develop
After finishing the build, you can find the directory `elfconv/build/`, and you can build the *'lifter'* (*'lifter'* is the module that converts the ELF binary to LLVM bitcode and those source codes are mainly located in the [`backend/remill/`](https://github.com/yomaytk/elfconv/tree/main/backend/remill) and [`lifter/`](https://github.com/yomaytk/elfconv/tree/main/lifter)) by *ninja* after modifying the *'lifter'* codes.

You can compile the ELF binary to the WASM binary using [`scripts/dev.sh`](https://github.com/yomaytk/elfconv/blob/main/scripts/dev.sh) as follows. `dev.sh` execute the translation (ELF -> LLVM bitcode by *'lifter'*) and compiles the [`runtime/`](https://github.com/yomaytk/elfconv/tree/main/runtime) (statically linked with generated LLVM bitcode) and generate the WASM binary. when you execute the script, you should explicitly specify the path of the elfconv directory (`/root/elfconv` on the container) with `NEW_ROOT` or rewrite the `ROOT_DIR` in `dev.sh`. 
```bash
# TARGET=<elf_arch>-<target_arch> (e.g. ELF/aarch64 -> Wasi32: aarch64-wasi32)

### Native
~/elfconv/build# NEW_ROOT=/path/to/elfconv TARGET=aarch64-native ../scripts/dev.sh path/to/ELF # generate the Native binary (Host achitecture) under the elfconv/build/lifter
~/elfconv/build# ./exe.${HOST_CPU}
------------------------
### Browser (use xterm-pty (https://github.com/mame/xterm-pty))
~/elfconv/build# NEW_ROOT=/path/to/elfconv TARGET=aarch64-wasm ../scripts/dev.sh path/to/ELF # generate the WASM binary under the elfconv/build/lifter
~/elfconv/build# cp exe.wasm ../examples/browser
~/elfconv/build# cp exe.js ../examples/browser
~/elfconv/build# emrun --no_browser --port 8080 ../examples/browser/exe.html # execute the generated WASM binary with emscripten
------------------------
### Host (WASI Runtimes)
~/elfconv/build# NEW_ROOT=/path/to/elfconv TARGET=aarch64-wasi32 ../scripts/dev.sh path/to/ELF
~/elfconv/build# wasmedge ./exe.wasm # or wasmedge ./exe_o3.wasm
```
## Acknowledgement
elfconv uses or references some projects as follows. Great thanks to its all developers!
- remill ([Apache Lisence 2.0](https://github.com/lifting-bits/remill/blob/master/LICENSE))
    - Original Source: https://github.com/lifting-bits/remill
    - elfconv uses remill in order to convert machine codes to LLVM IR instructions. the source code is contained in [`./backend/remill`](https://github.com/yomaytk/elfconv/tree/main/backend/remill) and is modified for using from front-end and supporting additional instructions.
- Sleigh Library ([Apache Lisence 2.0](https://github.com/lifting-bits/sleigh/blob/master/LICENSE))
    - Original Source: https://github.com/lifting-bits/sleigh
    - sleigh is a language to describe the semantics of instructions, and this library is part of the [Ghidra reverse engineering platform](https://github.com/NationalSecurityAgency/ghidra) and underpins its disassemler and decompilation engines.
- MyAOT ([Apache Lisence 2.0](https://github.com/AkihiroSuda/myaot/blob/master/LICENSE))
    - Original Source: https://github.com/AkihiroSuda/myaot
    - An experimental AOT-ish compiler (Linux/riscv32 ELF → Linux/x86_64 ELF, Mach-O, WASM, ...)
    - We referenced the design of MyAOT for developing elfconv.
