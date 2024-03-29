# How to use release packages
This shows how to use the release packages (e.g. elfconv-v0.1.0-linux-arm64.tar.gz). 
## Quick Start
You can translate the ELF binary to the WASM binary using `elfconv.sh`. `TARGET` should be `wasm-host` for WASI runtimes or `wasm-browser` for the browser. elfconv generates the WASM using [emscripten](https://github.com/emscripten-core/emscripten) for the browser and [wasi-sdk](https://github.com/WebAssembly/wasi-sdk) for WASI runtimes, so please configure the following settings.
### settings
#### emscripten
`emcc`: compile command of emscripten
#### wasi-sdk
`WASI_SDK_PATH`: path to the parent directory of `bin` of wasi-sdk.
### command
After configuring the above settings, you can try translation by the command as follows.
```bash
$ cd <unzipped directory>
$ TARGET=wasm-host ./elfconv.sh </path/to/ELF> ./bitcode
```
## Contents
The unzipped directory includes 3 shell scripts (`prepare.sh`, `elfconv.sh`, `clean.sh`) and 3 directories (`bin`, `bitcode`, `lib`).

`elfconv.sh`: for translating the ELF binary to WASM binary.

`prepare.sh`: for prepareing the files and directorie to make the release packages.

`clean.sh`: for removing the generated resources by the `prepare.sh`

`bin/`: includes `elflift` that is statically linked executable file to translate the ELF binary to the LLVM bitcode.

`bitcode/`: includes several LLVM bitcode files that provides the all virtual instruction sets for the translated LLVM IR sets of the original ELF binary.

`lib/`: includes the two archives of *elfconv-runtime*. `libelfconvbrowser.a` is for browser and `libelfconvwasi.a` is for WASI runtimes.
