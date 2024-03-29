# How to use release packages
This shows how to use the release packages (e.g. elfconv-v0.1.0-linux-arm64.tar.gz). 
## Quick Start
You can translate the ELF binary to the WASM binary by the following command. `TARGET` should be `wasm-host` for WASI runtimes or `wasm-browser` for browser.
```bash
$ cd <unzipped directory>
$ TARGET=wasm-host ./elfconv.sh /path/to/ELF ./bitcode
```
## Contents
The unzipped directory includes 3 shell scripts (`prepare.sh`, `elfconv.sh`, `clean.sh`) and 3 directories (`bin`, `bitcode`, `lib`).

`elfconv.sh`: for translating the ELF binary to WASM binary.

`prepare.sh`: for prepareing the files and directorie to make the release packages.

`clean.sh`: for removing the generated resources by the `prepare.sh`

`bin/`: includes `elflift` that is statically linked executable file to translate the ELF binary to the LLVM bitcode.

`bitcode/`: includes several LLVM bitcode files that provides the all virtual instruction sets for the translated LLVM IR sets of the original ELF binary.

`lib/`: includes the two archives of *elfconv-runtime*. `libelfconvbrowser.a` is for browser and `libelfconvwasi.a` is for WASI runtimes.
