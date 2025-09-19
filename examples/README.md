# Examples for conversion

This directory has some example programs you can try converting the Linux/ELF. You can build the Linux/ELF by using a Makefile included in the every directory.

[`examples-repos`](https://github.com/yomaytk/elfconv/tree/main/examples/examples-repos) has patch or config files that can be used to convert the third-party programs. You can convert those Linux/ELF binaries following the steps below.
## [mnist-neural-network-plain-c](https://github.com/AndrewCarterUK/mnist-neural-network-plain-c)
- This is the neural network training MNIST dataset written by C. After applying patch file [`example-repos/mnist-neural-network-plain-c.patch`](https://github.com/yomaytk/elfconv/tree/main/examples/examples-repos/mnist-neural-network-plain-c.patch) (needed for configuring static linking and so on), you can convert the generated ELF binary.
```bash
$ git clone https://github.com/AndrewCarterUK/mnist-neural-network-plain-c
$ cd mnist-neural-network-plain-c
$ git apply path/to/mnist-neural-network-plain-c.patch
$ make # mnist.aarch64 is generated, and you can convert it.
```
## [busybox](https://github.com/mirror/busybox)
- This is a software suite that provides several Unix utilities in a single executable file. [wiki](https://en.wikipedia.org/wiki/BusyBox)
- We should set some configuration when we build this project. You can use [`examples-repos/.config`](https://github.com/yomaytk/elfconv/tree/main/examples/examples-repos/.config) for configuration.
> [!WARNING]
> When you convert the busybox binary by elfconv, please use `scripts/dev.sh` and add the environment variable `TEST_MODE=1`.

```bash
$ git clone https://github.com/mirror/busybox
$ cd busybox
$ git checkout 1_36_stable # We've confirmed that at least 'v1_36_stable' works.
$ cp path/to/examples-repos/.config .config
$ make # busybox is generated, and you can convert it.
```
### sh-busybox
- We customize BusyBox to add a simple shell program (based on [`lsh`](https://github.com/brenns10/lsh)) that executes BusyBox in the browser, called `sh-busybox`. `sh-busybox` can be converted to a unit Wasm application, and you can try executing some busybox applet commands in the browser.
```bash
# same up to the `cp` command above.
$ git apply path/to/sh-busybox.patch
$ make # busybox is generated, and you can convert it and execute it on the browser.
```
