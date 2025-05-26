## Examples for conversion

This directory has some example programs you can try converting the Linux/ELF. You can build the Linux/ELF by using a Makefile included in the every directory.

[`examples-repos`](https://github.com/yomaytk/elfconv/tree/main/examples/examples-repos) has patch or config files that can be used to convert the third-party programs. You can convert those Linux/ELF binaries following the steps below.
### [mnist-neural-network-plain-c](https://github.com/AndrewCarterUK/mnist-neural-network-plain-c)
- This is the neural network training MNIST dataset written by C. After applying patch file [`example-repos/mnist-neural-network-plain-c.patch`](https://github.com/yomaytk/elfconv/tree/main/examples/examples-repos/mnist-neural-network-plain-c.patch) (needed for configuring static linking and so on), you can convert the generated ELF binary.
```bash
$ git clone https://github.com/AndrewCarterUK/mnist-neural-network-plain-c
$ cd mnist-neural-network-plain-c
$ git apply path/to/examples-repos/mnist-neural-network-plain-c.patch
$ make # mnist.aarch64 is generated, and you can convert it.
```
### [busybox](https://github.com/mirror/busybox)
- This is a software suite that provides several Unix utilities in a single executable file. [wiki](https://en.wikipedia.org/wiki/BusyBox)
- We should set some configuration when we build this project. You can use [`examples-repos/.config`](https://github.com/yomaytk/elfconv/tree/main/examples/examples-repos/.config) for configuration.
```bash
$ git clone https://github.com/mirror/busybox
$ cd busybox
$ cp path/to/examples-repos/.config .config
$ make # busybox is generated, and you can convert it.
```
