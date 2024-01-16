#!/usr/bin/env bash
# entry directory: /root/elfconv

source ~/.bash_profile

# build elfconv
./scripts/build.sh

# elfconv integration test
make -C ~/elfconv/examples/print_hello
make -C  ~/elfconv/examples/eratosthenes_sieve
make -C  ~/elfconv/examples/hello
cd ~/elfconv/build && ctest && cd ~/elfconv

# bash
exec bash && source ~/.bash_profile
