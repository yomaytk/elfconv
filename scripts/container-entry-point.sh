#!/usr/bin/env bash
# entry directory: /root/elfconv

source ~/.bash_profile

# build elfconv
./scripts/build.sh

# elfconv integration test
cd ~/elfconv/examples/print_hello && make
cd ~/elfconv/examples/eratosthenes_sieve && make
cd ~/elfconv/examples/hello && make
cd ~/elfconv/build && ctest

# bash
exec bash && source ~/.bash_profile
