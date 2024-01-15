#!/usr/bin/env bash
# entry directory: /root/elfconv

source ~/.bash_profile

# build elfconv
./scripts/build.sh

# elfconv integration test
cd build && ctest

# bash
exec bash && source ~/.bash_profile
