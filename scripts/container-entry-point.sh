#!/usr/bin/env bash
# entry directory: /root/elfconv

if [ -d "./build" ]; then
  rm -rf ./build
  echo "Delete build for re-build (at scripts/container-entry-point.sh)"
fi

source ~/.bash_profile

# build elfconv
./scripts/build.sh

# elfconv integration test
make -C  ~/elfconv/examples/eratosthenes_sieve
make -C  ~/elfconv/examples/hello
cd ~/elfconv/build
if ctest; then
  echo "Integration Test Passed."
else
  echo "Integration Test failed."
  exit 1
fi
cd ~/elfconv

# bash
exec bash && source ~/.bash_profile