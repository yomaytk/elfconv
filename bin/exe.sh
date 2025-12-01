#!/usr/bin/env bash

# $PWD must be 'path/to/elfconv/bin'
ECV_DIR=$( dirname "$PWD" )

source "${ECV_DIR}/scripts/elfconv.sh"

if [ -n "$CLEAN" ]; then
  rm *.bc *.ll *.o *.wasm *.js *.html
fi

main "$@"
