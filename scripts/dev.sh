#!/usr/bin/env bash

# $PWD must be 'path/to/elfconv/build'
ECV_DIR=$( dirname "$PWD" )

source "${ECV_DIR}/scripts/elfconv.sh"

main "$@"
