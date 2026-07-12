#!/bin/sh
set -eu
include=$(llvm-config-21 --includedir)
test -r "$include/llvm-c/blake3.h" || { echo "Missing LLVM BLAKE3 header: $include/llvm-c/blake3.h" >&2; exit 1; }
printf '%s\n' "-I$include -L$(llvm-config-21 --libdir) -lLLVM-21"
