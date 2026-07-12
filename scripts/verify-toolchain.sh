#!/bin/sh
set -eu
cxx=$(catalyst introspect _toolchain.compiler.cxx.executable)
version=$("$cxx" --version | head -n 1)
case "$version" in
*21.1.8*) ;;
*) echo "Axon requires Clang 21.1.8; $cxx is: $version" >&2; exit 1 ;;
esac
