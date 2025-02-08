#!/bin/bash
set -e

echo "Compilando AdvancedTokenization fuzz target..."

# Define el compilador y las banderas
export CC=clang
export CFLAGS="-O1 -g"

export OUT=./out
mkdir -p $OUT

$CC $CFLAGS -fsanitize=address,undefined -fsanitize=fuzzer advanced_fuzz_target.c -o $OUT/advanced_fuzz_target


echo "Compilación completada."
