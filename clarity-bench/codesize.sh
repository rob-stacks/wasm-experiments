#!/bin/sh
# Build one guest per case (KERNEL_CASE fixes the case at compile time, so only its
# code survives) into target/codesize/case-<id>.wasm, then measure them:
# wasm instructions and code-body bytes per case, minus the EMPTY (99) baseline.
set -e
cd "$(dirname "$0")"
mkdir -p target/codesize
for id in 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 20 21 22 23 24 30 31 32 33 34 35 36 37 38 98 99; do
    KERNEL_CASE=$id CARGO_TARGET_DIR=target/codesize-build \
        cargo build -q --release -p guest --target wasm32-unknown-unknown
    cp target/codesize-build/wasm32-unknown-unknown/release/guest.wasm target/codesize/case-$id.wasm
done
cargo build -q --release -p bench
exec ./target/release/bench --codesize target/codesize "$@"
