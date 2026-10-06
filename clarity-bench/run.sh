#!/bin/sh
# Build the pure-wasm guest and the native host, then run the benchmark.
#   ./run.sh            full run (writes results.md)
#   ./run.sh --quick    shorter samples
#   ./run.sh sha256     only cases whose label contains "sha256"
#   WIDE=1 ./run.sh     guest built with the wide-arithmetic proposal + 64-bit curve25519 limbs
set -e
cd "$(dirname "$0")"
if [ -n "$WIDE" ]; then
    # wide-arithmetic is an unstable rustc target feature (it warns on stable).
    RUSTFLAGS='-C target-feature=+wide-arithmetic --cfg curve25519_dalek_bits="64"' \
        CARGO_TARGET_DIR=target/wide cargo build -q --release -p guest --target wasm32-unknown-unknown 2>/dev/null
    export GUEST_WASM=target/wide/wasm32-unknown-unknown/release/guest.wasm
else
    cargo build -q --release -p guest --target wasm32-unknown-unknown
fi
cargo build -q --release -p bench
exec ./target/release/bench "$@"
