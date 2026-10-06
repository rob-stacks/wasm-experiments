# wasm-experiments

Experiments about running [Clarity](https://github.com/stacks-network/stacks-core) built-ins as WebAssembly.

| Directory | What it is |
|---|---|
| [`wat/`](wat/) | Hand-written WebAssembly text: `keccak256.wat` (Keccak-256 / SHA3-256) and `ecdsa.wat` (secp256k1 ECDSA verification, low-S, compressed/uncompressed keys). Node tests check them against OpenSSL and known vectors: `npm install && npm test`. |
| [`clarity-bench/`](clarity-bench/) | Rust benchmark of Clarity's Conversions and Hashing & Crypto built-ins (extracted from `clarity/` + `stacks-common`, minus the VM) natively vs. pure wasm under wasmtime (Cranelift) and wasmi, with wasmi fuel and code size. See its README; results in `clarity-wasm-bench.pdf` / `clarity-wasm-bench.md`. |

`clarity-bench` is a Cargo workspace pinned to Rust 1.98.0 with the `wasm32-unknown-unknown` target
(`rustup target add wasm32-unknown-unknown --toolchain 1.98.0`). The code under test was extracted from
stacks-core commit `778e37a` (branch `marf/g3-db-snapshot` of rob-stacks/stacks-core); the `kernels`
equivalence tests depend on `stacks-common` / `clarity-types` at that commit.
