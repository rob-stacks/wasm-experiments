# clarity-bench

Benchmarks Clarity's **Conversions** and **Hashing & Crypto** built-ins natively and
as pure WebAssembly under wasmtime (Cranelift JIT) and wasmi, with wasmi fuel and per-function
code size. (wasmtime's Pulley interpreter was measured too — 2–3× slower than wasmi on every
case — and has been dropped.)

```
./run.sh            # full run, writes results.md
./run.sh --quick    # shorter samples
./run.sh secp256k1  # only cases whose label contains the filter
WIDE=1 ./run.sh > results-wide.md   # guest built with the wide-arithmetic proposal
./run.sh --fuel     # wasmi fuel per call -> fuel.tsv
./codesize.sh       # per-case guests -> wasm instructions / code bytes -> codesize.tsv
./run.sh --cold from-consensus   # first call in a fresh instance -> cold.md
./make_report.py    # all of the above -> clarity-wasm-bench.{pdf,md} (needs weasyprint)
./wasm_by_crate.py target/codesize/case-14.wasm   # code bytes per Rust crate
```

`results.md` is the default-guest run; `results-wide.md` the `WIDE=1` run (only its wasmi column is
used). The report (`clarity-wasm-bench.{pdf,md}`) has the full notes, including "The regex issue":
`from-consensus-buff?` is 831 KB of wasm because clarity-types validates Clarity names with the `regex`
crate. `consensus::ManualNames` is an equivalent hand-written check (`kernels/tests/names_equiv.rs` proves
equivalence against clarity-types); the `no regex` case benchmarks it next to the chain's version.

## Layout

| Crate / dir | What it is |
|---|---|
| `kernels/` | The built-ins, copied from `clarity/src/vm/functions/{conversions,crypto}.rs` and the `stacks-common` / `clarity-types` helpers they call, with the Clarity VM removed (no `Value` args, eval, costs, VM errors). Same crate versions/features as stacks-core. `cases.rs` has the case ids, input layouts and the benchmark loop. |
| `kernels/src/consensus.rs` | Port of `clarity-types` consensus (SIP-005) serialization for `to/from-consensus-buff?`; `kernels/tests/consensus_equiv.rs` checks it byte-for-byte against the real `clarity-types` (≈125k cases). |
| `guest/` | `kernels` as a `cdylib` for `wasm32-unknown-unknown`: **no imports**, exports `alloc` and `run(case, ptr, len, iters)`. |
| `bench/` | Native host: fixtures, the three engines, measurement, `results.md`. |
| `wat/` | The hand-written `keccak256` and `secp256k1-verify` modules, with an added `bench` loop export. |

## Methodology

- The loop runs **inside** the guest (and inside `kernels::run` natively), so host↔guest call cost is
  not measured; every iteration folds its result into a checksum (`black_box`'d).
- Before timing, every engine must reproduce the native checksum for the case (WAT: the keccak
  checksum must agree across engines; ecdsa must verify).
- Iteration count is calibrated to ≥20 ms, then best of 5 × 100 ms samples is reported.
- Ratios are against the native column (WAT rows: against the native row of the same function).
- Engines use default configs: wasmtime 49.0.2 (`Strategy::Cranelift`), wasmi 2.0.0 (default config,
  lazy translation, no fuel during timing). Built with stable Rust 1.98, `lto = "fat"`.

## Caveats

- **secp256k1 backends.** On this stacks-core branch the chain uses the C library natively and
  pure-Rust `libsecp256k1` in wasm (`stacks-common/src/util/secp256k1/{native,wasm}.rs`). The
  "chain backend" rows reproduce that; the "libsecp256k1 everywhere" rows run the Rust library on
  every target, which isolates the engine cost from the library difference.
- **SHA-2 natively uses the ARMv8 SHA instructions** (`sha2` `asm` feature, as in stacks-common);
  wasm has no equivalent, which inflates the sha256/hash160 ratios.
- No metering (fuel / epoch interruption) is enabled; a Clarity-on-wasm VM would need it.
- The wasm guest's allocator (Rust's default dlmalloc) differs from macOS malloc, which is why a
  few allocation-heavy cases (`to-consensus-buff?`) are not slower — or even faster — in wasm.

## Making the wasm faster (measured, wasmi time vs the default guest)

| Guest build | Effect |
|---|---|
| `WIDE=1` (`+wide-arithmetic`, `curve25519_dalek_bits="64"`) | secp256r1-verify 0.47× (Cranelift 0.37×), ed25519-verify 0.73×, string-to-uint? 0.50×, int-to-ascii 0.68×; everything else unchanged. secp256k1 unchanged: pure-Rust libsecp256k1 always uses 32-bit limbs. Needs an engine with the wide-arithmetic proposal (wasmtime, wasmi; not browsers). |
| `wasm-opt -O3` (Binaryen 132) | secp256k1 ~0.9×, hashes ~1.05× — a wash. |
| `+simd128` | no gain; hash160 32 B 4.8× slower. |
| guest `opt-level = "s"` | worse: geomean 1.2×, up to 3× on small conversions. |
| wasmi dispatch features | already optimal: the default `auto-dispatch` uses tail-call dispatch on aarch64 release builds. |

Not yet tried: compiling the C libsecp256k1 (`secp256k1-sys`) to wasm, which would use its
64-bit field code with `__int128` → `i64.mul_wide_u`. Needs a wasm-capable clang (e.g. Homebrew `llvm`).

## Results

See [`clarity-wasm-bench.md`](clarity-wasm-bench.md) / `clarity-wasm-bench.pdf`.
