| Function | Input | native | wasmtime (Cranelift) | wasmi |
|---|---|--:|--:|--:|
| **Conversions** | | | | | 
| `buff-to-int-le` | 16-byte buffer | 2.7 ns | 4.9 ns (1.8×) | 49.9 ns (18.2×) |
| `buff-to-int-be` | 16-byte buffer | 2.4 ns | 11.0 ns (4.6×) | 44.7 ns (18.8×) |
| `buff-to-uint-le` | 16-byte buffer | 2.7 ns | 5.1 ns (1.9×) | 49.8 ns (18.2×) |
| `buff-to-uint-be` | 16-byte buffer | 2.4 ns | 10.8 ns (4.5×) | 44.9 ns (18.9×) |
| `string-to-int?` | i128 min (40 chars) | 70.6 ns | 321.4 ns (4.6×) | 2.28 µs (32.4×) |
| `string-to-uint?` | u128 max (39 chars) | 55.6 ns | 59.3 ns (1.1×) | 909.9 ns (16.4×) |
| `int-to-ascii` | i128 min | 37.6 ns | 48.3 ns (1.3×) | 340.8 ns (9.1×) |
| `int-to-utf8` | i128 min | 537.0 ns | 562.7 ns (1.0×) | 3.99 µs (7.4×) |
| `to-ascii?` | uint (u128 max) | 66.8 ns | 75.9 ns (1.1×) | 558.0 ns (8.4×) |
| `to-ascii?` | 32-byte buffer | 93.1 ns | 112.4 ns (1.2×) | 1.04 µs (11.2×) |
| `to-ascii?` | standard principal | 277.0 ns | 432.6 ns (1.6×) | 3.57 µs (12.9×) |
| `to-ascii?` | contract principal | 343.0 ns | 499.4 ns (1.5×) | 4.24 µs (12.4×) |
| `to-ascii?` | utf8 string (56 chars) | 135.1 ns | 134.0 ns (1.0×) | 1.35 µs (10.0×) |
| `to-consensus-buff?` | tuple, 5 fields (194 B) | 219.8 ns | 165.4 ns (0.8×) | 1.32 µs (6.0×) |
| `from-consensus-buff?` | tuple, 5 fields (194 B) | 1.25 µs | 1.72 µs (1.4×) | 31.55 µs (25.2×) |
| `from-consensus-buff?` | tuple, 5 fields (194 B), no regex | 1.12 µs | 1.66 µs (1.5×) | 26.78 µs (23.9×) |
| **Hashing & Crypto** | | | | | 
| `hash160` | 32 B | 187.9 ns | 307.1 ns (1.6×) | 1.68 µs (8.9×) |
| `sha256` | 32 B | 30.0 ns | 149.3 ns (5.0×) | 983.6 ns (32.7×) |
| `sha512` | 32 B | 82.8 ns | 182.4 ns (2.2×) | 1.33 µs (16.1×) |
| `sha512/256` | 32 B | 76.5 ns | 184.5 ns (2.4×) | 1.31 µs (17.2×) |
| `keccak256` | 32 B | 161.4 ns | 245.8 ns (1.5×) | 1.82 µs (11.3×) |
| `hash160` | 1 KiB | 530.7 ns | 2.26 µs (4.3×) | 14.97 µs (28.2×) |
| `sha256` | 1 KiB | 365.3 ns | 2.09 µs (5.7×) | 14.41 µs (39.4×) |
| `sha512` | 1 KiB | 595.8 ns | 1.42 µs (2.4×) | 10.25 µs (17.2×) |
| `sha512/256` | 1 KiB | 593.1 ns | 1.42 µs (2.4×) | 10.20 µs (17.2×) |
| `keccak256` | 1 KiB | 1.17 µs | 1.68 µs (1.4×) | 13.75 µs (11.8×) |
| `hash160` | 64 KiB | 22.30 µs | 121.54 µs (5.4×) | 846.20 µs (37.9×) |
| `sha256` | 64 KiB | 22.16 µs | 120.86 µs (5.5×) | 846.18 µs (38.2×) |
| `sha512` | 64 KiB | 32.86 µs | 77.92 µs (2.4×) | 564.53 µs (17.2×) |
| `sha512/256` | 64 KiB | 32.89 µs | 77.28 µs (2.3×) | 566.13 µs (17.2×) |
| `keccak256` | 64 KiB | 67.30 µs | 97.28 µs (1.4×) | 814.46 µs (12.1×) |
| `secp256k1-recover?` | chain backend | 18.83 µs | 96.54 µs (5.1×) | 769.59 µs (40.9×) |
| `secp256k1-recover?` | libsecp256k1 everywhere | 77.56 µs | 96.28 µs (1.2×) | 758.87 µs (9.8×) |
| `secp256k1-verify` | chain backend | 18.24 µs | 91.23 µs (5.0×) | 748.78 µs (41.1×) |
| `secp256k1-verify` | libsecp256k1 everywhere | 72.86 µs | 91.41 µs (1.3×) | 723.96 µs (9.9×) |
| `secp256k1-decompress?` | chain backend | 2.13 µs | 4.85 µs (2.3×) | 30.70 µs (14.4×) |
| `secp256k1-decompress?` | libsecp256k1 everywhere | 4.26 µs | 4.87 µs (1.1×) | 30.97 µs (7.3×) |
| `secp256r1-verify` | Clarity 5+ (prehashed) | 134.55 µs | 176.63 µs (1.3×) | 2.52 ms (18.8×) |
| `secp256r1-verify` | Clarity ≤ 4 (double SHA-256) | 135.44 µs | 177.15 µs (1.3×) | 2.52 ms (18.6×) |
| `ed25519-verify` | 64-byte message | 23.93 µs | 33.58 µs (1.4×) | 345.23 µs (14.4×) |
| **Hand-written WAT (from the earlier modules)** | | | | | 
| `keccak256` | 32 B | — | 614.8 ns (3.8×) | 6.99 µs (43.3×) |
| `keccak256` | 1 KiB | — | 4.78 µs (4.1×) | 54.59 µs (46.7×) |
| `keccak256` | 64 KiB | — | 285.98 µs (4.2×) | 3.23 ms (48.0×) |
| `secp256k1-verify` | hand-written WAT | — | 553.58 µs (30.4×) | 4.89 ms (268.2×) |
