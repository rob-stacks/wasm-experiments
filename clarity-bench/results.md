| Function | Input | native | wasmtime (Cranelift) | wasmi |
|---|---|--:|--:|--:|
| **Conversions** | | | | | 
| `buff-to-int-le` | 16-byte buffer | 2.9 ns | 4.8 ns (1.7×) | 49.0 ns (17.1×) |
| `buff-to-int-be` | 16-byte buffer | 2.3 ns | 5.5 ns (2.4×) | 43.8 ns (18.9×) |
| `buff-to-uint-le` | 16-byte buffer | 2.8 ns | 4.4 ns (1.6×) | 49.5 ns (17.6×) |
| `buff-to-uint-be` | 16-byte buffer | 2.3 ns | 5.2 ns (2.2×) | 44.4 ns (19.0×) |
| `string-to-int?` | i128 min (40 chars) | 70.2 ns | 314.8 ns (4.5×) | 2.33 µs (33.1×) |
| `string-to-uint?` | u128 max (39 chars) | 54.7 ns | 189.7 ns (3.5×) | 1.69 µs (30.9×) |
| `int-to-ascii` | i128 min | 37.8 ns | 63.0 ns (1.7×) | 515.9 ns (13.6×) |
| `int-to-utf8` | i128 min | 545.5 ns | 598.0 ns (1.1×) | 4.25 µs (7.8×) |
| `to-ascii?` | uint (u128 max) | 64.7 ns | 94.3 ns (1.5×) | 742.8 ns (11.5×) |
| `to-ascii?` | 32-byte buffer | 93.2 ns | 105.4 ns (1.1×) | 1.05 µs (11.3×) |
| `to-ascii?` | standard principal | 258.1 ns | 433.0 ns (1.7×) | 3.49 µs (13.5×) |
| `to-ascii?` | contract principal | 318.8 ns | 494.2 ns (1.6×) | 3.96 µs (12.4×) |
| `to-ascii?` | utf8 string (56 chars) | 127.9 ns | 132.2 ns (1.0×) | 1.26 µs (9.8×) |
| `to-consensus-buff?` | tuple, 5 fields (194 B) | 210.8 ns | 157.7 ns (0.7×) | 1.28 µs (6.1×) |
| `from-consensus-buff?` | tuple, 5 fields (194 B) | 1.19 µs | 1.71 µs (1.4×) | 29.28 µs (24.6×) |
| `from-consensus-buff?` | tuple, 5 fields (194 B), no regex | 1.12 µs | 1.60 µs (1.4×) | 25.14 µs (22.5×) |
| **Hashing & Crypto** | | | | | 
| `hash160` | 32 B | 174.6 ns | 298.8 ns (1.7×) | 1.65 µs (9.4×) |
| `sha256` | 32 B | 29.8 ns | 144.9 ns (4.9×) | 970.3 ns (32.6×) |
| `sha512` | 32 B | 75.0 ns | 178.1 ns (2.4×) | 1.33 µs (17.7×) |
| `sha512/256` | 32 B | 73.7 ns | 181.1 ns (2.5×) | 1.28 µs (17.3×) |
| `keccak256` | 32 B | 161.0 ns | 245.3 ns (1.5×) | 1.78 µs (11.0×) |
| `hash160` | 1 KiB | 531.1 ns | 2.17 µs (4.1×) | 14.86 µs (28.0×) |
| `sha256` | 1 KiB | 356.1 ns | 2.00 µs (5.6×) | 14.12 µs (39.7×) |
| `sha512` | 1 KiB | 579.9 ns | 1.38 µs (2.4×) | 10.07 µs (17.4×) |
| `sha512/256` | 1 KiB | 579.9 ns | 1.39 µs (2.4×) | 10.10 µs (17.4×) |
| `keccak256` | 1 KiB | 1.16 µs | 1.67 µs (1.4×) | 13.62 µs (11.8×) |
| `hash160` | 64 KiB | 22.30 µs | 119.33 µs (5.4×) | 841.47 µs (37.7×) |
| `sha256` | 64 KiB | 22.15 µs | 118.03 µs (5.3×) | 838.28 µs (37.8×) |
| `sha512` | 64 KiB | 32.89 µs | 76.40 µs (2.3×) | 563.00 µs (17.1×) |
| `sha512/256` | 64 KiB | 32.87 µs | 76.61 µs (2.3×) | 559.53 µs (17.0×) |
| `keccak256` | 64 KiB | 67.11 µs | 97.77 µs (1.5×) | 812.85 µs (12.1×) |
| `secp256k1-recover?` | chain backend | 18.55 µs | 96.42 µs (5.2×) | 775.04 µs (41.8×) |
| `secp256k1-recover?` | libsecp256k1 everywhere | 76.43 µs | 96.14 µs (1.3×) | 759.66 µs (9.9×) |
| `secp256k1-verify` | chain backend | 18.06 µs | 91.14 µs (5.0×) | 734.24 µs (40.7×) |
| `secp256k1-verify` | libsecp256k1 everywhere | 72.19 µs | 91.03 µs (1.3×) | 742.39 µs (10.3×) |
| `secp256k1-decompress?` | chain backend | 2.10 µs | 4.82 µs (2.3×) | 30.50 µs (14.5×) |
| `secp256k1-decompress?` | libsecp256k1 everywhere | 4.23 µs | 4.81 µs (1.1×) | 30.49 µs (7.2×) |
| `secp256r1-verify` | Clarity 5+ (prehashed) | 133.05 µs | 489.49 µs (3.7×) | 5.33 ms (40.0×) |
| `secp256r1-verify` | Clarity ≤ 4 (double SHA-256) | 133.30 µs | 487.49 µs (3.7×) | 5.30 ms (39.8×) |
| `ed25519-verify` | 64-byte message | 23.83 µs | 57.57 µs (2.4×) | 487.56 µs (20.5×) |
| **Hand-written WAT (from the earlier modules)** | | | | | 
| `keccak256` | 32 B | — | 611.5 ns (3.8×) | 6.88 µs (42.7×) |
| `keccak256` | 1 KiB | — | 4.97 µs (4.3×) | 57.17 µs (49.5×) |
| `keccak256` | 64 KiB | — | 284.29 µs (4.2×) | 3.16 ms (47.0×) |
| `secp256k1-verify` | hand-written WAT | — | 553.63 µs (30.7×) | 4.83 ms (267.5×) |
