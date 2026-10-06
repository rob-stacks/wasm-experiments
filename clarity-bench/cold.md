| Function | Input | engine | first call (fresh instance) | warm call |
|---|---|---|--:|--:|
| `from-consensus-buff?` | tuple, 5 fields (194 B) | wasmtime (Cranelift) | 94.62 µs | 3.50 µs |
| `from-consensus-buff?` | tuple, 5 fields (194 B) | wasmi | 980.33 µs | 67.46 µs |
| `from-consensus-buff?` | tuple, 5 fields (194 B), no regex | wasmtime (Cranelift) | 3.62 µs | 2.96 µs |
| `from-consensus-buff?` | tuple, 5 fields (194 B), no regex | wasmi | 54.67 µs | 53.12 µs |
