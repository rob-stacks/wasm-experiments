;; Keccak-256 (original Keccak padding, as used by Ethereum / Clarity `keccak256`)
;; in hand-written WebAssembly (MVP features only: no bulk-memory, no SIMD).
;;
;; Exports:
;;   memory                      - 1 page (64 KiB), grow as needed from the host
;;   heap_base : i32 global      - first byte free for host data (1024)
;;   keccak256(ptr, len, out)    - hash memory[ptr..ptr+len], write 32 bytes to out
;;   sha3_256(ptr, len, out)     - same sponge with FIPS-202 padding (0x06)
;;
;; Memory layout:
;;     0 ..  200   state A[25] (i64 lanes, little-endian, A[x + 5y])
;;   200 ..  392   round constants RC[24]
;;   392 ..  416   rho rotation offsets (u8, in pi-chain order)
;;   416 ..  440   pi lane indices (u8, in pi-chain order)
;;   448 ..  584   padding buffer for the final block (rate = 136 bytes)
;;  1024 ..        free for the host
(module
  (memory (export "memory") 1)
  (global (export "heap_base") i32 (i32.const 1024))

  (data (i32.const 200)
    "\01\00\00\00\00\00\00\00\82\80\00\00\00\00\00\00\8a\80\00\00\00\00\00\80\00\80\00\80\00\00\00\80"
    "\8b\80\00\00\00\00\00\00\01\00\00\80\00\00\00\00\81\80\00\80\00\00\00\80\09\80\00\00\00\00\00\80"
    "\8a\00\00\00\00\00\00\00\88\00\00\00\00\00\00\00\09\80\00\80\00\00\00\00\0a\00\00\80\00\00\00\00"
    "\8b\80\00\80\00\00\00\00\8b\00\00\00\00\00\00\80\89\80\00\00\00\00\00\80\03\80\00\00\00\00\00\80"
    "\02\80\00\00\00\00\00\80\80\00\00\00\00\00\00\80\0a\80\00\00\00\00\00\00\0a\00\00\80\00\00\00\80"
    "\81\80\00\80\00\00\00\80\80\80\00\00\00\00\00\80\01\00\00\80\00\00\00\00\08\80\00\80\00\00\00\80")
  (data (i32.const 392)
    "\01\03\06\0a\0f\15\1c\24\2d\37\02\0e\1b\29\38\08\19\2b\3e\12\27\3d\14\2c")
  (data (i32.const 416)
    "\0a\07\0b\11\12\03\05\10\08\15\18\04\0f\17\13\0d\0c\02\14\0e\16\09\06\01")

  ;; XOR of the five lanes in column x.
  (func $column (param $x i32) (result i64)
    (local $p i32)
    (local.set $p (i32.shl (local.get $x) (i32.const 3)))
    (i64.xor
      (i64.xor
        (i64.xor (i64.load offset=0 (local.get $p)) (i64.load offset=40 (local.get $p)))
        (i64.xor (i64.load offset=80 (local.get $p)) (i64.load offset=120 (local.get $p))))
      (i64.load offset=160 (local.get $p))))

  ;; A[x, y] ^= d for every y.
  (func $theta_apply (param $x i32) (param $d i64)
    (local $p i32)
    (local.set $p (i32.shl (local.get $x) (i32.const 3)))
    (i64.store offset=0   (local.get $p) (i64.xor (i64.load offset=0   (local.get $p)) (local.get $d)))
    (i64.store offset=40  (local.get $p) (i64.xor (i64.load offset=40  (local.get $p)) (local.get $d)))
    (i64.store offset=80  (local.get $p) (i64.xor (i64.load offset=80  (local.get $p)) (local.get $d)))
    (i64.store offset=120 (local.get $p) (i64.xor (i64.load offset=120 (local.get $p)) (local.get $d)))
    (i64.store offset=160 (local.get $p) (i64.xor (i64.load offset=160 (local.get $p)) (local.get $d))))

  ;; Keccak-f[1600] on the state at address 0.
  (func $keccak_f
    (local $round i32) (local $i i32) (local $j i32) (local $p i32)
    (local $c0 i64) (local $c1 i64) (local $c2 i64) (local $c3 i64) (local $c4 i64)
    (local $t i64) (local $u i64)
    (loop $rounds
      ;; theta
      (local.set $c0 (call $column (i32.const 0)))
      (local.set $c1 (call $column (i32.const 1)))
      (local.set $c2 (call $column (i32.const 2)))
      (local.set $c3 (call $column (i32.const 3)))
      (local.set $c4 (call $column (i32.const 4)))
      (call $theta_apply (i32.const 0) (i64.xor (local.get $c4) (i64.rotl (local.get $c1) (i64.const 1))))
      (call $theta_apply (i32.const 1) (i64.xor (local.get $c0) (i64.rotl (local.get $c2) (i64.const 1))))
      (call $theta_apply (i32.const 2) (i64.xor (local.get $c1) (i64.rotl (local.get $c3) (i64.const 1))))
      (call $theta_apply (i32.const 3) (i64.xor (local.get $c2) (i64.rotl (local.get $c4) (i64.const 1))))
      (call $theta_apply (i32.const 4) (i64.xor (local.get $c3) (i64.rotl (local.get $c0) (i64.const 1))))

      ;; rho + pi: walk the 24-lane permutation cycle starting at A[1]
      (local.set $t (i64.load (i32.const 8)))
      (local.set $i (i32.const 0))
      (loop $rhopi
        (local.set $j (i32.shl (i32.load8_u offset=416 (local.get $i)) (i32.const 3)))
        (local.set $u (i64.load (local.get $j)))
        (i64.store (local.get $j)
          (i64.rotl (local.get $t) (i64.extend_i32_u (i32.load8_u offset=392 (local.get $i)))))
        (local.set $t (local.get $u))
        (br_if $rhopi (i32.lt_u (local.tee $i (i32.add (local.get $i) (i32.const 1))) (i32.const 24))))

      ;; chi: row by row
      (local.set $p (i32.const 0))
      (loop $chi
        (local.set $c0 (i64.load offset=0  (local.get $p)))
        (local.set $c1 (i64.load offset=8  (local.get $p)))
        (local.set $c2 (i64.load offset=16 (local.get $p)))
        (local.set $c3 (i64.load offset=24 (local.get $p)))
        (local.set $c4 (i64.load offset=32 (local.get $p)))
        (i64.store offset=0  (local.get $p)
          (i64.xor (local.get $c0) (i64.and (i64.xor (local.get $c1) (i64.const -1)) (local.get $c2))))
        (i64.store offset=8  (local.get $p)
          (i64.xor (local.get $c1) (i64.and (i64.xor (local.get $c2) (i64.const -1)) (local.get $c3))))
        (i64.store offset=16 (local.get $p)
          (i64.xor (local.get $c2) (i64.and (i64.xor (local.get $c3) (i64.const -1)) (local.get $c4))))
        (i64.store offset=24 (local.get $p)
          (i64.xor (local.get $c3) (i64.and (i64.xor (local.get $c4) (i64.const -1)) (local.get $c0))))
        (i64.store offset=32 (local.get $p)
          (i64.xor (local.get $c4) (i64.and (i64.xor (local.get $c0) (i64.const -1)) (local.get $c1))))
        (br_if $chi (i32.lt_u (local.tee $p (i32.add (local.get $p) (i32.const 40))) (i32.const 200))))

      ;; iota
      (i64.store (i32.const 0)
        (i64.xor (i64.load (i32.const 0))
                 (i64.load offset=200 (i32.shl (local.get $round) (i32.const 3)))))

      (br_if $rounds (i32.lt_u (local.tee $round (i32.add (local.get $round) (i32.const 1))) (i32.const 24)))))

  ;; XOR one 136-byte block at $src into the first 17 lanes, then permute.
  (func $absorb (param $src i32)
    (local $i i32)
    (loop $lanes
      (i64.store (local.get $i)
        (i64.xor (i64.load (local.get $i))
                 (i64.load (i32.add (local.get $src) (local.get $i)))))
      (br_if $lanes (i32.lt_u (local.tee $i (i32.add (local.get $i) (i32.const 8))) (i32.const 136))))
    (call $keccak_f))

  ;; 256-bit sponge (rate 136, capacity 512) with the given domain/padding byte.
  (func $sponge256 (param $ptr i32) (param $len i32) (param $out i32) (param $pad i32)
    (local $i i32)
    ;; reset state
    (local.set $i (i32.const 0))
    (loop $zero
      (i64.store (local.get $i) (i64.const 0))
      (br_if $zero (i32.lt_u (local.tee $i (i32.add (local.get $i) (i32.const 8))) (i32.const 200))))

    ;; full blocks
    (block $done
      (loop $blocks
        (br_if $done (i32.lt_u (local.get $len) (i32.const 136)))
        (call $absorb (local.get $ptr))
        (local.set $ptr (i32.add (local.get $ptr) (i32.const 136)))
        (local.set $len (i32.sub (local.get $len) (i32.const 136)))
        (br $blocks)))

    ;; final block: zeroed buffer + remaining bytes + padding
    (local.set $i (i32.const 0))
    (loop $clear
      (i64.store offset=448 (local.get $i) (i64.const 0))
      (br_if $clear (i32.lt_u (local.tee $i (i32.add (local.get $i) (i32.const 8))) (i32.const 136))))
    (local.set $i (i32.const 0))
    (block $copied
      (loop $copy
        (br_if $copied (i32.ge_u (local.get $i) (local.get $len)))
        (i32.store8 offset=448 (local.get $i) (i32.load8_u (i32.add (local.get $ptr) (local.get $i))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $copy)))
    (i32.store8 offset=448 (local.get $len) (local.get $pad))
    (i32.store8 (i32.const 583)
      (i32.or (i32.load8_u (i32.const 583)) (i32.const 0x80)))
    (call $absorb (i32.const 448))

    ;; squeeze 32 bytes
    (i64.store offset=0  (local.get $out) (i64.load (i32.const 0)))
    (i64.store offset=8  (local.get $out) (i64.load (i32.const 8)))
    (i64.store offset=16 (local.get $out) (i64.load (i32.const 16)))
    (i64.store offset=24 (local.get $out) (i64.load (i32.const 24))))

  (func (export "keccak256") (param $ptr i32) (param $len i32) (param $out i32)
    (call $sponge256 (local.get $ptr) (local.get $len) (local.get $out) (i32.const 0x01)))

  (func (export "sha3_256") (param $ptr i32) (param $len i32) (param $out i32)
    (call $sponge256 (local.get $ptr) (local.get $len) (local.get $out) (i32.const 0x06)))
)
