;; secp256k1 ECDSA signature verification in hand-written WebAssembly
;; (MVP features only: no bulk-memory, no SIMD, no multi-value).
;;
;; Semantics match stacks-common's `Secp256k1PublicKey::verify`: plain ECDSA
;; over a 32-byte message hash, with high-S signatures rejected.
;;
;; Exports:
;;   memory                                    - 1 page (64 KiB)
;;   heap_base : i32 global                    - first byte free for host data (4096)
;;   ecdsa_verify(hash, sig, pub, pub_len) -> i32
;;       hash    : 32-byte big-endian message hash
;;       sig     : 64-byte compact signature r || s (big-endian)
;;       pub     : 33-byte compressed (02/03 || x) or 65-byte uncompressed (04 || x || y)
;;       returns 1 if valid, 0 otherwise (including any malformed input)
;;
;; Numbers are 256-bit, stored as 8 little-endian 32-bit limbs (32 bytes).
;; Field elements are kept in Montgomery form (a * 2^256 mod m) and multiplied
;; with CIOS Montgomery multiplication. Points use Jacobian coordinates
;; (X, Y, Z) -> (X/Z^2, Y/Z^3); Z = 0 is the point at infinity.
;;
;; Memory layout:
;;     0 ..  128   MOD_P: p, R^2 mod p, R mod p (Montgomery 1), -p^-1 mod 2^32
;;   128 ..  256   MOD_N: same for the group order n
;;   256 ..  544   constants (see data segments)
;;   544 ..  584   Montgomery multiplication scratch (10 limbs)
;;  1024 .. 2048   field temporaries
;;  2048 .. 2432   points: G, Q, G+Q (contiguous, indexed by bit pair), accumulator
;;  4096 ..        free for the host
(module
  (memory (export "memory") 1)
  (global (export "heap_base") i32 (i32.const 4096))

  ;; ---- constants ----
  (global $MOD_P      i32 (i32.const 0))
  (global $MOD_N      i32 (i32.const 128))
  (global $P_MINUS_2  i32 (i32.const 256))
  (global $N_MINUS_2  i32 (i32.const 288))
  (global $SQRT_EXP   i32 (i32.const 320))   ;; (p + 1) / 4
  (global $SEVEN_M    i32 (i32.const 352))   ;; 7, Montgomery form mod p
  (global $GX_M       i32 (i32.const 384))   ;; generator, Montgomery form mod p
  (global $GY_M       i32 (i32.const 416))
  (global $ONE        i32 (i32.const 448))   ;; plain 1 (multiplying by it leaves Montgomery form)
  (global $HALF_N     i32 (i32.const 480))   ;; n / 2 (rounded down), the high-S bound
  (global $ZERO       i32 (i32.const 512))   ;; never written
  (global $T          i32 (i32.const 544))

  ;; ---- temporaries ----
  (global $PW_B i32 (i32.const 1024)) (global $PW_R i32 (i32.const 1056))
  (global $FA   i32 (i32.const 1088)) (global $FB   i32 (i32.const 1120))
  (global $FC   i32 (i32.const 1152)) (global $FD   i32 (i32.const 1184))
  (global $FE   i32 (i32.const 1216)) (global $FF   i32 (i32.const 1248))
  (global $X3   i32 (i32.const 1280)) (global $Y3   i32 (i32.const 1312))
  (global $Z3   i32 (i32.const 1344)) (global $Z1Z1 i32 (i32.const 1376))
  (global $Z2Z2 i32 (i32.const 1408)) (global $U1   i32 (i32.const 1440))
  (global $U2   i32 (i32.const 1472)) (global $S1   i32 (i32.const 1504))
  (global $S2   i32 (i32.const 1536)) (global $H    i32 (i32.const 1568))
  (global $RR   i32 (i32.const 1600)) (global $I    i32 (i32.const 1632))
  (global $J    i32 (i32.const 1664)) (global $V    i32 (i32.const 1696))
  (global $TMP  i32 (i32.const 1728)) (global $TMP2 i32 (i32.const 1760))
  (global $SIG_R i32 (i32.const 1792)) (global $SIG_S i32 (i32.const 1824))
  (global $HZ   i32 (i32.const 1856)) (global $W    i32 (i32.const 1888))
  (global $K1   i32 (i32.const 1920)) (global $K2   i32 (i32.const 1952))
  (global $XA   i32 (i32.const 1984)) (global $YN   i32 (i32.const 2016))
  (global $PG   i32 (i32.const 2048))    ;; table[1] = G
  (global $PQ   i32 (i32.const 2144))    ;; table[2] = Q (public key)
  (global $PGQ  i32 (i32.const 2240))    ;; table[3] = G + Q
  (global $ACC  i32 (i32.const 2336))

  ;; MOD_P
  (data (i32.const 0)
    "\2f\fc\ff\ff\fe\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff"
    "\a1\90\0e\00\a2\07\00\00\01\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00"
    "\d1\03\00\00\01\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00"
    "\31\35\25\d2")
  ;; MOD_N
  (data (i32.const 128)
    "\41\41\36\d0\8c\5e\d2\bf\3b\a0\48\af\e6\dc\ae\ba\fe\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff"
    "\40\d1\d7\67\14\f2\6c\89\78\f8\7c\0e\c2\96\14\74\c6\07\cd\5b\e4\f5\97\e6\c5\9b\c6\81\d5\1c\67\9d"
    "\bf\be\c9\2f\73\a1\2d\40\c4\5f\b7\50\19\23\51\45\01\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00"
    "\3f\b1\88\55")
  (data (i32.const 256)
    ;; p - 2
    "\2d\fc\ff\ff\fe\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff"
    ;; n - 2
    "\3f\41\36\d0\8c\5e\d2\bf\3b\a0\48\af\e6\dc\ae\ba\fe\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff"
    ;; (p + 1) / 4
    "\0c\ff\ff\bf\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\3f"
    ;; 7 * R mod p
    "\b7\1a\00\00\07\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00"
    ;; Gx * R mod p
    "\97\20\7e\48\5a\2e\36\d7\db\66\bc\29\53\29\1e\23\9c\12\fd\33\c0\48\9f\97\48\9f\08\e9\43\e6\81\99"
    ;; Gy * R mod p
    "\e2\ab\db\d3\d2\a6\5e\b1\4d\c6\1d\1f\5d\5d\fc\8d\36\c1\19\ac\9a\b5\b6\70\d6\82\a5\d4\1f\85\3f\cf"
    ;; 1
    "\01\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00"
    ;; n / 2
    "\a0\20\1b\68\46\2f\e9\df\1d\50\a4\57\73\6e\57\5d\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\7f")

  ;; =====================================================================
  ;; 256-bit integer helpers
  ;; =====================================================================

  (func $copy (param $dst i32) (param $src i32)
    (i64.store offset=0  (local.get $dst) (i64.load offset=0  (local.get $src)))
    (i64.store offset=8  (local.get $dst) (i64.load offset=8  (local.get $src)))
    (i64.store offset=16 (local.get $dst) (i64.load offset=16 (local.get $src)))
    (i64.store offset=24 (local.get $dst) (i64.load offset=24 (local.get $src))))

  (func $is_zero (param $a i32) (result i32)
    (i64.eqz
      (i64.or
        (i64.or (i64.load offset=0  (local.get $a)) (i64.load offset=8  (local.get $a)))
        (i64.or (i64.load offset=16 (local.get $a)) (i64.load offset=24 (local.get $a))))))

  (func $eq (param $a i32) (param $b i32) (result i32)
    (i32.and
      (i32.and
        (i64.eq (i64.load offset=0  (local.get $a)) (i64.load offset=0  (local.get $b)))
        (i64.eq (i64.load offset=8  (local.get $a)) (i64.load offset=8  (local.get $b))))
      (i32.and
        (i64.eq (i64.load offset=16 (local.get $a)) (i64.load offset=16 (local.get $b)))
        (i64.eq (i64.load offset=24 (local.get $a)) (i64.load offset=24 (local.get $b))))))

  ;; a >= b (unsigned), comparing 64-bit words from the top.
  (func $geq (param $a i32) (param $b i32) (result i32)
    (local $i i32) (local $x i64) (local $y i64)
    (local.set $i (i32.const 24))
    (loop $words
      (local.set $x (i64.load (i32.add (local.get $a) (local.get $i))))
      (local.set $y (i64.load (i32.add (local.get $b) (local.get $i))))
      (if (i64.ne (local.get $x) (local.get $y))
        (then (return (i64.gt_u (local.get $x) (local.get $y)))))
      (br_if $words (i32.ge_s (local.tee $i (i32.sub (local.get $i) (i32.const 8))) (i32.const 0))))
    (i32.const 1))

  ;; out = a + b, returns the carry out.
  (func $add_raw (param $out i32) (param $a i32) (param $b i32) (result i32)
    (local $i i32) (local $c i64)
    (loop $limbs
      (local.set $c
        (i64.add (local.get $c)
          (i64.add (i64.load32_u (i32.add (local.get $a) (local.get $i)))
                   (i64.load32_u (i32.add (local.get $b) (local.get $i))))))
      (i64.store32 (i32.add (local.get $out) (local.get $i)) (local.get $c))
      (local.set $c (i64.shr_u (local.get $c) (i64.const 32)))
      (br_if $limbs (i32.lt_u (local.tee $i (i32.add (local.get $i) (i32.const 4))) (i32.const 32))))
    (i32.wrap_i64 (local.get $c)))

  ;; out = a - b, returns the borrow out.
  (func $sub_raw (param $out i32) (param $a i32) (param $b i32) (result i32)
    (local $i i32) (local $d i64) (local $borrow i64)
    (loop $limbs
      (local.set $d
        (i64.sub
          (i64.sub (i64.load32_u (i32.add (local.get $a) (local.get $i)))
                   (i64.load32_u (i32.add (local.get $b) (local.get $i))))
          (local.get $borrow)))
      (i64.store32 (i32.add (local.get $out) (local.get $i)) (local.get $d))
      (local.set $borrow (i64.shr_u (local.get $d) (i64.const 63)))
      (br_if $limbs (i32.lt_u (local.tee $i (i32.add (local.get $i) (i32.const 4))) (i32.const 32))))
    (i32.wrap_i64 (local.get $borrow)))

  ;; Load a 32-byte big-endian number into limb form.
  (func $load_be (param $dst i32) (param $src i32)
    (local $i i32) (local $q i32)
    (loop $limbs
      (local.set $q (i32.sub (i32.add (local.get $src) (i32.const 28)) (local.get $i)))
      (i32.store (i32.add (local.get $dst) (local.get $i))
        (i32.or
          (i32.or (i32.shl (i32.load8_u offset=0 (local.get $q)) (i32.const 24))
                  (i32.shl (i32.load8_u offset=1 (local.get $q)) (i32.const 16)))
          (i32.or (i32.shl (i32.load8_u offset=2 (local.get $q)) (i32.const 8))
                  (i32.load8_u offset=3 (local.get $q)))))
      (br_if $limbs (i32.lt_u (local.tee $i (i32.add (local.get $i) (i32.const 4))) (i32.const 32)))))

  ;; Bit i (0 = least significant) of a 256-bit number.
  (func $bit (param $k i32) (param $i i32) (result i32)
    (i32.and
      (i32.shr_u
        (i32.load (i32.add (local.get $k) (i32.shl (i32.shr_u (local.get $i) (i32.const 5)) (i32.const 2))))
        (local.get $i))
      (i32.const 1)))

  ;; =====================================================================
  ;; Modular arithmetic, generic over a modulus descriptor $m (MOD_P / MOD_N)
  ;; =====================================================================

  (func $add_mod (param $out i32) (param $a i32) (param $b i32) (param $m i32)
    (if (i32.or (call $add_raw (local.get $out) (local.get $a) (local.get $b))
                (call $geq (local.get $out) (local.get $m)))
      (then (drop (call $sub_raw (local.get $out) (local.get $out) (local.get $m))))))

  (func $sub_mod (param $out i32) (param $a i32) (param $b i32) (param $m i32)
    (if (call $sub_raw (local.get $out) (local.get $a) (local.get $b))
      (then (drop (call $add_raw (local.get $out) (local.get $out) (local.get $m))))))

  ;; out = a * b * R^-1 mod m (CIOS Montgomery multiplication).
  ;; out may alias a or b: the result is built in $T and copied at the end.
  (func $mul (param $out i32) (param $a i32) (param $b i32) (param $m i32)
    (local $i i32) (local $j i32) (local $t i32)
    (local $bi i64) (local $q i64) (local $c i64) (local $x i64)
    (local.set $t (global.get $T))
    (i64.store offset=0  (local.get $t) (i64.const 0))
    (i64.store offset=8  (local.get $t) (i64.const 0))
    (i64.store offset=16 (local.get $t) (i64.const 0))
    (i64.store offset=24 (local.get $t) (i64.const 0))
    (i64.store offset=32 (local.get $t) (i64.const 0))
    (loop $outer
      ;; T += a * b[i]
      (local.set $bi (i64.load32_u (i32.add (local.get $b) (local.get $i))))
      (local.set $c (i64.const 0))
      (local.set $j (i32.const 0))
      (loop $mul_limbs
        (local.set $x
          (i64.add
            (i64.add (i64.load32_u (i32.add (local.get $t) (local.get $j))) (local.get $c))
            (i64.mul (i64.load32_u (i32.add (local.get $a) (local.get $j))) (local.get $bi))))
        (i64.store32 (i32.add (local.get $t) (local.get $j)) (local.get $x))
        (local.set $c (i64.shr_u (local.get $x) (i64.const 32)))
        (br_if $mul_limbs (i32.lt_u (local.tee $j (i32.add (local.get $j) (i32.const 4))) (i32.const 32))))
      (local.set $x (i64.add (i64.load32_u offset=32 (local.get $t)) (local.get $c)))
      (i64.store32 offset=32 (local.get $t) (local.get $x))
      (i64.store32 offset=36 (local.get $t) (i64.shr_u (local.get $x) (i64.const 32)))

      ;; T = (T + q * m) / 2^32, with q chosen so the low limb cancels
      (local.set $q
        (i64.and
          (i64.mul (i64.load32_u (local.get $t)) (i64.load32_u offset=96 (local.get $m)))
          (i64.const 0xffffffff)))
      (local.set $c
        (i64.shr_u
          (i64.add (i64.load32_u (local.get $t))
                   (i64.mul (local.get $q) (i64.load32_u (local.get $m))))
          (i64.const 32)))
      (local.set $j (i32.const 4))
      (loop $reduce_limbs
        (local.set $x
          (i64.add
            (i64.add (i64.load32_u (i32.add (local.get $t) (local.get $j))) (local.get $c))
            (i64.mul (local.get $q) (i64.load32_u (i32.add (local.get $m) (local.get $j))))))
        (i64.store32 (i32.sub (i32.add (local.get $t) (local.get $j)) (i32.const 4)) (local.get $x))
        (local.set $c (i64.shr_u (local.get $x) (i64.const 32)))
        (br_if $reduce_limbs (i32.lt_u (local.tee $j (i32.add (local.get $j) (i32.const 4))) (i32.const 32))))
      (local.set $x (i64.add (i64.load32_u offset=32 (local.get $t)) (local.get $c)))
      (i64.store32 offset=28 (local.get $t) (local.get $x))
      (i64.store32 offset=32 (local.get $t)
        (i64.add (i64.load32_u offset=36 (local.get $t)) (i64.shr_u (local.get $x) (i64.const 32))))

      (br_if $outer (i32.lt_u (local.tee $i (i32.add (local.get $i) (i32.const 4))) (i32.const 32))))

    ;; T < 2m here; one conditional subtraction makes it canonical
    (if (i32.or (i32.load offset=32 (local.get $t)) (call $geq (local.get $t) (local.get $m)))
      (then (drop (call $sub_raw (local.get $out) (local.get $t) (local.get $m))))
      (else (call $copy (local.get $out) (local.get $t)))))

  ;; out = base^e mod m (base and out in Montgomery form, e a plain 256-bit number).
  ;; Square-and-multiply over public exponents only.
  (func $pow (param $out i32) (param $base i32) (param $e i32) (param $m i32)
    (local $i i32)
    (call $copy (global.get $PW_B) (local.get $base))
    (call $copy (global.get $PW_R) (i32.add (local.get $m) (i32.const 64)))
    (local.set $i (i32.const 255))
    (loop $bits
      (call $mul (global.get $PW_R) (global.get $PW_R) (global.get $PW_R) (local.get $m))
      (if (call $bit (local.get $e) (local.get $i))
        (then (call $mul (global.get $PW_R) (global.get $PW_R) (global.get $PW_B) (local.get $m))))
      (br_if $bits (i32.ge_s (local.tee $i (i32.sub (local.get $i) (i32.const 1))) (i32.const 0))))
    (call $copy (local.get $out) (global.get $PW_R)))

  ;; Field shorthands (mod p)
  (func $fmul (param $o i32) (param $a i32) (param $b i32)
    (call $mul (local.get $o) (local.get $a) (local.get $b) (global.get $MOD_P)))
  (func $fsqr (param $o i32) (param $a i32)
    (call $mul (local.get $o) (local.get $a) (local.get $a) (global.get $MOD_P)))
  (func $fadd (param $o i32) (param $a i32) (param $b i32)
    (call $add_mod (local.get $o) (local.get $a) (local.get $b) (global.get $MOD_P)))
  (func $fsub (param $o i32) (param $a i32) (param $b i32)
    (call $sub_mod (local.get $o) (local.get $a) (local.get $b) (global.get $MOD_P)))

  ;; =====================================================================
  ;; Jacobian point arithmetic on y^2 = x^3 + 7
  ;; A point is 96 bytes: X at +0, Y at +32, Z at +64.
  ;; =====================================================================

  (func $pcopy (param $dst i32) (param $src i32)
    (call $copy (local.get $dst) (local.get $src))
    (call $copy (i32.add (local.get $dst) (i32.const 32)) (i32.add (local.get $src) (i32.const 32)))
    (call $copy (i32.add (local.get $dst) (i32.const 64)) (i32.add (local.get $src) (i32.const 64))))

  (func $pstore (param $dst i32)
    (call $copy (local.get $dst) (global.get $X3))
    (call $copy (i32.add (local.get $dst) (i32.const 32)) (global.get $Y3))
    (call $copy (i32.add (local.get $dst) (i32.const 64)) (global.get $Z3)))

  ;; out = 2 * p   (dbl-2009-l; out may alias p; infinity stays infinity)
  (func $pdbl (param $out i32) (param $p i32)
    (local $x i32) (local $y i32) (local $z i32)
    (local.set $x (local.get $p))
    (local.set $y (i32.add (local.get $p) (i32.const 32)))
    (local.set $z (i32.add (local.get $p) (i32.const 64)))
    (call $fsqr (global.get $FA) (local.get $x))                       ;; A = X^2
    (call $fsqr (global.get $FB) (local.get $y))                       ;; B = Y^2
    (call $fsqr (global.get $FC) (global.get $FB))                     ;; C = B^2
    (call $fadd (global.get $FD) (local.get $x) (global.get $FB))      ;; D = 2((X+B)^2 - A - C)
    (call $fsqr (global.get $FD) (global.get $FD))
    (call $fsub (global.get $FD) (global.get $FD) (global.get $FA))
    (call $fsub (global.get $FD) (global.get $FD) (global.get $FC))
    (call $fadd (global.get $FD) (global.get $FD) (global.get $FD))
    (call $fadd (global.get $FE) (global.get $FA) (global.get $FA))    ;; E = 3A
    (call $fadd (global.get $FE) (global.get $FE) (global.get $FA))
    (call $fsqr (global.get $FF) (global.get $FE))                     ;; F = E^2
    (call $fsub (global.get $X3) (global.get $FF) (global.get $FD))    ;; X3 = F - 2D
    (call $fsub (global.get $X3) (global.get $X3) (global.get $FD))
    (call $fadd (global.get $FC) (global.get $FC) (global.get $FC))    ;; C = 8C
    (call $fadd (global.get $FC) (global.get $FC) (global.get $FC))
    (call $fadd (global.get $FC) (global.get $FC) (global.get $FC))
    (call $fsub (global.get $Y3) (global.get $FD) (global.get $X3))    ;; Y3 = E(D - X3) - 8C
    (call $fmul (global.get $Y3) (global.get $Y3) (global.get $FE))
    (call $fsub (global.get $Y3) (global.get $Y3) (global.get $FC))
    (call $fmul (global.get $Z3) (local.get $y) (local.get $z))        ;; Z3 = 2YZ
    (call $fadd (global.get $Z3) (global.get $Z3) (global.get $Z3))
    (call $pstore (local.get $out)))

  ;; out = p + q   (add-2007-bl, with the infinity / equal-point cases; out may alias p or q)
  (func $padd (param $out i32) (param $p i32) (param $q i32)
    (local $x1 i32) (local $y1 i32) (local $z1 i32)
    (local $x2 i32) (local $y2 i32) (local $z2 i32)
    (local.set $x1 (local.get $p))
    (local.set $y1 (i32.add (local.get $p) (i32.const 32)))
    (local.set $z1 (i32.add (local.get $p) (i32.const 64)))
    (local.set $x2 (local.get $q))
    (local.set $y2 (i32.add (local.get $q) (i32.const 32)))
    (local.set $z2 (i32.add (local.get $q) (i32.const 64)))
    (if (call $is_zero (local.get $z1))
      (then (call $pcopy (local.get $out) (local.get $q)) (return)))
    (if (call $is_zero (local.get $z2))
      (then (call $pcopy (local.get $out) (local.get $p)) (return)))
    (call $fsqr (global.get $Z1Z1) (local.get $z1))                    ;; Z1Z1 = Z1^2
    (call $fsqr (global.get $Z2Z2) (local.get $z2))                    ;; Z2Z2 = Z2^2
    (call $fmul (global.get $U1) (local.get $x1) (global.get $Z2Z2))   ;; U1 = X1 Z2Z2
    (call $fmul (global.get $U2) (local.get $x2) (global.get $Z1Z1))   ;; U2 = X2 Z1Z1
    (call $fmul (global.get $S1) (local.get $y1) (local.get $z2))      ;; S1 = Y1 Z2 Z2Z2
    (call $fmul (global.get $S1) (global.get $S1) (global.get $Z2Z2))
    (call $fmul (global.get $S2) (local.get $y2) (local.get $z1))      ;; S2 = Y2 Z1 Z1Z1
    (call $fmul (global.get $S2) (global.get $S2) (global.get $Z1Z1))
    (call $fsub (global.get $H) (global.get $U2) (global.get $U1))     ;; H = U2 - U1
    (call $fsub (global.get $RR) (global.get $S2) (global.get $S1))    ;; r = S2 - S1
    (if (call $is_zero (global.get $H))
      (then
        (if (call $is_zero (global.get $RR))
          (then (call $pdbl (local.get $out) (local.get $p)))              ;; p == q
          (else (call $copy (i32.add (local.get $out) (i32.const 64)) (global.get $ZERO))))  ;; p == -q
        (return)))
    (call $fadd (global.get $RR) (global.get $RR) (global.get $RR))    ;; r = 2(S2 - S1)
    (call $fadd (global.get $I) (global.get $H) (global.get $H))       ;; I = (2H)^2
    (call $fsqr (global.get $I) (global.get $I))
    (call $fmul (global.get $J) (global.get $H) (global.get $I))       ;; J = H I
    (call $fmul (global.get $V) (global.get $U1) (global.get $I))      ;; V = U1 I
    (call $fsqr (global.get $X3) (global.get $RR))                     ;; X3 = r^2 - J - 2V
    (call $fsub (global.get $X3) (global.get $X3) (global.get $J))
    (call $fsub (global.get $X3) (global.get $X3) (global.get $V))
    (call $fsub (global.get $X3) (global.get $X3) (global.get $V))
    (call $fmul (global.get $S1) (global.get $S1) (global.get $J))     ;; Y3 = r(V - X3) - 2 S1 J
    (call $fadd (global.get $S1) (global.get $S1) (global.get $S1))
    (call $fsub (global.get $Y3) (global.get $V) (global.get $X3))
    (call $fmul (global.get $Y3) (global.get $Y3) (global.get $RR))
    (call $fsub (global.get $Y3) (global.get $Y3) (global.get $S1))
    (call $fadd (global.get $Z3) (local.get $z1) (local.get $z2))      ;; Z3 = ((Z1+Z2)^2 - Z1Z1 - Z2Z2) H
    (call $fsqr (global.get $Z3) (global.get $Z3))
    (call $fsub (global.get $Z3) (global.get $Z3) (global.get $Z1Z1))
    (call $fsub (global.get $Z3) (global.get $Z3) (global.get $Z2Z2))
    (call $fmul (global.get $Z3) (global.get $Z3) (global.get $H))
    (call $pstore (local.get $out)))

  ;; =====================================================================
  ;; ECDSA
  ;; =====================================================================

  ;; Parse a SEC1 public key into point Q, checking it lies on the curve.
  (func $decode_pubkey (param $pub i32) (param $len i32) (result i32)
    (local $prefix i32) (local $qy i32)
    (local.set $prefix (i32.load8_u (local.get $pub)))
    (local.set $qy (i32.add (global.get $PQ) (i32.const 32)))
    (if (i32.eqz
          (i32.or
            (i32.and (i32.eq (local.get $len) (i32.const 65)) (i32.eq (local.get $prefix) (i32.const 4)))
            (i32.and (i32.eq (local.get $len) (i32.const 33))
                     (i32.eq (i32.or (local.get $prefix) (i32.const 1)) (i32.const 3)))))
      (then (return (i32.const 0))))

    ;; x (must be < p), to Montgomery form
    (call $load_be (global.get $PQ) (i32.add (local.get $pub) (i32.const 1)))
    (if (call $geq (global.get $PQ) (global.get $MOD_P)) (then (return (i32.const 0))))
    (call $fmul (global.get $PQ) (global.get $PQ) (i32.add (global.get $MOD_P) (i32.const 32)))

    ;; TMP = x^3 + 7
    (call $fsqr (global.get $TMP) (global.get $PQ))
    (call $fmul (global.get $TMP) (global.get $TMP) (global.get $PQ))
    (call $fadd (global.get $TMP) (global.get $TMP) (global.get $SEVEN_M))

    (if (i32.eq (local.get $prefix) (i32.const 4))
      (then
        (call $load_be (local.get $qy) (i32.add (local.get $pub) (i32.const 33)))
        (if (call $geq (local.get $qy) (global.get $MOD_P)) (then (return (i32.const 0))))
        (call $fmul (local.get $qy) (local.get $qy) (i32.add (global.get $MOD_P) (i32.const 32))))
      (else
        ;; p = 3 mod 4, so a square root is TMP^((p+1)/4); pick the one with the right parity
        (call $pow (local.get $qy) (global.get $TMP) (global.get $SQRT_EXP) (global.get $MOD_P))
        (call $fmul (global.get $YN) (local.get $qy) (global.get $ONE))
        (if (i32.ne (i32.and (i32.load (global.get $YN)) (i32.const 1))
                    (i32.and (local.get $prefix) (i32.const 1)))
          (then (call $fsub (local.get $qy) (global.get $ZERO) (local.get $qy))))))

    ;; y^2 == x^3 + 7 (also rejects compressed x with no square root)
    (call $fsqr (global.get $TMP2) (local.get $qy))
    (if (i32.eqz (call $eq (global.get $TMP2) (global.get $TMP))) (then (return (i32.const 0))))
    (call $copy (i32.add (global.get $PQ) (i32.const 64)) (i32.add (global.get $MOD_P) (i32.const 64)))
    (i32.const 1))

  (func (export "ecdsa_verify")
    (param $hash i32) (param $sig i32) (param $pub i32) (param $pub_len i32) (result i32)
    (local $i i32) (local $sel i32)

    ;; r in [1, n), s in [1, n/2]
    (call $load_be (global.get $SIG_R) (local.get $sig))
    (call $load_be (global.get $SIG_S) (i32.add (local.get $sig) (i32.const 32)))
    (if (i32.or (call $is_zero (global.get $SIG_R)) (call $geq (global.get $SIG_R) (global.get $MOD_N)))
      (then (return (i32.const 0))))
    (if (i32.or (call $is_zero (global.get $SIG_S))
                (i32.eqz (call $geq (global.get $HALF_N) (global.get $SIG_S))))
      (then (return (i32.const 0))))

    ;; z = hash mod n (hash < 2^256 < 2n, so one subtraction is enough)
    (call $load_be (global.get $HZ) (local.get $hash))
    (if (call $geq (global.get $HZ) (global.get $MOD_N))
      (then (drop (call $sub_raw (global.get $HZ) (global.get $HZ) (global.get $MOD_N)))))

    (if (i32.eqz (call $decode_pubkey (local.get $pub) (local.get $pub_len)))
      (then (return (i32.const 0))))

    ;; w = s^-1 mod n (Montgomery form). Multiplying a plain number by a
    ;; Montgomery-form one gives a plain result: u1 = z w, u2 = r w.
    (call $mul (global.get $W) (global.get $SIG_S) (i32.add (global.get $MOD_N) (i32.const 32)) (global.get $MOD_N))
    (call $pow (global.get $W) (global.get $W) (global.get $N_MINUS_2) (global.get $MOD_N))
    (call $mul (global.get $K1) (global.get $HZ) (global.get $W) (global.get $MOD_N))
    (call $mul (global.get $K2) (global.get $SIG_R) (global.get $W) (global.get $MOD_N))

    ;; table: G, Q, G + Q
    (call $copy (global.get $PG) (global.get $GX_M))
    (call $copy (i32.add (global.get $PG) (i32.const 32)) (global.get $GY_M))
    (call $copy (i32.add (global.get $PG) (i32.const 64)) (i32.add (global.get $MOD_P) (i32.const 64)))
    (call $padd (global.get $PGQ) (global.get $PG) (global.get $PQ))

    ;; ACC = u1 G + u2 Q (Shamir's trick: one shared double-and-add pass)
    (call $copy (i32.add (global.get $ACC) (i32.const 64)) (global.get $ZERO))
    (local.set $i (i32.const 255))
    (loop $bits
      (call $pdbl (global.get $ACC) (global.get $ACC))
      (local.set $sel
        (i32.or (call $bit (global.get $K1) (local.get $i))
                (i32.shl (call $bit (global.get $K2) (local.get $i)) (i32.const 1))))
      (if (local.get $sel)
        (then
          (call $padd (global.get $ACC) (global.get $ACC)
            (i32.add (global.get $PG) (i32.mul (i32.sub (local.get $sel) (i32.const 1)) (i32.const 96))))))
      (br_if $bits (i32.ge_s (local.tee $i (i32.sub (local.get $i) (i32.const 1))) (i32.const 0))))

    (if (call $is_zero (i32.add (global.get $ACC) (i32.const 64)))
      (then (return (i32.const 0))))

    ;; affine x = X / Z^2, out of Montgomery form, reduced mod n; compare with r
    (call $pow (global.get $TMP) (i32.add (global.get $ACC) (i32.const 64)) (global.get $P_MINUS_2) (global.get $MOD_P))
    (call $fsqr (global.get $TMP) (global.get $TMP))
    (call $fmul (global.get $XA) (global.get $ACC) (global.get $TMP))
    (call $fmul (global.get $XA) (global.get $XA) (global.get $ONE))
    (if (call $geq (global.get $XA) (global.get $MOD_N))
      (then (drop (call $sub_raw (global.get $XA) (global.get $XA) (global.get $MOD_N)))))
    (call $eq (global.get $XA) (global.get $SIG_R)))
)
