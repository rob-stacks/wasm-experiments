//! Benchmark cases: one id per Clarity built-in (and backend), a byte-level
//! input layout per id, and a loop that runs the built-in `iters` times.
//!
//! The same `run` executes natively and inside the wasm guest. Per-case setup
//! (decoding the input into typed arguments) happens once, outside the loop.
//! Each iteration folds its result into a checksum so the work can't be
//! optimised away and so every engine can be checked to compute the same thing.

use std::hint::black_box;

use crate::consensus::{self, ManualNames};
use crate::conversions::{self, ToAsciiArg};
use crate::crypto::{self, SECP256K1_CHAIN, SECP256K1_RUST};

// Conversions
pub const BUFF_TO_INT_LE: u32 = 0; //          input: buffer (<= 16 bytes)
pub const BUFF_TO_INT_BE: u32 = 1;
pub const BUFF_TO_UINT_LE: u32 = 2;
pub const BUFF_TO_UINT_BE: u32 = 3;
pub const STRING_TO_INT: u32 = 4; //           input: ASCII string
pub const STRING_TO_UINT: u32 = 5;
pub const INT_TO_ASCII: u32 = 6; //            input: i128, 16 bytes LE
pub const INT_TO_UTF8: u32 = 7;
pub const TO_ASCII_UINT: u32 = 8; //           input: u128, 16 bytes LE
pub const TO_ASCII_BUFF: u32 = 9; //           input: buffer
pub const TO_ASCII_STANDARD_PRINCIPAL: u32 = 10; // input: version || hash160
pub const TO_ASCII_CONTRACT_PRINCIPAL: u32 = 11; // input: version || hash160 || name
pub const TO_ASCII_UTF8: u32 = 12; //          input: UTF-8 string
pub const TO_CONSENSUS_BUFF: u32 = 13; //      input: consensus-serialized value
pub const FROM_CONSENSUS_BUFF: u32 = 14; //    input: consensus-serialized value (type = its own type)
/// FROM_CONSENSUS_BUFF validating names without the `regex` crate (same accepted set).
pub const FROM_CONSENSUS_BUFF_NO_REGEX: u32 = 15;

// Hashing & crypto
pub const HASH160: u32 = 20; //                input: data
pub const SHA256: u32 = 21;
pub const SHA512: u32 = 22;
pub const SHA512_256: u32 = 23;
pub const KECCAK256: u32 = 24;
pub const SECP256K1_RECOVER_CHAIN: u32 = 30; //    input: msg32 || sig65
pub const SECP256K1_VERIFY_CHAIN: u32 = 31; //     input: msg32 || sig65 || pubkey33
pub const SECP256K1_DECOMPRESS_CHAIN: u32 = 32; // input: pubkey33
pub const SECP256K1_RECOVER_RUST: u32 = 33;
pub const SECP256K1_VERIFY_RUST: u32 = 34;
pub const SECP256K1_DECOMPRESS_RUST: u32 = 35;
pub const SECP256R1_VERIFY: u32 = 36; //           input: msg32 || sig64 || pubkey33 (Clarity 5+)
pub const SECP256R1_VERIFY_DOUBLE_HASH: u32 = 37; // same, Clarity <= 4 semantics
pub const ED25519_VERIFY: u32 = 38; //             input: pubkey32 || sig64 || message

/// Does nothing: the baseline for per-case code-size measurements.
pub const EMPTY: u32 = 99;
/// Only the TO_CONSENSUS_BUFF setup (deserializing the input into a Value): the
/// code-size baseline for that case, whose setup — unlike the built-in itself —
/// needs the deserializer (and with it the `regex` name validation).
pub const CONSENSUS_SETUP: u32 = 98;

/// Results fold into the checksum through this trait.
trait Fold {
    fn fold(&self, acc: u64) -> u64;
}

fn mix(acc: u64, word: u64) -> u64 {
    (acc ^ word).wrapping_mul(0x100_0000_01b3).rotate_left(17)
}

impl Fold for [u8] {
    fn fold(&self, acc: u64) -> u64 {
        let mut word = [0u8; 8];
        let n = self.len().min(8);
        word[..n].copy_from_slice(&self[..n]);
        mix(acc, u64::from_le_bytes(word) ^ (self.len() as u64) << 56)
    }
}
impl Fold for Vec<u8> {
    fn fold(&self, acc: u64) -> u64 {
        self.as_slice().fold(acc)
    }
}
impl Fold for Vec<Vec<u8>> {
    fn fold(&self, acc: u64) -> u64 {
        let acc = mix(acc, self.len() as u64);
        self.first().map_or(acc, |c| c.fold(acc))
    }
}
impl Fold for bool {
    fn fold(&self, acc: u64) -> u64 {
        mix(acc, *self as u64)
    }
}
impl Fold for i128 {
    fn fold(&self, acc: u64) -> u64 {
        mix(acc, *self as u64 ^ (*self >> 64) as u64)
    }
}
impl Fold for u128 {
    fn fold(&self, acc: u64) -> u64 {
        mix(acc, *self as u64 ^ (*self >> 64) as u64)
    }
}
impl Fold for consensus::Value {
    fn fold(&self, acc: u64) -> u64 {
        mix(acc, 0x5eed)
    }
}
impl<T: Fold> Fold for Option<T> {
    fn fold(&self, acc: u64) -> u64 {
        match self {
            Some(v) => v.fold(mix(acc, 1)),
            None => mix(acc, 2),
        }
    }
}
impl<T: Fold> Fold for Result<T, u32> {
    fn fold(&self, acc: u64) -> u64 {
        match self {
            Ok(v) => v.fold(mix(acc, 3)),
            Err(e) => mix(acc, 4 + *e as u64),
        }
    }
}

fn le16(input: &[u8]) -> [u8; 16] {
    input[..16].try_into().expect("16-byte input")
}

/// Run case `case` on `input` `iters` times and return the result checksum.
///
/// Always inlined, so a caller passing a constant case (the per-case code-size
/// guests) compiles only that case's arm.
#[inline(always)]
pub fn run(case: u32, input: &[u8], iters: u32) -> u64 {
    let mut acc = 0u64;
    macro_rules! bench {
        (|$x:ident| $body:expr) => {{
            for _ in 0..iters {
                let $x = black_box(input);
                let out = $body;
                acc = black_box(&out).fold(acc);
            }
        }};
        ($arg:expr, |$x:ident| $body:expr) => {{
            let arg = $arg;
            for _ in 0..iters {
                let $x = black_box(&arg);
                let out = $body;
                acc = black_box(&out).fold(acc);
            }
        }};
    }

    match case {
        BUFF_TO_INT_LE => bench!(|b| conversions::buff_to_int_le(b)),
        BUFF_TO_INT_BE => bench!(|b| conversions::buff_to_int_be(b)),
        BUFF_TO_UINT_LE => bench!(|b| conversions::buff_to_uint_le(b)),
        BUFF_TO_UINT_BE => bench!(|b| conversions::buff_to_uint_be(b)),
        // The VM hands these functions an owned Value, hence the copy.
        STRING_TO_INT => bench!(|s| conversions::string_to_int(s.to_vec())),
        STRING_TO_UINT => bench!(|s| conversions::string_to_uint(s.to_vec())),
        INT_TO_ASCII => bench!(i128::from_le_bytes(le16(input)), |v| conversions::int_to_ascii(*v)),
        INT_TO_UTF8 => bench!(i128::from_le_bytes(le16(input)), |v| conversions::int_to_utf8(*v)),
        TO_ASCII_UINT => bench!(ToAsciiArg::UInt(u128::from_le_bytes(le16(input))), |v| conversions::to_ascii(v)),
        TO_ASCII_BUFF => bench!(ToAsciiArg::Buffer(input.to_vec()), |v| conversions::to_ascii(v)),
        TO_ASCII_STANDARD_PRINCIPAL => bench!(
            ToAsciiArg::StandardPrincipal(input[0], input[1..21].try_into().unwrap()),
            |v| conversions::to_ascii(v)
        ),
        TO_ASCII_CONTRACT_PRINCIPAL => bench!(
            ToAsciiArg::ContractPrincipal(
                input[0],
                input[1..21].try_into().unwrap(),
                String::from_utf8(input[21..].to_vec()).unwrap()
            ),
            |v| conversions::to_ascii(v)
        ),
        TO_ASCII_UTF8 => bench!(
            ToAsciiArg::Utf8(conversions::string_utf8_from_bytes(input.to_vec()).unwrap()),
            |v| conversions::to_ascii(v)
        ),
        TO_CONSENSUS_BUFF => bench!(
            consensus::deserialize_exact(input, None).expect("valid serialized value"),
            |v| consensus::to_consensus_buff(v)
        ),
        FROM_CONSENSUS_BUFF => bench!(
            {
                let value = consensus::deserialize_exact(input, None).expect("valid serialized value");
                consensus::type_of(&value).expect("typeable value")
            },
            |ty| consensus::from_consensus_buff(black_box(input), ty)
        ),
        FROM_CONSENSUS_BUFF_NO_REGEX => bench!(
            {
                let value = consensus::deserialize_exact_with::<ManualNames>(input, None).expect("valid serialized value");
                consensus::type_of(&value).expect("typeable value")
            },
            |ty| consensus::from_consensus_buff_with::<ManualNames>(black_box(input), ty)
        ),

        HASH160 => bench!(|d| crypto::hash160(d)),
        SHA256 => bench!(|d| crypto::sha256(d)),
        SHA512 => bench!(|d| crypto::sha512(d)),
        SHA512_256 => bench!(|d| crypto::sha512_256(d)),
        KECCAK256 => bench!(|d| crypto::keccak256(d)),

        SECP256K1_RECOVER_CHAIN => bench!(|i| crypto::secp256k1_recover(&SECP256K1_CHAIN, &i[..32], &i[32..97])),
        SECP256K1_VERIFY_CHAIN => bench!(|i| crypto::secp256k1_verify(&SECP256K1_CHAIN, &i[..32], &i[32..97], &i[97..130])),
        SECP256K1_DECOMPRESS_CHAIN => bench!(|i| crypto::secp256k1_decompress(&SECP256K1_CHAIN, i)),
        SECP256K1_RECOVER_RUST => bench!(|i| crypto::secp256k1_recover(&SECP256K1_RUST, &i[..32], &i[32..97])),
        SECP256K1_VERIFY_RUST => bench!(|i| crypto::secp256k1_verify(&SECP256K1_RUST, &i[..32], &i[32..97], &i[97..130])),
        SECP256K1_DECOMPRESS_RUST => bench!(|i| crypto::secp256k1_decompress(&SECP256K1_RUST, i)),
        SECP256R1_VERIFY => bench!(|i| crypto::secp256r1_verify(&i[..32], &i[32..96], &i[96..129], false)),
        SECP256R1_VERIFY_DOUBLE_HASH => bench!(|i| crypto::secp256r1_verify(&i[..32], &i[32..96], &i[96..129], true)),
        ED25519_VERIFY => bench!(|i| crypto::ed25519_verify(&i[96..], &i[32..96], &i[..32])),

        EMPTY => {}
        CONSENSUS_SETUP => {
            black_box(consensus::deserialize_exact(input, None).expect("valid serialized value"));
        }
        _ => panic!("unknown case {case}"),
    }
    acc
}
