//! Benchmark inputs. Signatures are produced deterministically from fixed keys.

use anyhow::{anyhow, bail, Result};
use kernels::cases::*;
use kernels::{conversions, crypto};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy)]
pub enum Code {
    /// A `kernels::cases` id, run natively and in the Rust guest.
    Kernel(u32),
    /// The hand-written WAT modules (wasm engines only).
    KeccakWat,
    EcdsaWat,
}

pub struct Case {
    pub group: &'static str,
    pub function: &'static str,
    pub input_desc: String,
    pub code: Code,
    pub input: Vec<u8>,
    /// For WAT cases: label of the kernel case whose native time is the baseline.
    pub baseline: Option<String>,
    /// Sanity check of the fixture against the native kernels.
    expect: Option<fn(&[u8]) -> bool>,
}

impl Case {
    pub fn label(&self) -> String {
        format!("{} [{}]", self.function, self.input_desc)
    }
}

fn case(group: &'static str, function: &'static str, input_desc: impl Into<String>, id: u32, input: Vec<u8>, expect: fn(&[u8]) -> bool) -> Case {
    Case { group, function, input_desc: input_desc.into(), code: Code::Kernel(id), input, baseline: None, expect: Some(expect) }
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

const CONV: &str = "Conversions";
const HASH: &str = "Hashing & Crypto";
const WAT: &str = "Hand-written WAT (from the earlier modules)";

pub fn cases() -> Result<Vec<Case>> {
    let mut v = vec![];

    // ---- Conversions --------------------------------------------------------
    let buff16: Vec<u8> = (1..=16).collect();
    v.push(case(CONV, "buff-to-int-le", "16-byte buffer", BUFF_TO_INT_LE, buff16.clone(), |i| conversions::buff_to_int_le(i).is_some()));
    v.push(case(CONV, "buff-to-int-be", "16-byte buffer", BUFF_TO_INT_BE, buff16.clone(), |i| conversions::buff_to_int_be(i).is_some()));
    v.push(case(CONV, "buff-to-uint-le", "16-byte buffer", BUFF_TO_UINT_LE, buff16.clone(), |i| conversions::buff_to_uint_le(i).is_some()));
    v.push(case(CONV, "buff-to-uint-be", "16-byte buffer", BUFF_TO_UINT_BE, buff16, |i| conversions::buff_to_uint_be(i).is_some()));
    v.push(case(CONV, "string-to-int?", "i128 min (40 chars)", STRING_TO_INT, i128::MIN.to_string().into_bytes(),
        |i| conversions::string_to_int(i.to_vec()) == Some(i128::MIN)));
    v.push(case(CONV, "string-to-uint?", "u128 max (39 chars)", STRING_TO_UINT, u128::MAX.to_string().into_bytes(),
        |i| conversions::string_to_uint(i.to_vec()) == Some(u128::MAX)));
    v.push(case(CONV, "int-to-ascii", "i128 min", INT_TO_ASCII, i128::MIN.to_le_bytes().to_vec(),
        |_| conversions::int_to_ascii(i128::MIN).is_some()));
    v.push(case(CONV, "int-to-utf8", "i128 min", INT_TO_UTF8, i128::MIN.to_le_bytes().to_vec(),
        |_| conversions::int_to_utf8(i128::MIN).is_some_and(|s| s.len() == 40)));
    v.push(case(CONV, "to-ascii?", "uint (u128 max)", TO_ASCII_UINT, u128::MAX.to_le_bytes().to_vec(), |_| true));
    v.push(case(CONV, "to-ascii?", "32-byte buffer", TO_ASCII_BUFF, (0..32).collect(), |_| true));
    let hash160: Vec<u8> = (100..120).collect();
    v.push(case(CONV, "to-ascii?", "standard principal", TO_ASCII_STANDARD_PRINCIPAL, cat(&[&[22], &hash160]),
        |i| conversions::to_ascii(&conversions::ToAsciiArg::StandardPrincipal(i[0], i[1..21].try_into().unwrap()))
            .is_ok_and(|s| s.starts_with(b"SP"))));
    v.push(case(CONV, "to-ascii?", "contract principal", TO_ASCII_CONTRACT_PRINCIPAL, cat(&[&[22], &hash160, b"sip-010-token"]), |_| true));
    let utf8 = "Clarity smart contracts on Bitcoin, decidable by design.";
    v.push(case(CONV, "to-ascii?", format!("utf8 string ({} chars)", utf8.len()), TO_ASCII_UTF8, utf8.as_bytes().to_vec(), |_| true));
    if let Some(serialized) = crate::fixtures::consensus_fixture() {
        let desc = format!("tuple, 5 fields ({} B)", serialized.len());
        let desc = desc.as_str();
        v.push(case(CONV, "to-consensus-buff?", desc, TO_CONSENSUS_BUFF, serialized.clone(), |i| {
            let v = kernels::consensus::deserialize_exact(i, None).unwrap();
            kernels::consensus::to_consensus_buff(&v).as_deref() == Some(i)
        }));
        let serialized_no_regex = serialized.clone();
        v.push(case(CONV, "from-consensus-buff?", desc, FROM_CONSENSUS_BUFF, serialized, |i| {
            let v = kernels::consensus::deserialize_exact(i, None).unwrap();
            let ty = kernels::consensus::type_of(&v).unwrap();
            kernels::consensus::from_consensus_buff(i, &ty).is_some()
        }));
        let desc_no_regex = format!("{desc}, no regex");
        v.push(case(CONV, "from-consensus-buff?", desc_no_regex, FROM_CONSENSUS_BUFF_NO_REGEX, serialized_no_regex, |i| {
            use kernels::consensus::{deserialize_exact_with, from_consensus_buff_with, type_of, ManualNames};
            let v = deserialize_exact_with::<ManualNames>(i, None).unwrap();
            let ty = type_of(&v).unwrap();
            from_consensus_buff_with::<ManualNames>(i, &ty) == kernels::consensus::from_consensus_buff(i, &ty)
        }));
    }

    // ---- Hashes ------------------------------------------------------------------
    for (len, desc) in [(32usize, "32 B"), (1024, "1 KiB"), (65536, "64 KiB")] {
        let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
        v.push(case(HASH, "hash160", desc, HASH160, data.clone(), |_| true));
        v.push(case(HASH, "sha256", desc, SHA256, data.clone(), |_| true));
        v.push(case(HASH, "sha512", desc, SHA512, data.clone(), |_| true));
        v.push(case(HASH, "sha512/256", desc, SHA512_256, data.clone(), |_| true));
        v.push(case(HASH, "keccak256", desc, KECCAK256, data, |_| true));
    }

    // ---- secp256k1 -------------------------------------------------------------
    let msg: [u8; 32] = Sha256::digest(b"clarity-bench message").into();
    let sk = libsecp256k1::SecretKey::parse(&[0x11; 32])?;
    let (sig, recid) = libsecp256k1::sign(&libsecp256k1::Message::parse(&msg), &sk);
    let pk33 = libsecp256k1::PublicKey::from_secret_key(&sk).serialize_compressed();
    let sig65 = cat(&[&sig.serialize(), &[recid.serialize()]]);
    let recover_in = cat(&[&msg, &sig65]);
    let verify_in = cat(&[&msg, &sig65, &pk33]);

    const CHAIN: &str = "chain backend";
    const RUST: &str = "libsecp256k1 everywhere";
    v.push(case(HASH, "secp256k1-recover?", CHAIN, SECP256K1_RECOVER_CHAIN, recover_in.clone(),
        |i| crypto::secp256k1_recover(&crypto::SECP256K1_CHAIN, &i[..32], &i[32..]).is_ok()));
    v.push(case(HASH, "secp256k1-recover?", RUST, SECP256K1_RECOVER_RUST, recover_in,
        |i| crypto::secp256k1_recover(&crypto::SECP256K1_RUST, &i[..32], &i[32..]).is_ok()));
    v.push(case(HASH, "secp256k1-verify", CHAIN, SECP256K1_VERIFY_CHAIN, verify_in.clone(),
        |i| crypto::secp256k1_verify(&crypto::SECP256K1_CHAIN, &i[..32], &i[32..97], &i[97..])));
    v.push(case(HASH, "secp256k1-verify", RUST, SECP256K1_VERIFY_RUST, verify_in.clone(),
        |i| crypto::secp256k1_verify(&crypto::SECP256K1_RUST, &i[..32], &i[32..97], &i[97..])));
    v.push(case(HASH, "secp256k1-decompress?", CHAIN, SECP256K1_DECOMPRESS_CHAIN, pk33.to_vec(),
        |i| crypto::secp256k1_decompress(&crypto::SECP256K1_CHAIN, i).is_ok()));
    v.push(case(HASH, "secp256k1-decompress?", RUST, SECP256K1_DECOMPRESS_RUST, pk33.to_vec(),
        |i| crypto::secp256k1_decompress(&crypto::SECP256K1_RUST, i).is_ok()));

    // ---- secp256r1 -------------------------------------------------------------
    {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        use p256::ecdsa::signature::Signer;
        use p256::ecdsa::{Signature, SigningKey};
        let sk = SigningKey::from_slice(&[0x22; 32]).map_err(|e| anyhow!("{e}"))?;
        let pk = sk.verifying_key().to_encoded_point(true);
        let prehashed: Signature = sk.sign_prehash(&msg).map_err(|e| anyhow!("{e}"))?;
        let double: Signature = sk.sign(&msg);
        v.push(case(HASH, "secp256r1-verify", "Clarity 5+ (prehashed)", SECP256R1_VERIFY,
            cat(&[&msg, &prehashed.to_bytes(), pk.as_bytes()]),
            |i| crypto::secp256r1_verify(&i[..32], &i[32..96], &i[96..], false)));
        v.push(case(HASH, "secp256r1-verify", "Clarity ≤ 4 (double SHA-256)", SECP256R1_VERIFY_DOUBLE_HASH,
            cat(&[&msg, &double.to_bytes(), pk.as_bytes()]),
            |i| crypto::secp256r1_verify(&i[..32], &i[32..96], &i[96..], true)));
    }

    // ---- ed25519 ---------------------------------------------------------------
    {
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::from_bytes(&[0x33; 32]);
        let message: Vec<u8> = (0..64).collect();
        let sig = sk.sign(&message);
        v.push(case(HASH, "ed25519-verify", "64-byte message", ED25519_VERIFY,
            cat(&[&sk.verifying_key().to_bytes(), &sig.to_bytes(), &message]),
            |i| crypto::ed25519_verify(&i[96..], &i[32..96], &i[..32])));
    }

    // ---- Hand-written WAT ---------------------------------------------------------
    for (len, desc) in [(32usize, "32 B"), (1024, "1 KiB"), (65536, "64 KiB")] {
        let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
        v.push(Case {
            group: WAT,
            function: "keccak256",
            input_desc: desc.into(),
            code: Code::KeccakWat,
            input: data,
            baseline: Some(format!("keccak256 [{desc}]")),
            expect: None,
        });
    }
    v.push(Case {
        group: WAT,
        function: "secp256k1-verify",
        input_desc: "hand-written WAT".into(),
        code: Code::EcdsaWat,
        input: verify_in,
        baseline: Some(format!("secp256k1-verify [{CHAIN}]")),
        expect: None,
    });

    Ok(v)
}

/// Fail early if a fixture doesn't produce the intended (successful) result natively.
pub fn check_expected(cases: &[Case]) -> Result<()> {
    for c in cases {
        if let Some(expect) = c.expect {
            if !expect(&c.input) {
                bail!("fixture {} does not produce the expected result", c.label());
            }
        }
    }
    Ok(())
}

/// A token-transfer-like record, serialized: the input of the consensus-buff cases.
pub fn consensus_fixture() -> Option<Vec<u8>> {
    use kernels::consensus::{serialize, Value};
    let build = || -> Result<Value, kernels::consensus::Error> {
        let tags = ["defi", "stacking", "sbtc", "nft"]
            .iter()
            .map(|t| Value::string_ascii(t.as_bytes().to_vec()))
            .collect::<Result<Vec<_>, _>>()?;
        Value::tuple(vec![
            ("amount", Value::UInt(1_000_000)),
            ("memo", Value::some(Value::buff((0..34).collect())?)?),
            ("recipient", Value::principal_contract(22, [7; 20], "sip-010-token")?),
            ("result", Value::okay(Value::Int(-42))?),
            ("tags", Value::list(tags)?),
        ])
    };
    let mut out = vec![];
    serialize(&build().expect("valid fixture value"), &mut out);
    Some(out)
}
