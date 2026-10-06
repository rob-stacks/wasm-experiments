//! Hashing and crypto built-ins from `clarity/src/vm/functions/crypto.rs`,
//! with the `stacks_common` helpers they call.

use sha2::{Digest, Sha256, Sha512, Sha512_256};

// ---------------------------------------------------------------------------
// Hashes (`native_hash_func!` + `stacks_common::util::hash::*::from_data`).
// The result is copied into a fresh buffer, as `Value::buff_from` does.
// ---------------------------------------------------------------------------

pub fn hash160(data: &[u8]) -> Vec<u8> {
    let sha2_result = Sha256::digest(data);
    let ripe_160_result = ripemd::Ripemd160::digest(sha2_result);
    ripe_160_result.to_vec()
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

pub fn sha512(data: &[u8]) -> Vec<u8> {
    Sha512::digest(data).to_vec()
}

pub fn sha512_256(data: &[u8]) -> Vec<u8> {
    Sha512_256::digest(data).to_vec()
}

pub fn keccak256(data: &[u8]) -> Vec<u8> {
    sha3::Keccak256::digest(data).to_vec()
}

// ---------------------------------------------------------------------------
// secp256k1 primitives. stacks-common picks the backend per target:
// `native.rs` (C libsecp256k1 via the `secp256k1` crate) or `wasm.rs`
// (pure-Rust `libsecp256k1`). Both are kept here so either can be measured.
// ---------------------------------------------------------------------------

/// `stacks_common::util::secp256k1::native` (C library).
#[cfg(not(target_family = "wasm"))]
pub mod secp256k1_c {
    use secp256k1::ecdsa::{RecoverableSignature, RecoveryId, Signature};
    use secp256k1::{All, Error, Message, PublicKey, Secp256k1};

    thread_local!(static _SECP256K1: Secp256k1<All> = Secp256k1::new());

    pub fn secp256k1_recover(message_arr: &[u8], serialized_signature_arr: &[u8]) -> Result<[u8; 33], Error> {
        _SECP256K1.with(|ctx| {
            let message = Message::from_slice(message_arr)?;
            let rec_id = RecoveryId::from_i32(serialized_signature_arr[64] as i32)?;
            let recovered_sig = RecoverableSignature::from_compact(&serialized_signature_arr[..64], rec_id)?;
            let recovered_pub = ctx.recover_ecdsa(&message, &recovered_sig)?;
            Ok(recovered_pub.serialize())
        })
    }

    pub fn secp256k1_verify(message_arr: &[u8], serialized_signature_arr: &[u8], pubkey_arr: &[u8]) -> Result<(), Error> {
        _SECP256K1.with(|ctx| {
            let message = Message::from_slice(message_arr)?;
            let expanded_sig = Signature::from_compact(&serialized_signature_arr[..64])?;
            let pubkey = PublicKey::from_slice(pubkey_arr)?;
            // `verify_ecdsa()` rejects high-S signatures
            ctx.verify_ecdsa(&message, &expanded_sig, &pubkey)
        })
    }

    pub fn secp256k1_decompress(compressed_pubkey_arr: &[u8]) -> Result<[u8; 65], Error> {
        let pubkey = PublicKey::from_slice(compressed_pubkey_arr)?;
        Ok(pubkey.serialize_uncompressed())
    }
}

/// `stacks_common::util::secp256k1::wasm` (pure-Rust libsecp256k1).
pub mod secp256k1_rust {
    use libsecp256k1::{Error, Message, PublicKey, PublicKeyFormat, RecoveryId, Signature};

    /// Check `s <= floor(n / 2)` without `Scalar::is_high()`'s off-by-one at the boundary.
    fn is_low_s(sig: &Signature) -> bool {
        sig.s.b32() <= (-sig.s).b32()
    }

    pub fn secp256k1_recover(message_arr: &[u8], serialized_signature: &[u8]) -> Result<[u8; 33], Error> {
        let recovery_id = RecoveryId::parse(serialized_signature[64])?;
        let message = Message::parse_slice(message_arr)?;
        let signature = Signature::parse_standard_slice(&serialized_signature[..64])?;
        let recovered_pub_key = libsecp256k1::recover(&message, &signature, &recovery_id)?;
        Ok(recovered_pub_key.serialize_compressed())
    }

    pub fn secp256k1_verify(message_arr: &[u8], serialized_signature: &[u8], pubkey_arr: &[u8]) -> Result<(), Error> {
        let message = Message::parse_slice(message_arr)?;
        let signature = Signature::parse_standard_slice(&serialized_signature[..64])?;
        let pubkey = PublicKey::parse_slice(pubkey_arr, Some(PublicKeyFormat::Compressed))?;
        if !is_low_s(&signature) {
            return Err(Error::InvalidSignature);
        }
        if libsecp256k1::verify(&message, &signature, &pubkey) {
            Ok(())
        } else {
            Err(Error::InvalidPublicKey)
        }
    }

    pub fn secp256k1_decompress(compressed_pubkey_arr: &[u8]) -> Result<[u8; 65], Error> {
        let pubkey = PublicKey::parse_slice(compressed_pubkey_arr, None)?;
        Ok(pubkey.serialize())
    }
}

/// The backend the chain itself uses on this target.
#[cfg(not(target_family = "wasm"))]
pub use secp256k1_c as secp256k1_chain;
#[cfg(target_family = "wasm")]
pub use secp256k1_rust as secp256k1_chain;

// ---------------------------------------------------------------------------
// Clarity-level wrappers (argument checks from the `special_*` functions).
// The secp256k1 ones take the primitive set so each backend can be measured.
// ---------------------------------------------------------------------------

pub struct Secp256k1Backend {
    pub recover: fn(&[u8], &[u8]) -> Result<[u8; 33], ()>,
    pub verify: fn(&[u8], &[u8], &[u8]) -> bool,
    pub decompress: fn(&[u8]) -> Result<[u8; 65], ()>,
}

pub const SECP256K1_CHAIN: Secp256k1Backend = Secp256k1Backend {
    recover: |m, s| secp256k1_chain::secp256k1_recover(m, s).map_err(|_| ()),
    verify: |m, s, p| secp256k1_chain::secp256k1_verify(m, s, p).is_ok(),
    decompress: |p| secp256k1_chain::secp256k1_decompress(p).map_err(|_| ()),
};

pub const SECP256K1_RUST: Secp256k1Backend = Secp256k1Backend {
    recover: |m, s| secp256k1_rust::secp256k1_recover(m, s).map_err(|_| ()),
    verify: |m, s, p| secp256k1_rust::secp256k1_verify(m, s, p).is_ok(),
    decompress: |p| secp256k1_rust::secp256k1_decompress(p).map_err(|_| ()),
};

/// `special_secp256k1_recover`: `(ok pubkey)`, `(err u1)` on recovery failure,
/// `(err u2)` on a malformed signature.
pub fn secp256k1_recover(b: &Secp256k1Backend, message: &[u8], signature: &[u8]) -> Result<Vec<u8>, u32> {
    if signature.len() < 65 || signature[64] > 3 {
        return Err(2);
    }
    let Ok(pubkey) = (b.recover)(message, signature) else {
        return Err(1);
    };
    Ok(pubkey.to_vec())
}

/// `special_secp256k1_verify`
pub fn secp256k1_verify(b: &Secp256k1Backend, message: &[u8], signature: &[u8], pubkey: &[u8]) -> bool {
    if signature.len() < 64 {
        return false;
    }
    if signature.len() == 65 && signature[64] > 3 {
        return false;
    }
    (b.verify)(message, signature, pubkey)
}

/// `native_secp256k1_decompress`
pub fn secp256k1_decompress(b: &Secp256k1Backend, public_key: &[u8]) -> Result<Vec<u8>, u32> {
    let Ok(public_key_uncompressed) = (b.decompress)(public_key) else {
        return Err(1);
    };
    Ok(public_key_uncompressed.to_vec())
}

/// `special_secp256r1_verify` + `stacks_common::util::secp256r1`.
/// `double_hashing` is `ClarityVersion::uses_secp256r1_double_hashing()` (Clarity <= 4).
pub fn secp256r1_verify(message: &[u8], signature: &[u8], pubkey: &[u8], double_hashing: bool) -> bool {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::elliptic_curve::sec1::FromEncodedPoint;
    use p256::{EncodedPoint, PublicKey};

    if signature.len() != 64 {
        return false;
    }
    let verify = || -> Result<(), ()> {
        let _msg: &[u8; 32] = message.try_into().map_err(|_| ())?;
        let encoded_point = EncodedPoint::from_bytes(pubkey).map_err(|_| ())?;
        let public_key = Option::<PublicKey>::from(PublicKey::from_encoded_point(&encoded_point)).ok_or(())?;
        let key = VerifyingKey::from(public_key);
        let sig = Signature::from_slice(signature).map_err(|_| ())?;
        if double_hashing {
            key.verify(message, &sig).map_err(|_| ())
        } else {
            key.verify_prehash(message, &sig).map_err(|_| ())
        }
    };
    verify().is_ok()
}

/// `native_ed25519_verify` + `stacks_common::util::ed25519::ed25519_verify`.
pub fn ed25519_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};
    let verify = || -> Result<(), ()> {
        let sig_bytes: &[u8; 64] = signature.try_into().map_err(|_| ())?;
        let data32: [u8; 32] = public_key.try_into().map_err(|_| ())?;
        let verifying_key = VerifyingKey::from_bytes(&data32).map_err(|_| ())?;
        let sig = Signature::from_bytes(sig_bytes);
        verifying_key.verify_strict(message, &sig).map_err(|_| ())
    };
    verify().is_ok()
}
