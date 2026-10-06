//! Hex and c32check encoding, from `stacks_common::util::hash` and
//! `stacks_common::address::c32`.

use sha2::{Digest, Sha256};

const HEX_CHARS: [u8; 16] = *b"0123456789abcdef";
const C32_CHARACTERS: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// `stacks_common::util::hash::to_hex`
pub fn to_hex(s: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(s.len() * 2);
    for &b in s.iter() {
        bytes.push(HEX_CHARS[(b >> 4) as usize]);
        bytes.push(HEX_CHARS[(b & 0x0f) as usize]);
    }
    String::from_utf8(bytes).expect("hex is ASCII")
}

fn double_sha256_checksum(data: &[u8]) -> [u8; 4] {
    let hashed = Sha256::digest(Sha256::digest(data));
    let mut checksum = [0u8; 4];
    checksum.copy_from_slice(&hashed[0..4]);
    checksum
}

fn c32_encode(input_bytes: &[u8]) -> String {
    let size = input_bytes.len().saturating_mul(8).div_ceil(5);
    let mut result = Vec::with_capacity(size);
    let mut carry = 0;
    let mut carry_bits = 0;

    for current_value in input_bytes.iter().rev() {
        let low_bits_to_take = 5 - carry_bits;
        let low_bits = current_value & ((1 << low_bits_to_take) - 1);
        let c32_value = (low_bits << carry_bits) + carry;
        result.push(C32_CHARACTERS[c32_value as usize]);
        carry_bits = (8 + carry_bits) - 5;
        carry = current_value >> (8 - carry_bits);

        if carry_bits >= 5 {
            let c32_value = carry & ((1 << 5) - 1);
            result.push(C32_CHARACTERS[c32_value as usize]);
            carry_bits -= 5;
            carry >>= 5;
        }
    }

    if carry_bits > 0 {
        result.push(C32_CHARACTERS[carry as usize]);
    }

    // remove leading zeros from c32 encoding
    while let Some(v) = result.pop() {
        if v != C32_CHARACTERS[0] {
            result.push(v);
            break;
        }
    }

    // add leading zeros from input.
    for current_value in input_bytes.iter() {
        if *current_value == 0 {
            result.push(C32_CHARACTERS[0]);
        } else {
            break;
        }
    }

    let result: Vec<u8> = result.into_iter().rev().collect();
    String::from_utf8(result).unwrap()
}

fn c32_check_encode(version: u8, data: &[u8]) -> Option<String> {
    if version >= 32 {
        return None;
    }

    let mut check_data = vec![version];
    check_data.extend_from_slice(data);
    let checksum = double_sha256_checksum(&check_data);

    let mut encoding_data = data.to_vec();
    encoding_data.extend_from_slice(&checksum);

    let mut c32_string = c32_encode(&encoding_data).into_bytes();
    let version_char = C32_CHARACTERS[version as usize];
    c32_string.insert(0, version_char);

    Some(String::from_utf8(c32_string).unwrap())
}

/// `StandardPrincipalData::to_address` (`c32_address` with its error fallback).
pub fn c32_address(version: u8, data: &[u8]) -> String {
    match c32_check_encode(version, data) {
        Some(c32_string) => format!("S{c32_string}"),
        None => "INVALID_C32_ADD".to_string(),
    }
}
