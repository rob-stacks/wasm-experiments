//! Conversion built-ins from `clarity/src/vm/functions/conversions.rs`.
//!
//! Type errors that the Clarity type checker makes unreachable are returned as
//! `None`; Clarity `(err uN)` results are `Err(N)`.

use crate::encoding::{c32_address, to_hex};

#[derive(PartialEq)]
pub enum EndianDirection {
    LittleEndian,
    BigEndian,
}

/// `buff_to_int_generic`: zero-pad a buffer of at most 16 bytes on the
/// appropriate side.
fn buff_to_int_generic(sequence_data: &[u8], direction: EndianDirection) -> Option<[u8; 16]> {
    if sequence_data.len() > 16 {
        return None;
    }
    let mut transfer_buffer = [0u8; 16];
    let offset = if direction == EndianDirection::LittleEndian {
        0
    } else {
        transfer_buffer.len() - sequence_data.len()
    };
    for (from_index, _) in sequence_data.iter().enumerate() {
        let to_index = from_index + offset;
        transfer_buffer[to_index] = sequence_data[from_index];
    }
    Some(transfer_buffer)
}

pub fn buff_to_int_le(buff: &[u8]) -> Option<i128> {
    buff_to_int_generic(buff, EndianDirection::LittleEndian).map(i128::from_le_bytes)
}

pub fn buff_to_uint_le(buff: &[u8]) -> Option<u128> {
    buff_to_int_generic(buff, EndianDirection::LittleEndian).map(u128::from_le_bytes)
}

pub fn buff_to_int_be(buff: &[u8]) -> Option<i128> {
    buff_to_int_generic(buff, EndianDirection::BigEndian).map(i128::from_be_bytes)
}

pub fn buff_to_uint_be(buff: &[u8]) -> Option<u128> {
    buff_to_int_generic(buff, EndianDirection::BigEndian).map(u128::from_be_bytes)
}

/// `native_string_to_int` on a `string-ascii` (the argument arrives as an owned
/// buffer, like a Clarity `Value`).
pub fn string_to_int(data: Vec<u8>) -> Option<i128> {
    match String::from_utf8(data) {
        Ok(as_string) => as_string.parse::<i128>().ok(),
        Err(_error) => None,
    }
}

pub fn string_to_uint(data: Vec<u8>) -> Option<u128> {
    match String::from_utf8(data) {
        Ok(as_string) => as_string.parse::<u128>().ok(),
        Err(_error) => None,
    }
}

/// `Value::string_ascii_from_bytes` (the length check against MAX_VALUE_SIZE
/// cannot fail for the inputs used here).
pub fn string_ascii_from_bytes(bytes: Vec<u8>) -> Result<Vec<u8>, u8> {
    for b in bytes.iter() {
        if !b.is_ascii_alphanumeric() && !b.is_ascii_punctuation() && !b.is_ascii_whitespace() {
            return Err(*b);
        }
    }
    Ok(bytes)
}

/// `Value::string_utf8_from_bytes`: validate, then split into per-character
/// byte vectors (Clarity's `UTF8Data` representation).
pub fn string_utf8_from_bytes(bytes: Vec<u8>) -> Option<Vec<Vec<u8>>> {
    let validated_utf8_str = std::str::from_utf8(&bytes).ok()?;
    let data = validated_utf8_str
        .chars()
        .map(|char| {
            let mut encoded_char = vec![0u8; char.len_utf8()];
            char.encode_utf8(&mut encoded_char);
            encoded_char
        })
        .collect::<Vec<_>>();
    Some(data)
}

pub fn int_to_ascii(value: i128) -> Option<Vec<u8>> {
    let as_string = value.to_string();
    string_ascii_from_bytes(as_string.into()).ok()
}

pub fn int_to_utf8(value: i128) -> Option<Vec<Vec<u8>>> {
    let as_string = value.to_string();
    string_utf8_from_bytes(as_string.into())
}

/// The argument kinds accepted by `to-ascii?`.
pub enum ToAsciiArg {
    Int(i128),
    UInt(u128),
    Bool(bool),
    StandardPrincipal(u8, [u8; 20]),
    ContractPrincipal(u8, [u8; 20], String),
    Buffer(Vec<u8>),
    Utf8(Vec<Vec<u8>>),
}

fn convert_string_to_ascii_ok(s: String) -> Result<Vec<u8>, u32> {
    Ok(string_ascii_from_bytes(s.into_bytes()).expect("Unexpected error converting string to ASCII"))
}

fn convert_utf8_to_ascii(s: String) -> Result<Vec<u8>, u32> {
    match string_ascii_from_bytes(s.into_bytes()) {
        Ok(ascii_value) => Ok(ascii_value),
        Err(_) => Err(1), // Non-ASCII characters in UTF8
    }
}

/// `special_to_ascii` after argument evaluation.
pub fn to_ascii(value: &ToAsciiArg) -> Result<Vec<u8>, u32> {
    match value {
        ToAsciiArg::Int(num) => convert_string_to_ascii_ok(num.to_string()),
        ToAsciiArg::UInt(num) => convert_string_to_ascii_ok(format!("u{num}")),
        ToAsciiArg::Bool(b) => convert_string_to_ascii_ok(if *b {
            "true".to_string()
        } else {
            "false".to_string()
        }),
        ToAsciiArg::StandardPrincipal(version, bytes) => {
            convert_string_to_ascii_ok(c32_address(*version, bytes))
        }
        ToAsciiArg::ContractPrincipal(version, bytes, name) => {
            convert_string_to_ascii_ok(format!("{}.{}", c32_address(*version, bytes), name))
        }
        ToAsciiArg::Buffer(buffer_data) => {
            convert_string_to_ascii_ok(format!("0x{}", to_hex(buffer_data)))
        }
        ToAsciiArg::Utf8(data) => {
            let flattened_bytes: Vec<u8> = data.iter().flatten().copied().collect();
            match String::from_utf8(flattened_bytes) {
                Ok(utf8_string) => convert_utf8_to_ascii(utf8_string),
                Err(_) => Err(1), // Invalid UTF8
            }
        }
    }
}
