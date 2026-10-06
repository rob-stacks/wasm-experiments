//! Clarity consensus (SIP-005) value serialization, ported from stacks-core.
//!
//! Sources (stacks-core):
//! - `clarity-types/src/types/serialization.rs`: `Value::serialize_write`,
//!   `Value::deserialize_read_count_with_options` / `inner_deserialize_read`,
//!   `Value::try_deserialize_bytes_exact_at_epoch`, `TypeSignature::max_serialized_size`,
//!   the guarded-string and standard-principal (de)serializers.
//! - `clarity-types/src/types/mod.rs`: `Value::{some, okay, error, list_with_type,
//!   cons_list_unsanitized, buff_from, string_ascii_from_bytes, string_utf8_from_bytes}`,
//!   `TupleData::{from_data, from_data_typed}`, `StandardPrincipalData::new`.
//! - `clarity-types/src/types/signatures.rs`: `TypeSignature::{type_of, admits (v2.1),
//!   least_supertype_v2_1, construct_parent_list_type, size, depth, ...}`.
//! - `clarity-types/src/representations.rs`: `ClarityName` / `ContractName` regexes.
//! - `clarity/src/vm/functions/conversions.rs`: `to-consensus-buff?` / `from-consensus-buff?`.
//!
//! Epoch-dependent behavior is fixed to the highest epoch (Epoch 4.1): value sanitization
//! is on for typed deserialization, typed tuples require the exact field set, and the
//! internal type checks use the Epoch 2.1 `admits` rules exactly like the chain does
//! (`DESERIALIZATION_TYPE_CHECK_EPOCH`).
//!
//! Omitted: `CallableContract` values, `CallableType` / `ListUnionType` /
//! `TraitReferenceType` signatures (only produced by the VM for callable values), cost
//! tracking, logging, and VM error plumbing.

use std::cmp;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, LazyLock};

use regex::Regex;

/// Maximum size in bytes allowed for types.
pub const MAX_VALUE_SIZE: u32 = 1024 * 1024;
/// Bytes serialization upper limit.
pub const BOUND_VALUE_SERIALIZATION_BYTES: u32 = MAX_VALUE_SIZE * 2;
/// Maximum length for UTF8 string.
pub const MAX_UTF8_VALUE_SIZE: u32 = MAX_VALUE_SIZE / 4;
/// Maximum allowed nesting depth of types.
pub const MAX_TYPE_DEPTH: u8 = 32;
/// Charged size for wrapped values, i.e., response or optionals.
pub const WRAPPER_VALUE_SIZE: u32 = 1;
/// Max length of a ClarityName / ContractName.
pub const MAX_STRING_LEN: u8 = 128;
const CONTRACT_MIN_NAME_LENGTH: usize = 1;
/// Pre-sanitization values could end up being larger than the deserializer originally
///  supported, so the bound is raised when sanitizing.
const SANITIZATION_READ_BOUND: u64 = 15_000_000;
/// Depth limit when not sanitizing (untyped path).
const UNSANITIZED_DEPTH_CHECK: usize = 16;
const INITIAL_DESERIALIZATION_CONTAINER_CAPACITY: usize = 1024;

// Same patterns (and the same `regex` crate) as clarity-types' representations.rs.
static CONTRACT_NAME_REGEX_STRING: LazyLock<String> = LazyLock::new(|| {
    format!(
        r#"([a-zA-Z](([a-zA-Z0-9]|[-_])){{{},{}}})"#,
        CONTRACT_MIN_NAME_LENGTH - 1,
        MAX_STRING_LEN - 1
    )
});
static CLARITY_NAME_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::unwrap_used)]
    Regex::new("^[a-zA-Z]([a-zA-Z0-9]|[-_!?+<>=/*])*$|^[-+=/*]$|^[<>]=?$").unwrap()
});
static CONTRACT_NAME_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::unwrap_used)]
    Regex::new(format!("^{}$|^__transient$", CONTRACT_NAME_REGEX_STRING.as_str()).as_str()).unwrap()
});

// ---------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------

/// Union of the `ClarityTypeError` and `SerializationError` variants reachable here.
#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    // ClarityTypeError
    ValueTooLarge,
    ValueOutOfBounds,
    TypeSignatureTooDeep,
    InvalidAsciiCharacter(u8),
    InvalidUtf8Encoding,
    InvalidPrincipalVersion(u8),
    InvalidClarityName(String),
    InvalidContractName(String),
    CouldNotDetermineType,
    CouldNotDetermineSerializationType,
    TypeMismatch(Box<TypeSig>, Box<TypeSig>),
    TypeMismatchValue(Box<TypeSig>, Box<Value>),
    SupertypeTooLarge,
    EmptyTuplesNotAllowed,
    DuplicateTupleField(String),
    NoSuchTupleField(String, TupleTypeSig),
    ListTypeMismatch,
    InvariantViolation(&'static str),
    // SerializationError
    /// Reading past the end of input (or the read bound): `IOError(UnexpectedEof)`.
    UnexpectedEof,
    DeserializeExpected(Box<TypeSig>),
    LeftoverBytesInDeserialization,
    DeserializationFailure(&'static str),
    UnexpectedSerialization,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}

impl From<&'static str> for Error {
    fn from(e: &'static str) -> Self {
        Error::DeserializationFailure(e)
    }
}

// ---------------------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------------------

/// Subset of `TypeSignature` (no callable/trait/list-union types).
///
/// Lengths in `Buffer`/`StringAscii`/`StringUtf8` play the role of `BufferLength` /
/// `StringUTF8Length`; use the checked constructors (`TypeSig::buffer`, ...) to stay
/// within chain bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeSig {
    NoType,
    Int,
    UInt,
    Bool,
    Buffer(u32),
    StringAscii(u32),
    StringUtf8(u32),
    Principal,
    List(ListTypeData),
    Tuple(TupleTypeSig),
    Optional(Box<TypeSig>),
    Response(Box<(TypeSig, TypeSig)>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListTypeData {
    max_len: u32,
    entry_type: Box<TypeSig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TupleTypeSig {
    type_map: Arc<BTreeMap<String, TypeSig>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    Standard {
        version: u8,
        hash160: [u8; 20],
    },
    Contract {
        version: u8,
        hash160: [u8; 20],
        name: String,
    },
}

/// Like `TupleData`: a sorted map plus the tuple's type signature.
#[derive(Debug, Clone)]
pub struct TupleData {
    pub type_signature: TupleTypeSig,
    pub data_map: BTreeMap<String, Value>,
}

#[derive(Debug, Clone)]
pub enum Value {
    Int(i128),
    UInt(u128),
    Bool(bool),
    Buffer(Vec<u8>),
    StringAscii(Vec<u8>),
    /// Per-character UTF-8 bytes, like `UTF8Data`.
    StringUtf8(Vec<Vec<u8>>),
    Principal(Principal),
    Optional(Option<Box<Value>>),
    /// `(committed, data)`
    Response(bool, Box<Value>),
    /// Items plus the list's type signature (like `ListData`).
    List(Vec<Value>, ListTypeData),
    Tuple(TupleData),
}

// Like clarity-types: list/tuple equality ignores the carried type signature.
impl PartialEq for Value {
    fn eq(&self, other: &Value) -> bool {
        use Value::*;
        match (self, other) {
            (Int(a), Int(b)) => a == b,
            (UInt(a), UInt(b)) => a == b,
            (Bool(a), Bool(b)) => a == b,
            (Buffer(a), Buffer(b)) => a == b,
            (StringAscii(a), StringAscii(b)) => a == b,
            (StringUtf8(a), StringUtf8(b)) => a == b,
            (Principal(a), Principal(b)) => a == b,
            (Optional(a), Optional(b)) => a == b,
            (Response(ca, a), Response(cb, b)) => ca == cb && a == b,
            (List(a, _), List(b, _)) => a == b,
            (Tuple(a), Tuple(b)) => a.data_map == b.data_map,
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------------------
// Name validation: the chain's regexes, or an equivalent hand-written check
// ---------------------------------------------------------------------------------------

/// How deserialization validates `ClarityName`s (tuple keys) and `ContractName`s.
/// `RegexNames` is what clarity-types does; `ManualNames` accepts exactly the same
/// strings without the `regex` crate (tests/names_equiv.rs checks the equivalence).
pub trait NameCheck {
    fn is_clarity_name(s: &str) -> bool;
    fn is_contract_name(s: &str) -> bool;
}

/// clarity-types' `CLARITY_NAME_REGEX` / `CONTRACT_NAME_REGEX`.
pub struct RegexNames;

impl NameCheck for RegexNames {
    fn is_clarity_name(s: &str) -> bool {
        CLARITY_NAME_REGEX.is_match(s)
    }
    fn is_contract_name(s: &str) -> bool {
        CONTRACT_NAME_REGEX.is_match(s)
    }
}

/// Hand-written equivalent of the two regexes (all allowed characters are ASCII,
/// so checking bytes is exact).
pub struct ManualNames;

impl NameCheck for ManualNames {
    /// `^[a-zA-Z]([a-zA-Z0-9]|[-_!?+<>=/*])*$|^[-+=/*]$|^[<>]=?$`
    fn is_clarity_name(s: &str) -> bool {
        match s.as_bytes() {
            [first, rest @ ..] if first.is_ascii_alphabetic() => rest
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b"-_!?+<>=/*".contains(b)),
            [single] if b"-+=/*<>".contains(single) => true,
            [b'<' | b'>', b'='] => true,
            _ => false,
        }
    }

    /// `^([a-zA-Z](([a-zA-Z0-9]|[-_])){0,127})$|^__transient$`
    fn is_contract_name(s: &str) -> bool {
        match s.as_bytes() {
            b"__transient" => true,
            [first, rest @ ..] if first.is_ascii_alphabetic() => {
                rest.len() < MAX_STRING_LEN as usize
                    && rest.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
            }
            _ => false,
        }
    }
}

/// Which kind of guarded string is being read.
#[derive(Clone, Copy)]
enum NameKind {
    Clarity,
    Contract,
}

impl NameKind {
    fn check<N: NameCheck>(self, s: &str) -> bool {
        match self {
            NameKind::Clarity => N::is_clarity_name(s),
            NameKind::Contract => N::is_contract_name(s),
        }
    }
}

// ---------------------------------------------------------------------------------------
// Guarded strings / length newtypes
// ---------------------------------------------------------------------------------------

/// `guarded_string!` `TryFrom<String>`.
fn guarded_string(value: String, regex: &Regex) -> Result<String, String> {
    if value.len() > (MAX_STRING_LEN as usize) {
        return Err(value);
    }
    if regex.is_match(&value) {
        Ok(value)
    } else {
        Err(value)
    }
}

/// `ClarityName::try_from`.
pub fn clarity_name(value: String) -> Result<String, Error> {
    guarded_string(value, &CLARITY_NAME_REGEX).map_err(Error::InvalidClarityName)
}

/// `ContractName::try_from`.
pub fn contract_name(value: String) -> Result<String, Error> {
    guarded_string(value, &CONTRACT_NAME_REGEX).map_err(Error::InvalidContractName)
}

/// `BufferLength::try_from(usize|u32)`.
fn buffer_length(data: usize) -> Result<u32, Error> {
    let data = data as i128;
    if data > (MAX_VALUE_SIZE as i128) {
        Err(Error::ValueTooLarge)
    } else if data < 0 {
        Err(Error::ValueOutOfBounds)
    } else {
        Ok(data as u32)
    }
}

/// `StringUTF8Length::try_from(usize)`.
fn utf8_length(data: usize) -> Result<u32, Error> {
    let data = data as i128;
    if data > (MAX_UTF8_VALUE_SIZE as i128) {
        Err(Error::ValueTooLarge)
    } else if data < 0 {
        Err(Error::ValueOutOfBounds)
    } else {
        Ok(data as u32)
    }
}

// ---------------------------------------------------------------------------------------
// Type signature construction, size & depth
// ---------------------------------------------------------------------------------------

impl ListTypeData {
    /// `ListTypeData::new_list`
    pub fn new_list(entry_type: TypeSig, max_len: u32) -> Result<ListTypeData, Error> {
        let would_be_depth = 1 + entry_type.depth();
        if would_be_depth > MAX_TYPE_DEPTH {
            return Err(Error::TypeSignatureTooDeep);
        }
        let list_data = ListTypeData {
            entry_type: Box::new(entry_type),
            max_len,
        };
        let would_be_size = list_data.inner_size()?.ok_or(Error::ValueTooLarge)?;
        if would_be_size > MAX_VALUE_SIZE {
            Err(Error::ValueTooLarge)
        } else {
            Ok(list_data)
        }
    }

    pub fn empty_list() -> ListTypeData {
        ListTypeData {
            entry_type: Box::new(TypeSig::NoType),
            max_len: 0,
        }
    }

    pub fn get_max_len(&self) -> u32 {
        self.max_len
    }

    pub fn get_list_item_type(&self) -> &TypeSig {
        &self.entry_type
    }

    fn inner_size(&self) -> Result<Option<u32>, Error> {
        let total_size = self
            .entry_type
            .size()?
            .checked_mul(self.max_len)
            .and_then(|x| x.checked_add(self.type_size()?));
        match total_size {
            Some(total_size) if total_size <= MAX_VALUE_SIZE => Ok(Some(total_size)),
            _ => Ok(None),
        }
    }

    fn type_size(&self) -> Option<u32> {
        let total_size = self.entry_type.inner_type_size()?.checked_add(4 + 1)?;
        if total_size > MAX_VALUE_SIZE {
            None
        } else {
            Some(total_size)
        }
    }
}

impl TupleTypeSig {
    /// `TupleTypeSignature::try_from(BTreeMap)`
    pub fn try_from_map(type_map: BTreeMap<String, TypeSig>) -> Result<TupleTypeSig, Error> {
        if type_map.is_empty() {
            return Err(Error::EmptyTuplesNotAllowed);
        }
        for child_sig in type_map.values() {
            if (1 + child_sig.depth()) > MAX_TYPE_DEPTH {
                return Err(Error::TypeSignatureTooDeep);
            }
        }
        let result = TupleTypeSig {
            type_map: Arc::new(type_map),
        };
        let would_be_size = result.inner_size()?.ok_or(Error::ValueTooLarge)?;
        if would_be_size > MAX_VALUE_SIZE {
            Err(Error::ValueTooLarge)
        } else {
            Ok(result)
        }
    }

    /// `TupleTypeSignature::try_from(Vec<(ClarityName, TypeSignature)>)`
    pub fn try_from_vec(type_data: Vec<(String, TypeSig)>) -> Result<TupleTypeSig, Error> {
        if type_data.is_empty() {
            return Err(Error::EmptyTuplesNotAllowed);
        }
        let mut type_map = BTreeMap::new();
        for (name, type_info) in type_data.into_iter() {
            let name = clarity_name(name)?;
            if let Entry::Vacant(e) = type_map.entry(name.clone()) {
                e.insert(type_info);
            } else {
                return Err(Error::DuplicateTupleField(name));
            }
        }
        Self::try_from_map(type_map)
    }

    pub fn len(&self) -> u64 {
        self.type_map.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.type_map.is_empty()
    }

    pub fn field_type(&self, field: &str) -> Option<&TypeSig> {
        self.type_map.get(field)
    }

    pub fn get_type_map(&self) -> &BTreeMap<String, TypeSig> {
        &self.type_map
    }

    fn admits(&self, other: &TupleTypeSig) -> Result<bool, Error> {
        if self.type_map.len() != other.type_map.len() {
            return Ok(false);
        }
        for (name, my_type_sig) in self.type_map.iter() {
            if let Some(other_type_sig) = other.type_map.get(name) {
                if !my_type_sig.admits_type_v2_1(other_type_sig)? {
                    return Ok(false);
                }
            } else {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn type_size(&self) -> Option<u32> {
        let mut type_map_size = u32::try_from(self.type_map.len()).ok()?.checked_mul(2)?;
        for (name, type_signature) in self.type_map.iter() {
            type_map_size = type_map_size
                .checked_add(type_signature.inner_type_size()?)?
                .checked_add(name.len() as u32)?;
        }
        if type_map_size > MAX_VALUE_SIZE {
            None
        } else {
            Some(type_map_size)
        }
    }

    fn max_depth(&self) -> u8 {
        let mut max = 0;
        for type_signature in self.type_map.values() {
            max = cmp::max(max, type_signature.depth())
        }
        max
    }

    fn inner_size(&self) -> Result<Option<u32>, Error> {
        let Some(mut total_size) = u32::try_from(self.type_map.len())
            .ok()
            .and_then(|x| x.checked_mul(2))
            .and_then(|x| x.checked_add(self.type_size()?))
        else {
            return Ok(None);
        };
        for (name, type_signature) in self.type_map.iter() {
            total_size = match total_size.checked_add(type_signature.size()?) {
                Some(s) => s,
                None => return Ok(None),
            };
            total_size = match total_size.checked_add(name.len() as u32) {
                Some(s) => s,
                None => return Ok(None),
            };
        }
        if total_size > MAX_VALUE_SIZE {
            Ok(None)
        } else {
            Ok(Some(total_size))
        }
    }
}

impl TypeSig {
    /// `(buff len)`
    pub fn buffer(len: u32) -> Result<TypeSig, Error> {
        Ok(TypeSig::Buffer(buffer_length(len as usize)?))
    }

    /// `(string-ascii len)`
    pub fn string_ascii(len: u32) -> Result<TypeSig, Error> {
        Ok(TypeSig::StringAscii(buffer_length(len as usize)?))
    }

    /// `(string-utf8 len)`
    pub fn string_utf8(len: u32) -> Result<TypeSig, Error> {
        Ok(TypeSig::StringUtf8(utf8_length(len as usize)?))
    }

    /// `(list max_len entry)` — `TypeSignature::list_of`
    pub fn list_of(entry: TypeSig, max_len: u32) -> Result<TypeSig, Error> {
        ListTypeData::new_list(entry, max_len).map(TypeSig::List)
    }

    /// `(tuple ...)`
    pub fn tuple(fields: Vec<(String, TypeSig)>) -> Result<TypeSig, Error> {
        TupleTypeSig::try_from_vec(fields).map(TypeSig::Tuple)
    }

    /// `TypeSignature::new_option`
    pub fn optional(inner_type: TypeSig) -> Result<TypeSig, Error> {
        let new_size = WRAPPER_VALUE_SIZE + inner_type.size()?;
        let new_depth = 1 + inner_type.depth();
        if new_size > MAX_VALUE_SIZE {
            Err(Error::ValueTooLarge)
        } else if new_depth > MAX_TYPE_DEPTH {
            Err(Error::TypeSignatureTooDeep)
        } else {
            Ok(TypeSig::Optional(Box::new(inner_type)))
        }
    }

    /// `TypeSignature::new_response`
    pub fn response(ok_type: TypeSig, err_type: TypeSig) -> Result<TypeSig, Error> {
        let new_size = WRAPPER_VALUE_SIZE + cmp::max(ok_type.size()?, err_type.size()?);
        let new_depth = 1 + cmp::max(ok_type.depth(), err_type.depth());
        if new_size > MAX_VALUE_SIZE {
            Err(Error::ValueTooLarge)
        } else if new_depth > MAX_TYPE_DEPTH {
            Err(Error::TypeSignatureTooDeep)
        } else {
            Ok(TypeSig::Response(Box::new((ok_type, err_type))))
        }
    }

    pub fn is_no_type(&self) -> bool {
        &TypeSig::NoType == self
    }

    pub fn depth(&self) -> u8 {
        match self {
            TypeSig::NoType
            | TypeSig::Int
            | TypeSig::UInt
            | TypeSig::Bool
            | TypeSig::Principal
            | TypeSig::Buffer(_)
            | TypeSig::StringAscii(_)
            | TypeSig::StringUtf8(_) => 1,
            TypeSig::Tuple(tuple_sig) => 1 + tuple_sig.max_depth(),
            TypeSig::List(list_type) => 1 + list_type.get_list_item_type().depth(),
            TypeSig::Optional(t) => 1 + t.depth(),
            TypeSig::Response(v) => 1 + cmp::max(v.0.depth(), v.1.depth()),
        }
    }

    pub fn size(&self) -> Result<u32, Error> {
        self.inner_size()?.ok_or(Error::InvariantViolation(
            "FAIL: .size() overflowed on too large of a type. Construction should have failed!",
        ))
    }

    fn inner_size(&self) -> Result<Option<u32>, Error> {
        let out = match self {
            TypeSig::NoType => Some(1),
            TypeSig::Int => Some(16),
            TypeSig::UInt => Some(16),
            TypeSig::Bool => Some(1),
            TypeSig::Principal => Some(148), // 20+128
            TypeSig::Tuple(tuple_sig) => tuple_sig.inner_size()?,
            TypeSig::Buffer(len) | TypeSig::StringAscii(len) => 4u32.checked_add(*len),
            TypeSig::List(list_type) => list_type.inner_size()?,
            TypeSig::StringUtf8(len) => len.checked_mul(4).and_then(|x| x.checked_add(4)),
            TypeSig::Optional(t) => t.size()?.checked_add(WRAPPER_VALUE_SIZE),
            TypeSig::Response(v) => {
                let t_size = v.0.size()?;
                let s_size = v.1.size()?;
                cmp::max(t_size, s_size).checked_add(WRAPPER_VALUE_SIZE)
            }
        };
        Ok(out)
    }

    fn inner_type_size(&self) -> Option<u32> {
        match self {
            TypeSig::NoType | TypeSig::Int | TypeSig::UInt | TypeSig::Bool | TypeSig::Principal => {
                Some(1)
            }
            TypeSig::Tuple(tuple_sig) => tuple_sig.type_size(),
            TypeSig::Buffer(_) | TypeSig::StringAscii(_) | TypeSig::StringUtf8(_) => Some(1 + 4),
            TypeSig::List(list_type) => list_type.type_size(),
            TypeSig::Optional(t) => t.inner_type_size()?.checked_add(1),
            TypeSig::Response(v) => {
                v.0.inner_type_size()?
                    .checked_add(v.1.inner_type_size()?)?
                    .checked_add(1)
            }
        }
    }

    /// `TypeSignature::max_serialized_size`
    pub fn max_serialized_size(&self) -> Result<u32, Error> {
        let type_prefix_size = 1;
        let max_output_size = match self {
            TypeSig::NoType => return Err(Error::CouldNotDetermineSerializationType),
            TypeSig::Int => 16,
            TypeSig::UInt => 16,
            TypeSig::Bool => 0,
            TypeSig::List(list_type) => {
                let list_length_encode = 4;
                list_type
                    .get_max_len()
                    .checked_mul(list_type.get_list_item_type().max_serialized_size()?)
                    .and_then(|x| x.checked_add(list_length_encode))
                    .ok_or(Error::ValueTooLarge)?
            }
            TypeSig::Buffer(len) | TypeSig::StringAscii(len) => {
                len.checked_add(4).ok_or(Error::ValueTooLarge)?
            }
            TypeSig::StringUtf8(len) => len
                .checked_mul(4)
                .and_then(|x| x.checked_add(4))
                .ok_or(Error::ValueTooLarge)?,
            TypeSig::Principal => {
                let maximum_issuer_size = 21;
                let contract_name_length_encode = 1;
                let maximum_contract_name = MAX_STRING_LEN as u32;
                maximum_contract_name + maximum_issuer_size + contract_name_length_encode
            }
            TypeSig::Tuple(tuple_type) => {
                let mut total_size: u32 = 4;
                for (key, value) in tuple_type.get_type_map().iter() {
                    let value_size = value.max_serialized_size()?;
                    total_size = total_size
                        .checked_add(1)
                        .and_then(|x| x.checked_add(key.len() as u32))
                        .and_then(|x| x.checked_add(value_size))
                        .ok_or(Error::ValueTooLarge)?;
                }
                total_size
            }
            TypeSig::Optional(some_type) => match some_type.max_serialized_size() {
                Ok(size) => size,
                Err(Error::CouldNotDetermineSerializationType) => 0,
                Err(e) => return Err(e),
            },
            TypeSig::Response(response_types) => {
                let (ok_type, err_type) = response_types.as_ref();
                let (ok_type_max_size, no_ok_type) = match ok_type.max_serialized_size() {
                    Ok(size) => (size, false),
                    Err(Error::CouldNotDetermineSerializationType) => (0, true),
                    Err(e) => return Err(e),
                };
                let err_type_max_size = match err_type.max_serialized_size() {
                    Ok(size) => size,
                    Err(Error::CouldNotDetermineSerializationType) => {
                        if no_ok_type {
                            return Err(Error::CouldNotDetermineSerializationType);
                        } else {
                            0
                        }
                    }
                    Err(e) => return Err(e),
                };
                cmp::max(ok_type_max_size, err_type_max_size)
            }
        };
        max_output_size
            .checked_add(type_prefix_size)
            .ok_or(Error::ValueTooLarge)
    }

    /// `TypeSignature::concretize`: identity for the supported subset (it still clones,
    /// like the chain does for non-callable types).
    fn concretize(&self) -> TypeSig {
        self.clone()
    }

    /// `TypeSignature::admits_type_v2_1`
    fn admits_type_v2_1(&self, other: &TypeSig) -> Result<bool, Error> {
        let other = other.concretize();
        match self {
            TypeSig::List(my_list_type) => {
                if let TypeSig::List(other_list_type) = &other {
                    if other_list_type.max_len == 0 {
                        Ok(true)
                    } else if my_list_type.max_len >= other_list_type.max_len {
                        my_list_type
                            .entry_type
                            .admits_type_v2_1(&other_list_type.entry_type)
                    } else {
                        Ok(false)
                    }
                } else {
                    Ok(false)
                }
            }
            TypeSig::Buffer(my_len) => match &other {
                TypeSig::Buffer(other_len) => Ok(my_len >= other_len),
                _ => Ok(false),
            },
            TypeSig::StringAscii(len) => match &other {
                TypeSig::StringAscii(other_len) => Ok(len >= other_len),
                _ => Ok(false),
            },
            TypeSig::StringUtf8(len) => match &other {
                TypeSig::StringUtf8(other_len) => Ok(len >= other_len),
                _ => Ok(false),
            },
            TypeSig::Optional(my_inner_type) => {
                if let TypeSig::Optional(other_inner_type) = &other {
                    if other_inner_type.is_no_type() {
                        Ok(true)
                    } else {
                        my_inner_type.admits_type_v2_1(other_inner_type)
                    }
                } else {
                    Ok(false)
                }
            }
            TypeSig::Response(my_inner_type) => {
                if let TypeSig::Response(other_inner_type) = &other {
                    if other_inner_type.0.is_no_type() {
                        my_inner_type.1.admits_type_v2_1(&other_inner_type.1)
                    } else if other_inner_type.1.is_no_type() {
                        my_inner_type.0.admits_type_v2_1(&other_inner_type.0)
                    } else {
                        Ok(my_inner_type.1.admits_type_v2_1(&other_inner_type.1)?
                            && my_inner_type.0.admits_type_v2_1(&other_inner_type.0)?)
                    }
                } else {
                    Ok(false)
                }
            }
            TypeSig::Tuple(tuple_sig) => {
                if let TypeSig::Tuple(other_tuple_sig) = &other {
                    tuple_sig.admits(other_tuple_sig)
                } else {
                    Ok(false)
                }
            }
            TypeSig::NoType => Err(Error::CouldNotDetermineType),
            _ => Ok(&other == self),
        }
    }

    /// `TypeSignature::factor_out_no_type` (Epoch 2.1 => v2_1 supertype)
    fn factor_out_no_type(a: &TypeSig, b: &TypeSig) -> Result<TypeSig, Error> {
        if a.is_no_type() {
            Ok(b.clone())
        } else if b.is_no_type() {
            Ok(a.clone())
        } else {
            Self::least_supertype_v2_1(a, b)
        }
    }

    /// `TypeSignature::least_supertype_v2_1` (callable/list-union arms omitted)
    fn least_supertype_v2_1(a: &TypeSig, b: &TypeSig) -> Result<TypeSig, Error> {
        match (a, b) {
            (
                TypeSig::Tuple(TupleTypeSig { type_map: types_a }),
                TypeSig::Tuple(TupleTypeSig { type_map: types_b }),
            ) => {
                let mut type_map_out = BTreeMap::new();
                for (name, entry_a) in types_a.iter() {
                    let entry_b = types_b.get(name).ok_or_else(|| {
                        Error::TypeMismatch(Box::new(a.clone()), Box::new(b.clone()))
                    })?;
                    let entry_out = Self::least_supertype_v2_1(entry_a, entry_b)?;
                    type_map_out.insert(name.clone(), entry_out);
                }
                TupleTypeSig::try_from_map(type_map_out)
                    .map(TypeSig::Tuple)
                    .map_err(|_| Error::SupertypeTooLarge)
            }
            (
                TypeSig::List(ListTypeData {
                    max_len: len_a,
                    entry_type: entry_a,
                }),
                TypeSig::List(ListTypeData {
                    max_len: len_b,
                    entry_type: entry_b,
                }),
            ) => {
                let entry_type = if *len_a == 0 {
                    *(entry_b.clone())
                } else if *len_b == 0 {
                    *(entry_a.clone())
                } else {
                    Self::least_supertype_v2_1(entry_a, entry_b)?
                };
                let max_len = cmp::max(len_a, len_b);
                Self::list_of(entry_type, *max_len).map_err(|_| Error::SupertypeTooLarge)
            }
            (TypeSig::Response(resp_a), TypeSig::Response(resp_b)) => {
                let ok_type = Self::factor_out_no_type(&resp_a.0, &resp_b.0)?;
                let err_type = Self::factor_out_no_type(&resp_a.1, &resp_b.1)?;
                Self::response(ok_type, err_type)
            }
            (TypeSig::Optional(some_a), TypeSig::Optional(some_b)) => {
                let some_type = Self::factor_out_no_type(some_a, some_b)?;
                Self::optional(some_type)
            }
            (TypeSig::Buffer(buff_a), TypeSig::Buffer(buff_b)) => {
                Ok(TypeSig::Buffer(cmp::max(*buff_a, *buff_b)))
            }
            (TypeSig::StringAscii(a_len), TypeSig::StringAscii(b_len)) => {
                Ok(TypeSig::StringAscii(cmp::max(*a_len, *b_len)))
            }
            (TypeSig::StringUtf8(a_len), TypeSig::StringUtf8(b_len)) => {
                Ok(TypeSig::StringUtf8(cmp::max(*a_len, *b_len)))
            }
            (TypeSig::NoType, x) | (x, TypeSig::NoType) => Ok(x.clone()),
            (x, y) => {
                if x == y {
                    Ok(x.clone())
                } else {
                    Err(Error::TypeMismatch(
                        Box::new(a.clone()),
                        Box::new(b.clone()),
                    ))
                }
            }
        }
    }

    /// `TypeSignature::construct_parent_list_type`
    fn construct_parent_list_type(args: &[Value]) -> Result<ListTypeData, Error> {
        let mut entry_type: Option<TypeSig> = None;
        for next in args.iter().map(type_of) {
            let next = next?;
            entry_type = Some(match entry_type {
                None => next,
                Some(current) if current == next => current,
                Some(current) => Self::least_supertype_v2_1(&current, &next)?,
            });
        }
        match entry_type {
            Some(entry_type) => {
                let len = u32::try_from(args.len()).map_err(|_| Error::ValueTooLarge)?;
                ListTypeData::new_list(entry_type, len)
            }
            None => Ok(ListTypeData::empty_list()),
        }
    }
}

/// `TypeSignature::type_of`
pub fn type_of(v: &Value) -> Result<TypeSig, Error> {
    Ok(match v {
        Value::Principal(_) => TypeSig::Principal,
        Value::Int(_) => TypeSig::Int,
        Value::UInt(_) => TypeSig::UInt,
        Value::Bool(_) => TypeSig::Bool,
        Value::Tuple(t) => TypeSig::Tuple(t.type_signature.clone()),
        Value::List(_, list_type) => TypeSig::List(list_type.clone()),
        Value::Buffer(d) => TypeSig::Buffer(buffer_length(d.len()).map_err(|_| {
            Error::InvariantViolation("ERROR: too large of a buffer successfully constructed.")
        })?),
        Value::StringAscii(d) => TypeSig::StringAscii(buffer_length(d.len()).map_err(|_| {
            Error::InvariantViolation("ERROR: too large of a buffer successfully constructed.")
        })?),
        Value::StringUtf8(d) => TypeSig::StringUtf8(utf8_length(d.len()).map_err(|_| {
            Error::InvariantViolation("ERROR: Too large of a buffer successfully constructed.")
        })?),
        Value::Optional(o) => match o {
            Some(v) => TypeSig::optional(type_of(v)?),
            None => TypeSig::optional(TypeSig::NoType),
        }
        .map_err(|_| {
            Error::InvariantViolation("ERROR: Should not have constructed too large of a type.")
        })?,
        Value::Response(committed, data) => if *committed {
            TypeSig::response(type_of(data)?, TypeSig::NoType)
        } else {
            TypeSig::response(TypeSig::NoType, type_of(data)?)
        }
        .map_err(|_| {
            Error::InvariantViolation("ERROR: Should not have constructed too large of a type.")
        })?,
    })
}

/// `TypeSignature::admits` at Epoch 2.1+ (i.e. the latest epoch).
pub fn admits(expected: &TypeSig, v: &Value) -> Result<bool, Error> {
    let x_type = type_of(v)?;
    expected.admits_type_v2_1(&x_type)
}

// ---------------------------------------------------------------------------------------
// Value constructors (ports of clarity-types' guarded constructors)
// ---------------------------------------------------------------------------------------

impl Principal {
    /// `StandardPrincipalData::new`
    pub fn standard(version: u8, hash160: [u8; 20]) -> Result<Principal, Error> {
        if version >= 32 {
            return Err(Error::InvalidPrincipalVersion(version));
        }
        Ok(Principal::Standard { version, hash160 })
    }

    /// Contract principal with a validated `ContractName`.
    pub fn contract(version: u8, hash160: [u8; 20], name: &str) -> Result<Principal, Error> {
        if version >= 32 {
            return Err(Error::InvalidPrincipalVersion(version));
        }
        let name = contract_name(name.to_string())?;
        Ok(Principal::Contract {
            version,
            hash160,
            name,
        })
    }
}

impl Value {
    pub fn none() -> Value {
        Value::Optional(None)
    }

    fn check_wrapped(data: &Value) -> Result<(), Error> {
        // `data.size()? + WRAPPER_VALUE_SIZE > MAX_VALUE_SIZE` and `data.depth()? + 1 > MAX_TYPE_DEPTH`
        // (each of which calls `type_of` on its own, like the chain).
        if type_of(data)?.size()? + WRAPPER_VALUE_SIZE > MAX_VALUE_SIZE {
            Err(Error::ValueTooLarge)
        } else if type_of(data)?.depth() + 1 > MAX_TYPE_DEPTH {
            Err(Error::TypeSignatureTooDeep)
        } else {
            Ok(())
        }
    }

    /// `Value::some`
    pub fn some(data: Value) -> Result<Value, Error> {
        Self::check_wrapped(&data)?;
        Ok(Value::Optional(Some(Box::new(data))))
    }

    /// `Value::okay`
    pub fn okay(data: Value) -> Result<Value, Error> {
        Self::check_wrapped(&data)?;
        Ok(Value::Response(true, Box::new(data)))
    }

    /// `Value::error`
    pub fn error(data: Value) -> Result<Value, Error> {
        Self::check_wrapped(&data)?;
        Ok(Value::Response(false, Box::new(data)))
    }

    /// `Value::buff_from`
    pub fn buff(data: Vec<u8>) -> Result<Value, Error> {
        buffer_length(data.len())?;
        Ok(Value::Buffer(data))
    }

    /// `Value::string_ascii_from_bytes`
    pub fn string_ascii(bytes: Vec<u8>) -> Result<Value, Error> {
        buffer_length(bytes.len())?;
        for b in bytes.iter() {
            if !b.is_ascii_alphanumeric() && !b.is_ascii_punctuation() && !b.is_ascii_whitespace() {
                return Err(Error::InvalidAsciiCharacter(*b));
            }
        }
        Ok(Value::StringAscii(bytes))
    }

    /// `Value::string_utf8_from_bytes`
    pub fn string_utf8_from_bytes(bytes: Vec<u8>) -> Result<Value, Error> {
        let validated_utf8_str =
            std::str::from_utf8(&bytes).map_err(|_| Error::InvalidUtf8Encoding)?;
        let data = validated_utf8_str
            .chars()
            .map(|char| {
                let mut encoded_char = vec![0u8; char.len_utf8()];
                char.encode_utf8(&mut encoded_char);
                encoded_char
            })
            .collect::<Vec<_>>();
        utf8_length(data.len())?;
        Ok(Value::StringUtf8(data))
    }

    /// Convenience: UTF-8 string from a `&str`.
    pub fn string_utf8(s: &str) -> Result<Value, Error> {
        Self::string_utf8_from_bytes(s.as_bytes().to_vec())
    }

    /// `Value::cons_list_unsanitized`: list whose type is inferred from its items.
    pub fn list(items: Vec<Value>) -> Result<Value, Error> {
        let type_sig = TypeSig::construct_parent_list_type(&items)?;
        Ok(Value::List(items, type_sig))
    }

    /// `Value::list_with_type` (Epoch 2.1 admits rules).
    pub fn list_with_type(items: Vec<Value>, expected_type: ListTypeData) -> Result<Value, Error> {
        if (expected_type.get_max_len() as usize) < items.len() {
            return Err(Error::ValueTooLarge);
        }
        {
            let expected_item_type = expected_type.get_list_item_type();
            for item in &items {
                if !admits(expected_item_type, item)? {
                    return Err(Error::ListTypeMismatch);
                }
            }
        }
        Ok(Value::List(items, expected_type))
    }

    /// Tuple from `(name, value)` pairs: validates names as `ClarityName`, then
    /// `TupleData::from_data`.
    pub fn tuple<S: Into<String>>(fields: Vec<(S, Value)>) -> Result<Value, Error> {
        let mut data = Vec::with_capacity(fields.len());
        for (name, value) in fields {
            data.push((clarity_name(name.into())?, value));
        }
        TupleData::from_data(data).map(Value::Tuple)
    }

    pub fn principal_standard(version: u8, hash160: [u8; 20]) -> Result<Value, Error> {
        Principal::standard(version, hash160).map(Value::Principal)
    }

    pub fn principal_contract(version: u8, hash160: [u8; 20], name: &str) -> Result<Value, Error> {
        Principal::contract(version, hash160, name).map(Value::Principal)
    }
}

impl TupleData {
    /// `TupleData::from_data` (names must already be valid ClarityNames).
    pub fn from_data(data: Vec<(String, Value)>) -> Result<TupleData, Error> {
        let mut type_map = BTreeMap::new();
        let mut data_map = BTreeMap::new();
        for (name, value) in data.into_iter() {
            let type_info = type_of(&value)?;
            match type_map.entry(name.clone()) {
                Entry::Vacant(e) => e.insert(type_info),
                Entry::Occupied(_) => return Err(Error::DuplicateTupleField(name)),
            };
            data_map.insert(name, value);
        }
        Ok(TupleData {
            type_signature: TupleTypeSig::try_from_map(type_map)?,
            data_map,
        })
    }

    /// `TupleData::from_data_typed` with `TupleFieldsBehavior::EXACT_FIELD_SET` (Epoch 4.1+).
    fn from_data_typed(
        data: Vec<(String, Value)>,
        expected: &TupleTypeSig,
    ) -> Result<TupleData, Error> {
        let mut data_map = BTreeMap::new();
        for (name, value) in data.into_iter() {
            let expected_type = expected
                .field_type(&name)
                .ok_or_else(|| Error::NoSuchTupleField(name.to_string(), expected.clone()))?;
            if !admits(expected_type, &value)? {
                return Err(Error::TypeMismatchValue(
                    Box::new(expected_type.clone()),
                    Box::new(value),
                ));
            }
            match data_map.entry(name) {
                Entry::Vacant(e) => {
                    e.insert(value);
                }
                Entry::Occupied(e) => {
                    // allow_duplicate_fields == false
                    return Err(Error::DuplicateTupleField(e.key().to_string()));
                }
            }
        }
        // allow_missing_fields == false
        if data_map.len() as u64 != expected.len() {
            let mut actual_types = BTreeMap::new();
            for (name, value) in data_map.iter() {
                actual_types.insert(name.clone(), type_of(value)?);
            }
            return Err(Error::TypeMismatch(
                Box::new(TypeSig::Tuple(expected.clone())),
                Box::new(TypeSig::Tuple(TupleTypeSig::try_from_map(actual_types)?)),
            ));
        }
        Ok(TupleData {
            type_signature: expected.clone(),
            data_map,
        })
    }
}

// ---------------------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------------------

mod prefix {
    pub const INT: u8 = 0;
    pub const UINT: u8 = 1;
    pub const BUFFER: u8 = 2;
    pub const BOOL_TRUE: u8 = 3;
    pub const BOOL_FALSE: u8 = 4;
    pub const PRINCIPAL_STANDARD: u8 = 5;
    pub const PRINCIPAL_CONTRACT: u8 = 6;
    pub const RESPONSE_OK: u8 = 7;
    pub const RESPONSE_ERR: u8 = 8;
    pub const OPTIONAL_NONE: u8 = 9;
    pub const OPTIONAL_SOME: u8 = 10;
    pub const LIST: u8 = 11;
    pub const TUPLE: u8 = 12;
    pub const STRING_ASCII: u8 = 13;
    pub const STRING_UTF8: u8 = 14;
}

fn type_prefix(v: &Value) -> u8 {
    match v {
        Value::Int(_) => prefix::INT,
        Value::UInt(_) => prefix::UINT,
        Value::Bool(true) => prefix::BOOL_TRUE,
        Value::Bool(false) => prefix::BOOL_FALSE,
        Value::Principal(Principal::Standard { .. }) => prefix::PRINCIPAL_STANDARD,
        Value::Principal(Principal::Contract { .. }) => prefix::PRINCIPAL_CONTRACT,
        Value::Response(true, _) => prefix::RESPONSE_OK,
        Value::Response(false, _) => prefix::RESPONSE_ERR,
        Value::Optional(None) => prefix::OPTIONAL_NONE,
        Value::Optional(Some(_)) => prefix::OPTIONAL_SOME,
        Value::Tuple(_) => prefix::TUPLE,
        Value::Buffer(_) => prefix::BUFFER,
        Value::List(..) => prefix::LIST,
        Value::StringAscii(_) => prefix::STRING_ASCII,
        Value::StringUtf8(_) => prefix::STRING_UTF8,
    }
}

fn write_guarded_string(s: &str, out: &mut Vec<u8>) {
    out.push(s.len() as u8);
    out.extend_from_slice(s.as_bytes());
}

/// `Value::serialize_write` into a `Vec<u8>` (infallible for well-formed values).
pub fn serialize(v: &Value, out: &mut Vec<u8>) {
    out.push(type_prefix(v));
    match v {
        Value::Int(value) => out.extend_from_slice(&value.to_be_bytes()),
        Value::UInt(value) => out.extend_from_slice(&value.to_be_bytes()),
        Value::Principal(Principal::Standard { version, hash160 }) => {
            out.push(*version);
            out.extend_from_slice(hash160);
        }
        Value::Principal(Principal::Contract {
            version,
            hash160,
            name,
        }) => {
            out.push(*version);
            out.extend_from_slice(hash160);
            write_guarded_string(name, out);
        }
        Value::Response(_, data) => serialize(data, out),
        Value::Bool(_) => {}
        Value::Optional(None) => {}
        Value::Optional(Some(value)) => serialize(value, out),
        Value::List(data, _) => {
            out.extend_from_slice(&(data.len() as u32).to_be_bytes());
            for item in data.iter() {
                serialize(item, out);
            }
        }
        Value::Buffer(value) | Value::StringAscii(value) => {
            out.extend_from_slice(&(value.len() as u32).to_be_bytes());
            out.extend_from_slice(value);
        }
        Value::StringUtf8(value) => {
            let total_len: u32 = value.iter().fold(0u32, |len, c| len + c.len() as u32);
            out.extend_from_slice(&total_len.to_be_bytes());
            for bytes in value.iter() {
                out.extend_from_slice(bytes);
            }
        }
        Value::Tuple(data) => {
            out.extend_from_slice(&(data.data_map.len() as u32).to_be_bytes());
            for (key, value) in data.data_map.iter() {
                write_guarded_string(key, out);
                serialize(value, out);
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// Deserialization
// ---------------------------------------------------------------------------------------

/// `BoundReader` over a byte slice: reads beyond `max_len` or the end of input EOF.
struct BoundReader<'a> {
    data: &'a [u8],
    pos: usize,
    limit: usize,
}

impl<'a> BoundReader<'a> {
    fn new(data: &'a [u8], max_len: u64) -> Self {
        let limit = cmp::min(data.len() as u64, max_len) as usize;
        BoundReader {
            data,
            pos: 0,
            limit,
        }
    }

    #[inline]
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        let end = self
            .pos
            .checked_add(buf.len())
            .ok_or(Error::UnexpectedEof)?;
        if end > self.limit {
            return Err(Error::UnexpectedEof);
        }
        buf.copy_from_slice(&self.data[self.pos..end]);
        self.pos = end;
        Ok(())
    }

    fn num_read(&self) -> u64 {
        self.pos as u64
    }
}

/// `ClarityName` / `ContractName` `deserialize_read`.
fn read_guarded_string<N: NameCheck>(r: &mut BoundReader, kind: NameKind) -> Result<String, Error> {
    let mut len = [0; 1];
    r.read_exact(&mut len)?;
    let len = u8::from_be_bytes(len);
    if len > MAX_STRING_LEN {
        return Err(Error::DeserializationFailure("String too long"));
    }
    let mut data = vec![0; len as usize];
    r.read_exact(&mut data)?;
    String::from_utf8(data)
        .map_err(|_| "Non-UTF8 string data".into())
        .and_then(|x| {
            // `guarded_string`: length bound, then the name grammar
            if x.len() <= MAX_STRING_LEN as usize && kind.check::<N>(&x) {
                Ok(x)
            } else {
                Err("Illegal Clarity string".into())
            }
        })
}

/// `StandardPrincipalData::deserialize_read` -> (version, hash160)
fn read_standard_principal(r: &mut BoundReader) -> Result<(u8, [u8; 20]), Error> {
    let mut version = [0; 1];
    let mut data = [0; 20];
    r.read_exact(&mut version)?;
    r.read_exact(&mut data)?;
    if version[0] >= 32 {
        return Err(Error::UnexpectedSerialization);
    }
    Ok((version[0], data))
}

enum DeserializeStackItem {
    List {
        items: Vec<Value>,
        expected_len: u32,
        expected_type: Option<ListTypeData>,
    },
    Tuple {
        items: Vec<(String, Value)>,
        expected_len: u64,
        processed_entries: u64,
        expected_type: Option<TupleTypeSig>,
        next_name: String,
        next_sanitize: bool,
    },
    OptionSome {
        inner_expected_type: Option<TypeSig>,
    },
    ResponseOk {
        inner_expected_type: Option<TypeSig>,
    },
    ResponseErr {
        inner_expected_type: Option<TypeSig>,
    },
    TopLevel {
        expected_type: Option<TypeSig>,
    },
}

impl DeserializeStackItem {
    fn next_expected_type(&self) -> Result<Option<&TypeSig>, Error> {
        match self {
            DeserializeStackItem::List { expected_type, .. } => {
                Ok(expected_type.as_ref().map(|lt| lt.get_list_item_type()))
            }
            DeserializeStackItem::Tuple {
                expected_type,
                next_name,
                next_sanitize,
                ..
            } => match expected_type {
                None => Ok(None),
                Some(some_tuple) => {
                    if *next_sanitize {
                        return Ok(None);
                    }
                    let field_type = some_tuple.field_type(next_name).ok_or_else(|| {
                        Error::DeserializeExpected(Box::new(TypeSig::Tuple(some_tuple.clone())))
                    })?;
                    Ok(Some(field_type))
                }
            },
            DeserializeStackItem::OptionSome {
                inner_expected_type,
            }
            | DeserializeStackItem::ResponseOk {
                inner_expected_type,
            }
            | DeserializeStackItem::ResponseErr {
                inner_expected_type,
            } => Ok(inner_expected_type.as_ref()),
            DeserializeStackItem::TopLevel { expected_type } => Ok(expected_type.as_ref()),
        }
    }
}

macro_rules! check_match {
    ($item:expr, $Pattern:pat) => {
        match $item {
            None => Ok(()),
            Some($Pattern) => Ok(()),
            Some(x) => Err(Error::DeserializeExpected(Box::new((*x).clone()))),
        }
    };
}

/// `Value::inner_deserialize_read`
fn inner_deserialize_read<N: NameCheck>(
    r: &mut BoundReader,
    top_expected_type: Option<&TypeSig>,
    sanitize: bool,
) -> Result<Value, Error> {
    let mut stack = vec![DeserializeStackItem::TopLevel {
        expected_type: top_expected_type.cloned(),
    }];

    while !stack.is_empty() {
        let depth_check = if sanitize {
            MAX_TYPE_DEPTH as usize
        } else {
            UNSANITIZED_DEPTH_CHECK
        };
        if stack.len() > depth_check {
            return Err(Error::TypeSignatureTooDeep);
        }

        #[allow(clippy::unwrap_used)]
        let expected_type = stack.last().unwrap().next_expected_type()?;

        let mut header = [0];
        r.read_exact(&mut header)?;
        let prefix = header[0];

        let item = match prefix {
            prefix::INT => {
                check_match!(expected_type, TypeSig::Int)?;
                let mut buffer = [0; 16];
                r.read_exact(&mut buffer)?;
                Ok(Value::Int(i128::from_be_bytes(buffer)))
            }
            prefix::UINT => {
                check_match!(expected_type, TypeSig::UInt)?;
                let mut buffer = [0; 16];
                r.read_exact(&mut buffer)?;
                Ok(Value::UInt(u128::from_be_bytes(buffer)))
            }
            prefix::BUFFER => {
                let mut buffer_len = [0; 4];
                r.read_exact(&mut buffer_len)?;
                let buffer_len = buffer_length(u32::from_be_bytes(buffer_len) as usize)?;
                if let Some(x) = expected_type {
                    let passed_test = match x {
                        TypeSig::Buffer(expected_len) => buffer_len <= *expected_len,
                        _ => false,
                    };
                    if !passed_test {
                        return Err(Error::DeserializeExpected(Box::new(x.clone())));
                    }
                }
                let mut data = vec![0; buffer_len as usize];
                r.read_exact(&mut data[..])?;
                Value::buff(data).map_err(|_| "Bad buffer".into())
            }
            prefix::BOOL_TRUE => {
                check_match!(expected_type, TypeSig::Bool)?;
                Ok(Value::Bool(true))
            }
            prefix::BOOL_FALSE => {
                check_match!(expected_type, TypeSig::Bool)?;
                Ok(Value::Bool(false))
            }
            prefix::PRINCIPAL_STANDARD => {
                check_match!(expected_type, TypeSig::Principal)?;
                read_standard_principal(r).map(|(version, hash160)| {
                    Value::Principal(Principal::Standard { version, hash160 })
                })
            }
            prefix::PRINCIPAL_CONTRACT => {
                check_match!(expected_type, TypeSig::Principal)?;
                let (version, hash160) = read_standard_principal(r)?;
                let name = read_guarded_string::<N>(r, NameKind::Contract)?;
                Ok(Value::Principal(Principal::Contract {
                    version,
                    hash160,
                    name,
                }))
            }
            prefix::RESPONSE_OK | prefix::RESPONSE_ERR => {
                let committed = prefix == prefix::RESPONSE_OK;
                let expect_contained_type = match expected_type {
                    None => None,
                    Some(x) => {
                        let contained_type = match (committed, x) {
                            (true, TypeSig::Response(types)) => Ok(&types.0),
                            (false, TypeSig::Response(types)) => Ok(&types.1),
                            _ => Err(Error::DeserializeExpected(Box::new(x.clone()))),
                        }?;
                        Some(contained_type)
                    }
                };
                let stack_item = if committed {
                    DeserializeStackItem::ResponseOk {
                        inner_expected_type: expect_contained_type.cloned(),
                    }
                } else {
                    DeserializeStackItem::ResponseErr {
                        inner_expected_type: expect_contained_type.cloned(),
                    }
                };
                stack.push(stack_item);
                continue;
            }
            prefix::OPTIONAL_NONE => {
                check_match!(expected_type, TypeSig::Optional(_))?;
                Ok(Value::none())
            }
            prefix::OPTIONAL_SOME => {
                let expect_contained_type = match expected_type {
                    None => None,
                    Some(x) => {
                        let contained_type = match x {
                            TypeSig::Optional(some_type) => Ok(some_type.as_ref()),
                            _ => Err(Error::DeserializeExpected(Box::new(x.clone()))),
                        }?;
                        Some(contained_type)
                    }
                };
                let stack_item = DeserializeStackItem::OptionSome {
                    inner_expected_type: expect_contained_type.cloned(),
                };
                stack.push(stack_item);
                continue;
            }
            prefix::LIST => {
                let mut len = [0; 4];
                r.read_exact(&mut len)?;
                let len = u32::from_be_bytes(len);

                if len > MAX_VALUE_SIZE {
                    return Err("Illegal list type".into());
                }

                let list_type = match expected_type {
                    None => None,
                    Some(TypeSig::List(list_type)) => {
                        if len > list_type.get_max_len() {
                            return Err(Error::DeserializeExpected(Box::new(TypeSig::List(
                                list_type.clone(),
                            ))));
                        }
                        Some(list_type)
                    }
                    Some(x) => {
                        return Err(Error::DeserializeExpected(Box::new(x.clone())));
                    }
                };

                if len > 0 {
                    let items = Vec::with_capacity(
                        (len as usize).min(INITIAL_DESERIALIZATION_CONTAINER_CAPACITY),
                    );
                    let stack_item = DeserializeStackItem::List {
                        items,
                        expected_len: len,
                        expected_type: list_type.cloned(),
                    };
                    stack.push(stack_item);
                    continue;
                } else {
                    let finished_list = if let Some(list_type) = list_type {
                        Value::list_with_type(vec![], list_type.clone())
                            .map_err(|_| "Illegal list type")?
                    } else {
                        Value::list(vec![]).map_err(|_| "Illegal list type")?
                    };
                    Ok(finished_list)
                }
            }
            prefix::TUPLE => {
                let mut len = [0; 4];
                r.read_exact(&mut len)?;
                let len = u32::from_be_bytes(len);
                let expected_len = u64::from(len);

                if len > MAX_VALUE_SIZE {
                    return Err(Error::DeserializationFailure("Illegal tuple type"));
                }

                let tuple_type = match expected_type {
                    None => None,
                    Some(TypeSig::Tuple(tuple_type)) => {
                        if sanitize {
                            if u64::from(len) < tuple_type.len() {
                                return Err(Error::DeserializeExpected(Box::new(TypeSig::Tuple(
                                    tuple_type.clone(),
                                ))));
                            }
                        } else if u64::from(len) != tuple_type.len() {
                            return Err(Error::DeserializeExpected(Box::new(TypeSig::Tuple(
                                tuple_type.clone(),
                            ))));
                        }
                        Some(tuple_type)
                    }
                    Some(x) => {
                        return Err(Error::DeserializeExpected(Box::new(x.clone())));
                    }
                };

                if len > 0 {
                    let items = Vec::with_capacity(
                        (expected_len as usize).min(INITIAL_DESERIALIZATION_CONTAINER_CAPACITY),
                    );
                    let first_key = read_guarded_string::<N>(r, NameKind::Clarity)?;
                    let next_sanitize = sanitize
                        && tuple_type
                            .map(|tt| tt.field_type(&first_key).is_none())
                            .unwrap_or(false);
                    let stack_item = DeserializeStackItem::Tuple {
                        items,
                        expected_len,
                        processed_entries: 0,
                        expected_type: tuple_type.cloned(),
                        next_name: first_key,
                        next_sanitize,
                    };
                    stack.push(stack_item);
                    continue;
                } else {
                    let finished_tuple = if let Some(tuple_type) = tuple_type {
                        TupleData::from_data_typed(vec![], tuple_type)
                            .map_err(|_| "Illegal tuple type")
                            .map(Value::Tuple)?
                    } else {
                        TupleData::from_data(vec![])
                            .map_err(|_| "Illegal tuple type")
                            .map(Value::Tuple)?
                    };
                    Ok(finished_tuple)
                }
            }
            prefix::STRING_ASCII => {
                let mut buffer_len = [0; 4];
                r.read_exact(&mut buffer_len)?;
                let buffer_len = buffer_length(u32::from_be_bytes(buffer_len) as usize)?;
                if let Some(x) = expected_type {
                    let passed_test = match x {
                        TypeSig::StringAscii(expected_len) => buffer_len <= *expected_len,
                        _ => false,
                    };
                    if !passed_test {
                        return Err(Error::DeserializeExpected(Box::new(x.clone())));
                    }
                }
                let mut data = vec![0; buffer_len as usize];
                r.read_exact(&mut data[..])?;
                Value::string_ascii(data).map_err(|_| "Bad string".into())
            }
            prefix::STRING_UTF8 => {
                let mut total_len = [0; 4];
                r.read_exact(&mut total_len)?;
                let total_len = buffer_length(u32::from_be_bytes(total_len) as usize)?;
                let mut data: Vec<u8> = vec![0; total_len as usize];
                r.read_exact(&mut data[..])?;
                let value = Value::string_utf8_from_bytes(data)
                    .map_err(|_| "Illegal string_utf8 type".into());
                if let Some(x) = expected_type {
                    let passed_test = match (x, &value) {
                        (TypeSig::StringUtf8(expected_len), Ok(Value::StringUtf8(utf8))) => {
                            utf8.len() as u32 <= *expected_len
                        }
                        _ => false,
                    };
                    if !passed_test {
                        return Err(Error::DeserializeExpected(Box::new(x.clone())));
                    }
                }
                value
            }
            _ => Err("Bad type prefix".into()),
        }?;

        let mut finished_item = Some(item);
        while let Some(item) = finished_item.take() {
            let Some(stack_frame) = stack.last_mut() else {
                return Err(
                    "Deserializer processed item, but deserializer stack does not expect another value"
                        .into(),
                );
            };
            match stack_frame {
                DeserializeStackItem::TopLevel { .. } => return Ok(item),
                DeserializeStackItem::List {
                    items,
                    expected_len,
                    ..
                } => {
                    items.push(item);
                    if (*expected_len as usize) <= items.len() {
                        let Some(DeserializeStackItem::List {
                            items,
                            expected_type,
                            ..
                        }) = stack.pop()
                        else {
                            return Err(
                                "BUG: deserializer stack should have a List frame on top".into()
                            );
                        };
                        let finished_list = if let Some(list_type) = expected_type {
                            Value::list_with_type(items, list_type)
                                .map_err(|_| "Illegal list type")?
                        } else {
                            Value::list(items).map_err(|_| "Illegal list type")?
                        };
                        finished_item.replace(finished_list);
                    }
                }
                DeserializeStackItem::Tuple {
                    items,
                    expected_len,
                    expected_type,
                    next_name,
                    next_sanitize,
                    processed_entries,
                } => {
                    let push_entry = if sanitize {
                        if expected_type.is_some() {
                            !*next_sanitize
                        } else {
                            true
                        }
                    } else {
                        true
                    };
                    *processed_entries += 1;
                    if *expected_len <= *processed_entries {
                        let Some(DeserializeStackItem::Tuple {
                            mut items,
                            expected_type,
                            next_name,
                            ..
                        }) = stack.pop()
                        else {
                            return Err(
                                "BUG: deserializer stack should have a Tuple frame on top".into()
                            );
                        };
                        if push_entry {
                            items.push((next_name, item));
                        }
                        let finished_tuple = if let Some(tuple_type) = expected_type {
                            if items.len() != tuple_type.len() as usize {
                                return Err(Error::DeserializeExpected(Box::new(TypeSig::Tuple(
                                    tuple_type,
                                ))));
                            }
                            TupleData::from_data_typed(items, &tuple_type)
                                .map_err(|_| "Illegal tuple type")
                                .map(Value::Tuple)?
                        } else {
                            TupleData::from_data(items)
                                .map_err(|_| "Illegal tuple type")
                                .map(Value::Tuple)?
                        };
                        finished_item.replace(finished_tuple);
                    } else {
                        let key = read_guarded_string::<N>(r, NameKind::Clarity)?;
                        *next_sanitize = sanitize
                            && expected_type
                                .as_ref()
                                .map(|tt| tt.field_type(&key).is_none())
                                .unwrap_or(false);
                        let name = std::mem::replace(next_name, key);
                        if push_entry {
                            items.push((name, item));
                        }
                    }
                }
                DeserializeStackItem::OptionSome { .. } => {
                    stack.pop();
                    let finished_some = Value::some(item).map_err(|_x| "Value too large")?;
                    finished_item.replace(finished_some);
                }
                DeserializeStackItem::ResponseOk { .. } => {
                    stack.pop();
                    let finished_some = Value::okay(item).map_err(|_x| "Value too large")?;
                    finished_item.replace(finished_some);
                }
                DeserializeStackItem::ResponseErr { .. } => {
                    stack.pop();
                    let finished_some = Value::error(item).map_err(|_x| "Value too large")?;
                    finished_item.replace(finished_some);
                }
            };
        }
    }

    Err(Error::DeserializationFailure(
        "Invalid data: stack ran out before finishing parsing",
    ))
}

/// `Value::deserialize_read_count_with_options` over a byte slice.
fn deserialize_read_count<N: NameCheck>(
    bytes: &[u8],
    expected_type: Option<&TypeSig>,
    sanitize: bool,
) -> Result<(Value, u64), Error> {
    let bound = if sanitize && expected_type.is_some() {
        SANITIZATION_READ_BOUND
    } else {
        BOUND_VALUE_SERIALIZATION_BYTES as u64
    };
    let mut bound_reader = BoundReader::new(bytes, bound);
    let value = inner_deserialize_read::<N>(&mut bound_reader, expected_type, sanitize)?;
    let bytes_read = bound_reader.num_read();
    if let Some(expected_type) = expected_type {
        // The chain computes this for a debug log only; keep the work.
        let expect_size = match expected_type.max_serialized_size() {
            Ok(x) => x,
            Err(_) => return Ok((value, bytes_read)),
        };
        std::hint::black_box(bytes_read > expect_size as u64);
    }
    Ok((value, bytes_read))
}

/// Typed: `Value::try_deserialize_bytes_exact_at_epoch` at the latest epoch (sanitizing,
/// exact typed-tuple field set).
/// Untyped (`None`): `Value::deserialize_read_count(.., None, sanitize = false)` (the path
/// of `try_deserialize_bytes_untyped` / `StacksMessageCodec`), plus the leftover-bytes check.
pub fn deserialize_exact(bytes: &[u8], expected: Option<&TypeSig>) -> Result<Value, Error> {
    deserialize_exact_with::<RegexNames>(bytes, expected)
}

/// `deserialize_exact` with a chosen name checker.
pub fn deserialize_exact_with<N: NameCheck>(bytes: &[u8], expected: Option<&TypeSig>) -> Result<Value, Error> {
    let input_length = bytes.len();
    let sanitize = expected.is_some();
    let (value, read_count) = deserialize_read_count::<N>(bytes, expected, sanitize)?;
    if read_count != (input_length as u64) {
        Err(Error::LeftoverBytesInDeserialization)
    } else {
        Ok(value)
    }
}

/// `to-consensus-buff?`: serialize, then `Value::buff_from` + `Value::some`; `None` when
/// the result does not fit in a Clarity buffer wrapped in an optional.
pub fn to_consensus_buff(v: &Value) -> Option<Vec<u8>> {
    let mut clar_buff_serialized = vec![];
    serialize(v, &mut clar_buff_serialized);
    let clar_buff_serialized = Value::buff(clar_buff_serialized).ok()?;
    match Value::some(clar_buff_serialized).ok()? {
        Value::Optional(Some(b)) => match *b {
            Value::Buffer(bytes) => Some(bytes),
            _ => None,
        },
        _ => None,
    }
}

/// `from-consensus-buff?` after the type argument is parsed: exact typed deserialization
/// at the latest epoch, then `admits`, then `Value::some`. `None` on any failure.
pub fn from_consensus_buff(bytes: &[u8], expected: &TypeSig) -> Option<Value> {
    from_consensus_buff_with::<RegexNames>(bytes, expected)
}

/// `from_consensus_buff` with a chosen name checker.
pub fn from_consensus_buff_with<N: NameCheck>(bytes: &[u8], expected: &TypeSig) -> Option<Value> {
    let result = deserialize_exact_with::<N>(bytes, Some(expected)).ok()?;
    if !admits(expected, &result).ok()? {
        return None;
    }
    match Value::some(result).ok()? {
        Value::Optional(Some(b)) => Some(*b),
        _ => None,
    }
}
