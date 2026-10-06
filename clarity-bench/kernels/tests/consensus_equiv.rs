//! Equivalence tests: `kernels::consensus` vs. stacks-core's `clarity-types`.
//!
//! For every case both implementations must agree on: serialized bytes, accept/reject of
//! typed (latest epoch) and untyped exact deserialization, the decoded value (compared via
//! re-serialization) and its carried type signature, and the outcome of
//! `to-consensus-buff?` / `from-consensus-buff?`.

use std::sync::atomic::{AtomicUsize, Ordering};

use clarity_types::types::{
    BufferLength, PrincipalData, QualifiedContractIdentifier, SequenceSubtype,
    StandardPrincipalData, StringSubtype, StringUTF8Length, TupleData as CTupleData,
    TupleTypeSignature, TypeSignature as CT, Value as CV,
};
use clarity_types::{ClarityName, ContractName};
use kernels::consensus::{self as k, Principal, TypeSig, Value};
use stacks_common::types::StacksEpochId;

const EPOCH: StacksEpochId = StacksEpochId::Epoch41;

static CASES: AtomicUsize = AtomicUsize::new(0);

// ------------------------------------------------------------------------------------
// Conversions kernels -> clarity-types
// ------------------------------------------------------------------------------------

fn to_ct(t: &TypeSig) -> CT {
    match t {
        TypeSig::NoType => CT::NoType,
        TypeSig::Int => CT::IntType,
        TypeSig::UInt => CT::UIntType,
        TypeSig::Bool => CT::BoolType,
        TypeSig::Principal => CT::PrincipalType,
        TypeSig::Buffer(n) => CT::SequenceType(SequenceSubtype::BufferType(
            BufferLength::try_from(*n).unwrap(),
        )),
        TypeSig::StringAscii(n) => CT::SequenceType(SequenceSubtype::StringType(
            StringSubtype::ASCII(BufferLength::try_from(*n).unwrap()),
        )),
        TypeSig::StringUtf8(n) => CT::SequenceType(SequenceSubtype::StringType(
            StringSubtype::UTF8(StringUTF8Length::try_from(*n).unwrap()),
        )),
        TypeSig::List(l) => CT::list_of(to_ct(l.get_list_item_type()), l.get_max_len()).unwrap(),
        TypeSig::Tuple(tt) => CT::TupleType(
            TupleTypeSignature::try_from(
                tt.get_type_map()
                    .iter()
                    .map(|(n, t)| (ClarityName::try_from(n.clone()).unwrap(), to_ct(t)))
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
        ),
        TypeSig::Optional(t) => CT::OptionalType(Box::new(to_ct(t))),
        TypeSig::Response(rt) => CT::ResponseType(Box::new((to_ct(&rt.0), to_ct(&rt.1)))),
    }
}

fn to_cv(v: &Value) -> CV {
    match v {
        Value::Int(i) => CV::Int(*i),
        Value::UInt(u) => CV::UInt(*u),
        Value::Bool(b) => CV::Bool(*b),
        Value::Buffer(b) => CV::buff_from(b.clone()).unwrap(),
        Value::StringAscii(b) => CV::string_ascii_from_bytes(b.clone()).unwrap(),
        Value::StringUtf8(chars) => CV::string_utf8_from_bytes(chars.concat()).unwrap(),
        Value::Principal(Principal::Standard { version, hash160 }) => CV::Principal(
            PrincipalData::Standard(StandardPrincipalData::new(*version, *hash160).unwrap()),
        ),
        Value::Principal(Principal::Contract {
            version,
            hash160,
            name,
        }) => CV::Principal(PrincipalData::Contract(QualifiedContractIdentifier::new(
            StandardPrincipalData::new(*version, *hash160).unwrap(),
            ContractName::try_from(name.clone()).unwrap(),
        ))),
        Value::Optional(None) => CV::none(),
        Value::Optional(Some(x)) => CV::some(to_cv(x)).unwrap(),
        Value::Response(true, x) => CV::okay(to_cv(x)).unwrap(),
        Value::Response(false, x) => CV::error(to_cv(x)).unwrap(),
        Value::List(items, _) => {
            CV::cons_list_unsanitized(items.iter().map(to_cv).collect()).unwrap()
        }
        Value::Tuple(t) => CV::Tuple(
            CTupleData::from_data(
                t.data_map
                    .iter()
                    .map(|(n, v)| (ClarityName::try_from(n.clone()).unwrap(), to_cv(v)))
                    .collect(),
            )
            .unwrap(),
        ),
    }
}

// ------------------------------------------------------------------------------------
// Chain-side entry points
// ------------------------------------------------------------------------------------

fn chain_typed(bytes: &[u8], t: &CT) -> Result<CV, String> {
    CV::try_deserialize_bytes_exact_at_epoch(&bytes.to_vec(), t, &EPOCH).map_err(|e| e.to_string())
}

fn chain_untyped(bytes: &[u8]) -> Result<CV, String> {
    let mut slice = bytes;
    let (v, n) = CV::deserialize_read_count(&mut slice, None, false).map_err(|e| e.to_string())?;
    if n as usize != bytes.len() {
        return Err("leftover".into());
    }
    Ok(v)
}

/// `conversions::to_consensus_buff`
fn chain_to_consensus_buff(v: &CV) -> Option<Vec<u8>> {
    let bytes = v.serialize_to_vec().unwrap();
    let buff = CV::buff_from(bytes.clone()).ok()?;
    CV::some(buff).ok()?;
    Some(bytes)
}

/// `conversions::from_consensus_buff` after argument evaluation
fn chain_from_consensus_buff(bytes: &[u8], t: &CT) -> Option<CV> {
    let v = CV::try_deserialize_bytes_exact_at_epoch(&bytes.to_vec(), t, &EPOCH).ok()?;
    if !t.admits(&EPOCH, &v).ok()? {
        return None;
    }
    CV::some(v.clone()).ok()?;
    Some(v)
}

fn ser(v: &Value) -> Vec<u8> {
    let mut out = vec![];
    k::serialize(v, &mut out);
    out
}

/// Compare a decoded kernels value with a decoded chain value: same bytes, same type.
fn assert_same_value(mine: &Value, chain: &CV, ctx: &str) {
    assert_eq!(
        ser(mine),
        chain.serialize_to_vec().unwrap(),
        "{ctx}: decoded bytes differ"
    );
    assert_eq!(
        to_ct(&k::type_of(mine).unwrap()),
        CT::type_of(chain).unwrap(),
        "{ctx}: decoded type differs"
    );
}

fn compare_result(mine: Result<Value, k::Error>, chain: Result<CV, String>, ctx: &str) -> bool {
    match (&mine, &chain) {
        (Ok(m), Ok(c)) => {
            assert_same_value(m, c, ctx);
            true
        }
        (Err(_), Err(_)) => false,
        _ => panic!("{ctx}: accept/reject mismatch: mine={mine:?} chain={chain:?}"),
    }
}

/// Compare both implementations on (bytes, optional expected type); returns whether accepted.
fn check_bytes(bytes: &[u8], expected: Option<&TypeSig>, ctx: &str) -> bool {
    CASES.fetch_add(1, Ordering::Relaxed);
    match expected {
        None => compare_result(k::deserialize_exact(bytes, None), chain_untyped(bytes), ctx),
        Some(t) => {
            let ct = to_ct(t);
            let accepted = compare_result(
                k::deserialize_exact(bytes, Some(t)),
                chain_typed(bytes, &ct),
                ctx,
            );
            let mine = k::from_consensus_buff(bytes, t);
            let chain = chain_from_consensus_buff(bytes, &ct);
            match (&mine, &chain) {
                (Some(m), Some(c)) => {
                    assert_same_value(m, c, &format!("{ctx} (from-consensus-buff)"))
                }
                (None, None) => {}
                _ => panic!("{ctx}: from-consensus-buff mismatch: mine={mine:?} chain={chain:?}"),
            }
            accepted
        }
    }
}

/// Full check for a well-formed value: serialization equality, type equality, round trips.
fn check_value(v: &Value, ctx: &str) {
    let cv = to_cv(v);
    let bytes = ser(v);
    assert_eq!(
        bytes,
        cv.serialize_to_vec().unwrap(),
        "{ctx}: serialization differs"
    );
    let t = k::type_of(v).unwrap();
    assert_eq!(
        to_ct(&t),
        CT::type_of(&cv).unwrap(),
        "{ctx}: type_of differs"
    );
    assert_eq!(
        k::admits(&t, v).unwrap(),
        CT::type_of(&cv).unwrap().admits(&EPOCH, &cv).unwrap()
    );

    assert!(
        check_bytes(&bytes, Some(&t), &format!("{ctx} typed")),
        "{ctx}: typed rejected"
    );
    assert!(
        check_bytes(&bytes, None, &format!("{ctx} untyped")),
        "{ctx}: untyped rejected"
    );
    assert!(
        k::deserialize_exact(&bytes, Some(&t)).unwrap() == *v,
        "{ctx}: typed round trip"
    );
    assert!(
        k::deserialize_exact(&bytes, None).unwrap() == *v,
        "{ctx}: untyped round trip"
    );
    // `(some v)` can exceed MAX_VALUE_SIZE for max-size values: then both return none.
    let fits_in_some = CV::some(cv.clone()).is_ok();
    let fcb = k::from_consensus_buff(&bytes, &t);
    assert!(
        if fits_in_some {
            fcb.as_ref() == Some(v)
        } else {
            fcb.is_none()
        },
        "{ctx}: from-consensus-buff"
    );
    assert!(
        k::to_consensus_buff(v) == chain_to_consensus_buff(&cv),
        "{ctx}: to-consensus-buff differs"
    );
}

// ------------------------------------------------------------------------------------
// Builders
// ------------------------------------------------------------------------------------

fn h(n: u8) -> [u8; 20] {
    [n; 20]
}
fn std_p(v: u8, n: u8) -> Value {
    Value::principal_standard(v, h(n)).unwrap()
}
fn con_p(v: u8, n: u8, name: &str) -> Value {
    Value::principal_contract(v, h(n), name).unwrap()
}
fn list(items: Vec<Value>) -> Value {
    Value::list(items).unwrap()
}
fn tuple(fields: Vec<(&str, Value)>) -> Value {
    Value::tuple(fields).unwrap()
}
fn some(v: Value) -> Value {
    Value::some(v).unwrap()
}
fn ok(v: Value) -> Value {
    Value::okay(v).unwrap()
}
fn err(v: Value) -> Value {
    Value::error(v).unwrap()
}
fn ascii(s: &str) -> Value {
    Value::string_ascii(s.as_bytes().to_vec()).unwrap()
}
fn utf8(s: &str) -> Value {
    Value::string_utf8(s).unwrap()
}
fn buff(b: &[u8]) -> Value {
    Value::buff(b.to_vec()).unwrap()
}
fn t_list(t: TypeSig, n: u32) -> TypeSig {
    TypeSig::list_of(t, n).unwrap()
}
fn t_tuple(fields: Vec<(&str, TypeSig)>) -> TypeSig {
    TypeSig::tuple(
        fields
            .into_iter()
            .map(|(n, t)| (n.to_string(), t))
            .collect(),
    )
    .unwrap()
}
fn t_opt(t: TypeSig) -> TypeSig {
    TypeSig::optional(t).unwrap()
}
fn t_resp(a: TypeSig, b: TypeSig) -> TypeSig {
    TypeSig::response(a, b).unwrap()
}

// raw byte builders
fn be32(n: u32) -> Vec<u8> {
    n.to_be_bytes().to_vec()
}
fn raw(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}
fn raw_ascii(bytes: &[u8]) -> Vec<u8> {
    raw(&[&[13], &be32(bytes.len() as u32), bytes])
}
fn raw_utf8(bytes: &[u8]) -> Vec<u8> {
    raw(&[&[14], &be32(bytes.len() as u32), bytes])
}
fn raw_name(name: &[u8]) -> Vec<u8> {
    raw(&[&[name.len() as u8], name])
}
fn raw_tuple(fields: &[(&[u8], Vec<u8>)]) -> Vec<u8> {
    let mut out = raw(&[&[12], &be32(fields.len() as u32)]);
    for (n, v) in fields {
        out.extend(raw_name(n));
        out.extend(v);
    }
    out
}
fn raw_list(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = raw(&[&[11], &be32(items.len() as u32)]);
    for i in items {
        out.extend(i);
    }
    out
}
fn raw_int(i: i128) -> Vec<u8> {
    raw(&[&[0], &i.to_be_bytes()])
}
fn raw_uint(i: u128) -> Vec<u8> {
    raw(&[&[1], &i.to_be_bytes()])
}
fn raw_contract(version: u8, name: &[u8]) -> Vec<u8> {
    raw(&[&[6, version], &h(7), &raw_name(name)])
}

// ------------------------------------------------------------------------------------
// Deterministic random generation
// ------------------------------------------------------------------------------------

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.below(100) < pct
    }
}

const NAMES: &[&str] = &["a", "b", "c", "foo-bar", "x?", "+", "<=", "baz!", "q*z"];
const CONTRACTS: &[&str] = &["c", "my-contract", "a_b", "__transient", "pox-4"];
const UCHARS: &[char] = &[
    'a',
    'Z',
    ' ',
    'é',
    'ß',
    '中',
    '😀',
    '\u{7f}',
    '\n',
    '\u{10FFFF}',
];

fn gen_type(r: &mut Rng, depth: u32) -> TypeSig {
    let leaf = depth == 0 || r.chance(40);
    if leaf {
        return match r.below(8) {
            0 => TypeSig::Int,
            1 => TypeSig::UInt,
            2 => TypeSig::Bool,
            3 => TypeSig::Principal,
            4 => TypeSig::buffer(r.below(40) as u32).unwrap(),
            5 => TypeSig::string_ascii(r.below(40) as u32).unwrap(),
            6 => TypeSig::string_utf8(r.below(20) as u32).unwrap(),
            _ => TypeSig::Int,
        };
    }
    match r.below(4) {
        0 => t_list(gen_type(r, depth - 1), r.below(6) as u32),
        1 => {
            let n = 1 + r.below(4) as usize;
            let mut fields: Vec<(String, TypeSig)> = vec![];
            for _ in 0..n {
                let name = NAMES[r.below(NAMES.len() as u64) as usize].to_string();
                if !fields.iter().any(|(f, _)| *f == name) {
                    fields.push((name, gen_type(r, depth - 1)));
                }
            }
            TypeSig::tuple(fields).unwrap()
        }
        2 => t_opt(gen_type(r, depth - 1)),
        _ => t_resp(gen_type(r, depth - 1), gen_type(r, depth - 1)),
    }
}

fn gen_value(r: &mut Rng, t: &TypeSig) -> Value {
    match t {
        TypeSig::NoType => unreachable!(),
        TypeSig::Int => Value::Int(match r.below(4) {
            0 => i128::MIN,
            1 => i128::MAX,
            2 => 0,
            _ => r.next() as i128 - (1 << 63),
        }),
        TypeSig::UInt => Value::UInt(if r.chance(20) {
            u128::MAX
        } else {
            r.next() as u128
        }),
        TypeSig::Bool => Value::Bool(r.chance(50)),
        TypeSig::Principal => {
            let version = r.below(32) as u8;
            if r.chance(50) {
                std_p(version, r.below(255) as u8)
            } else {
                con_p(
                    version,
                    r.below(255) as u8,
                    CONTRACTS[r.below(CONTRACTS.len() as u64) as usize],
                )
            }
        }
        TypeSig::Buffer(n) => {
            let len = r.below(*n as u64 + 1) as usize;
            buff(&(0..len).map(|_| r.next() as u8).collect::<Vec<_>>())
        }
        TypeSig::StringAscii(n) => {
            let len = r.below(*n as u64 + 1) as usize;
            Value::string_ascii((0..len).map(|_| 0x20 + r.below(0x5f) as u8).collect()).unwrap()
        }
        TypeSig::StringUtf8(n) => {
            let len = r.below(*n as u64 + 1) as usize;
            let s: String = (0..len)
                .map(|_| UCHARS[r.below(UCHARS.len() as u64) as usize])
                .collect();
            utf8(&s)
        }
        TypeSig::List(l) => {
            let len = r.below(l.get_max_len() as u64 + 1) as usize;
            list(
                (0..len)
                    .map(|_| gen_value(r, l.get_list_item_type()))
                    .collect(),
            )
        }
        TypeSig::Tuple(tt) => Value::tuple(
            tt.get_type_map()
                .iter()
                .map(|(n, t)| (n.clone(), gen_value(r, t)))
                .collect(),
        )
        .unwrap(),
        TypeSig::Optional(t) => {
            if r.chance(30) {
                Value::none()
            } else {
                some(gen_value(r, t))
            }
        }
        TypeSig::Response(rt) => {
            if r.chance(50) {
                ok(gen_value(r, &rt.0))
            } else {
                err(gen_value(r, &rt.1))
            }
        }
    }
}

fn mutate(r: &mut Rng, bytes: &[u8]) -> Vec<u8> {
    let mut b = bytes.to_vec();
    match r.below(7) {
        0 if !b.is_empty() => {
            let i = r.below(b.len() as u64) as usize;
            b[i] = r.next() as u8;
        }
        1 if !b.is_empty() => {
            let i = r.below(b.len() as u64) as usize;
            b[i] ^= 1 << r.below(8);
        }
        2 => {
            b.truncate(r.below(b.len() as u64 + 1) as usize);
        }
        3 => {
            b.push(r.next() as u8);
        }
        4 if !b.is_empty() => {
            // small increment/decrement of a byte (hits length fields & prefixes)
            let i = r.below(b.len() as u64) as usize;
            b[i] = if r.chance(50) {
                b[i].wrapping_add(1)
            } else {
                b[i].wrapping_sub(1)
            };
        }
        5 if !b.is_empty() => {
            let i = r.below(b.len() as u64) as usize;
            b.remove(i);
        }
        _ => {
            let i = r.below(b.len() as u64 + 1) as usize;
            b.insert(i, r.next() as u8);
        }
    }
    b
}

// ------------------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------------------

fn well_formed_values() -> Vec<(&'static str, Value)> {
    let mut v: Vec<(&'static str, Value)> = vec![
        ("int 0", Value::Int(0)),
        ("int min", Value::Int(i128::MIN)),
        ("int max", Value::Int(i128::MAX)),
        ("int -1", Value::Int(-1)),
        ("uint 0", Value::UInt(0)),
        ("uint max", Value::UInt(u128::MAX)),
        ("true", Value::Bool(true)),
        ("false", Value::Bool(false)),
        ("empty buff", buff(&[])),
        ("buff", buff(&[0, 1, 2, 0xff])),
        ("empty ascii", ascii("")),
        ("ascii", ascii("Hello, World! ~`{}|\\\t\n\r\x0c")),
        ("empty utf8", utf8("")),
        ("utf8", utf8("héllo wörld 中文 😀 \u{10FFFF}")),
        ("std principal v0", std_p(0, 0)),
        ("std principal v22", std_p(22, 9)),
        ("std principal v31", std_p(31, 0xff)),
        ("contract principal", con_p(26, 1, "my-contract")),
        ("contract principal 1-char", con_p(26, 1, "a")),
        ("contract principal __transient", con_p(1, 1, "__transient")),
        ("contract principal 40 chars", con_p(22, 3, &"a".repeat(40))),
        (
            "contract principal 128 chars",
            con_p(
                22,
                3,
                &format!("a{}", "-_9Z".repeat(31))
                    .chars()
                    .chain("abc".chars())
                    .collect::<String>(),
            ),
        ),
        ("none", Value::none()),
        ("some int", some(Value::Int(5))),
        ("some none", some(Value::none())),
        ("some some some", some(some(some(Value::Bool(true))))),
        ("ok", ok(Value::UInt(1))),
        ("err", err(ascii("boom"))),
        ("ok none", ok(Value::none())),
        ("err ok err", err(ok(err(Value::Int(-3))))),
        ("empty list", list(vec![])),
        (
            "list int",
            list(vec![Value::Int(1), Value::Int(2), Value::Int(3)]),
        ),
        (
            "list of empty lists",
            list(vec![list(vec![]), list(vec![])]),
        ),
        (
            "list mixed lists",
            list(vec![list(vec![]), list(vec![Value::Int(1)]), list(vec![])]),
        ),
        (
            "list buffers diff len",
            list(vec![buff(&[1]), buff(&[1, 2, 3]), buff(&[])]),
        ),
        (
            "list ascii diff len",
            list(vec![ascii("a"), ascii(""), ascii("abcdef")]),
        ),
        ("list utf8 diff len", list(vec![utf8("é"), utf8("abc😀")])),
        (
            "list principals mixed",
            list(vec![std_p(1, 1), con_p(2, 2, "x")]),
        ),
        (
            "list optionals",
            list(vec![Value::none(), some(Value::Int(1)), Value::none()]),
        ),
        (
            "list responses",
            list(vec![
                ok(Value::Int(1)),
                err(Value::UInt(2)),
                ok(Value::Int(3)),
            ]),
        ),
        (
            "list of only none",
            list(vec![Value::none(), Value::none()]),
        ),
        ("list of only ok", list(vec![ok(Value::Bool(true))])),
        ("tuple 1", tuple(vec![("a", Value::Int(1))])),
        (
            "tuple sym names",
            tuple(vec![
                ("+", Value::Int(1)),
                ("<=", Value::Int(2)),
                ("a-b?!", Value::Int(3)),
                ("-", Value::Int(4)),
                (">", Value::Int(5)),
            ]),
        ),
        (
            "tuple nested",
            tuple(vec![
                ("owner", std_p(22, 1)),
                ("amount", Value::UInt(1000)),
                ("memo", some(buff(b"memo"))),
                (
                    "inner",
                    tuple(vec![("x", list(vec![Value::Int(1)])), ("y", utf8("ü"))]),
                ),
            ]),
        ),
        (
            "list of tuples",
            list(vec![
                tuple(vec![("a", Value::Int(1)), ("b", buff(&[1]))]),
                tuple(vec![("a", Value::Int(2)), ("b", buff(&[1, 2]))]),
            ]),
        ),
        (
            "list of tuples w/ opt",
            list(vec![
                tuple(vec![("a", Value::none())]),
                tuple(vec![("a", some(Value::UInt(2)))]),
            ]),
        ),
        (
            "tuple long name",
            tuple(vec![(&*"n".repeat(128), Value::Bool(true))]),
        ),
    ];
    // nesting
    let mut deep = Value::Int(1);
    for _ in 0..14 {
        deep = some(deep);
    }
    v.push(("15-deep optional", deep.clone()));
    let mut deep_l = Value::Int(1);
    for _ in 0..14 {
        deep_l = list(vec![deep_l]);
    }
    v.push(("15-deep list", deep_l));
    // max-ish sizes
    v.push(("buff 64k", buff(&vec![0xab; 65536])));
    v.push((
        "buff 1MB-10",
        buff(&vec![7; (k::MAX_VALUE_SIZE - 10) as usize]),
    ));
    v.push((
        "ascii 100k",
        Value::string_ascii(vec![b'x'; 100_000]).unwrap(),
    ));
    v.push((
        "utf8 max chars 1-byte",
        Value::string_utf8_from_bytes(vec![b'a'; k::MAX_UTF8_VALUE_SIZE as usize]).unwrap(),
    ));
    v.push(("utf8 50k 4-byte", utf8(&"😀".repeat(50_000))));
    v.push(("list 5000 ints", list((0..5000).map(Value::Int).collect())));
    v.push((
        "list 500 tuples",
        list(
            (0..500)
                .map(|i| {
                    tuple(vec![
                        ("a", Value::UInt(i)),
                        ("b", some(Value::Bool(i % 2 == 0))),
                    ])
                })
                .collect(),
        ),
    ));
    v
}

#[test]
fn well_formed_values_match() {
    let values = well_formed_values();
    for (name, v) in &values {
        check_value(v, name);
    }
    eprintln!("well-formed values: {}", values.len());
}

#[test]
fn to_consensus_buff_size_boundary() {
    // serialized size = 5 + len; to-consensus-buff needs buff (<= 1MB) and some (size+1 <= 1MB)
    for len in [
        k::MAX_VALUE_SIZE - 11,
        k::MAX_VALUE_SIZE - 10,
        k::MAX_VALUE_SIZE - 9,
        k::MAX_VALUE_SIZE - 6,
        k::MAX_VALUE_SIZE - 5,
        k::MAX_VALUE_SIZE - 4,
        k::MAX_VALUE_SIZE,
    ] {
        let v = buff(&vec![1; len as usize]);
        let cv = to_cv(&v);
        let (m, c) = (k::to_consensus_buff(&v), chain_to_consensus_buff(&cv));
        assert_eq!(m, c, "len {len}");
        CASES.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn malformed_and_mismatched_inputs_agree() {
    let int1 = raw_int(1);
    let mut cases: Vec<(String, Vec<u8>, Option<TypeSig>)> = vec![];
    let mut add = |name: &str, bytes: Vec<u8>, t: Option<TypeSig>| {
        cases.push((name.to_string(), bytes.clone(), t.clone()));
        if t.is_some() {
            cases.push((format!("{name} [untyped]"), bytes, None));
        }
    };

    add("empty input", vec![], Some(TypeSig::Int));
    add("bad prefix 15", vec![15], Some(TypeSig::Int));
    add("bad prefix 255", vec![255, 0, 0], None);
    add("truncated int", int1[..10].to_vec(), Some(TypeSig::Int));
    add("leftover bytes", raw(&[&int1, &[0]]), Some(TypeSig::Int));
    add("int as uint", int1.clone(), Some(TypeSig::UInt));
    add("bool as int", vec![3], Some(TypeSig::Int));
    add("bool ok", vec![4], Some(TypeSig::Bool));
    add("none as int", vec![9], Some(TypeSig::Int));
    add("none as optional", vec![9], Some(t_opt(TypeSig::Int)));
    add(
        "some int as opt uint",
        raw(&[&[10], &int1]),
        Some(t_opt(TypeSig::UInt)),
    );
    add(
        "ok int vs response(int, uint)",
        raw(&[&[7], &int1]),
        Some(t_resp(TypeSig::Int, TypeSig::UInt)),
    );
    add(
        "err int vs response(int, uint)",
        raw(&[&[8], &int1]),
        Some(t_resp(TypeSig::Int, TypeSig::UInt)),
    );
    add(
        "ok vs optional",
        raw(&[&[7], &int1]),
        Some(t_opt(TypeSig::Int)),
    );
    // buffers
    add(
        "buff len > type",
        raw(&[&[2], &be32(3), &[1, 2, 3]]),
        Some(TypeSig::buffer(2).unwrap()),
    );
    add(
        "buff len == type",
        raw(&[&[2], &be32(2), &[1, 2]]),
        Some(TypeSig::buffer(2).unwrap()),
    );
    add(
        "buff truncated",
        raw(&[&[2], &be32(4), &[1, 2]]),
        Some(TypeSig::buffer(10).unwrap()),
    );
    add(
        "buff len > 1MB",
        raw(&[&[2], &be32(k::MAX_VALUE_SIZE + 1)]),
        None,
    );
    add(
        "buff declared 1MB truncated",
        raw(&[&[2], &be32(k::MAX_VALUE_SIZE), &[0; 10]]),
        Some(TypeSig::buffer(k::MAX_VALUE_SIZE).unwrap()),
    );
    add(
        "buff as ascii",
        raw(&[&[2], &be32(1), b"a"]),
        Some(TypeSig::string_ascii(5).unwrap()),
    );
    // ascii
    for (n, b) in [
        ("NUL", 0u8),
        ("VT", 0x0b),
        ("DEL", 0x7f),
        ("0x80", 0x80),
        ("0xff", 0xff),
        ("TAB", 0x09),
        ("FF", 0x0c),
        ("CR", 0x0d),
        ("tilde", b'~'),
    ] {
        add(
            &format!("ascii {n}"),
            raw_ascii(&[b'a', b, b'z']),
            Some(TypeSig::string_ascii(10).unwrap()),
        );
    }
    add(
        "ascii too long for type",
        raw_ascii(b"abcdef"),
        Some(TypeSig::string_ascii(5).unwrap()),
    );
    add(
        "ascii as utf8",
        raw_ascii(b"abc"),
        Some(TypeSig::string_utf8(5).unwrap()),
    );
    add(
        "ascii len > 1MB",
        raw(&[&[13], &be32(k::MAX_VALUE_SIZE + 1)]),
        None,
    );
    // utf8
    for (n, b) in [
        ("invalid 0xff", vec![0xffu8]),
        ("lone continuation", vec![0x80]),
        ("truncated 2-byte", vec![0xc3]),
        ("overlong /", vec![0xc0, 0xaf]),
        ("surrogate", vec![0xed, 0xa0, 0x80]),
        ("> U+10FFFF", vec![0xf4, 0x90, 0x80, 0x80]),
        ("valid 4-byte", "😀".as_bytes().to_vec()),
        ("valid mixed", "aé中😀".as_bytes().to_vec()),
        ("NUL", vec![0]),
    ] {
        add(
            &format!("utf8 {n}"),
            raw_utf8(&b),
            Some(TypeSig::string_utf8(10).unwrap()),
        );
    }
    add(
        "utf8 3 chars vs (string-utf8 2)",
        raw_utf8("é中😀".as_bytes()),
        Some(TypeSig::string_utf8(2).unwrap()),
    );
    add(
        "utf8 9 bytes 3 chars vs (string-utf8 3)",
        raw_utf8("é中😀".as_bytes()),
        Some(TypeSig::string_utf8(3).unwrap()),
    );
    add(
        "utf8 too many chars",
        raw_utf8(&vec![b'a'; k::MAX_UTF8_VALUE_SIZE as usize + 1]),
        None,
    );
    add(
        "utf8 total len > 1MB",
        raw(&[&[14], &be32(k::MAX_VALUE_SIZE + 1)]),
        None,
    );
    add(
        "utf8 as ascii",
        raw_utf8(b"abc"),
        Some(TypeSig::string_ascii(5).unwrap()),
    );
    // principals
    for v in [0u8, 22, 26, 31, 32, 33, 128, 255] {
        add(
            &format!("std principal version {v}"),
            raw(&[&[5, v], &h(1)]),
            Some(TypeSig::Principal),
        );
        add(
            &format!("contract principal version {v}"),
            raw_contract(v, b"foo"),
            Some(TypeSig::Principal),
        );
    }
    add(
        "std principal truncated",
        raw(&[&[5, 1], &[0; 19]]),
        Some(TypeSig::Principal),
    );
    add(
        "principal as int",
        raw(&[&[5, 1], &h(1)]),
        Some(TypeSig::Int),
    );
    for name in [
        &b""[..],
        b"a",
        b"1abc",
        b"-abc",
        b"a-b_c",
        b"ab.c",
        b"a b",
        b"__transient",
        b"__transien",
        b"_transient",
        b"a!",
        b"A9",
        "é".as_bytes(),
        &[0xff, 0x61],
        &[b'a'; 40],
        &[b'a'; 41],
        &[b'a'; 128],
    ] {
        add(
            &format!("contract name {:?}", String::from_utf8_lossy(name)),
            raw_contract(1, name),
            Some(TypeSig::Principal),
        );
    }
    add(
        "contract name len 129",
        raw(&[&[6, 1], &h(7), &[129], &[b'a'; 129]]),
        Some(TypeSig::Principal),
    );
    add(
        "contract name truncated",
        raw(&[&[6, 1], &h(7), &[10], b"abc"]),
        Some(TypeSig::Principal),
    );
    // tuples
    let tt_ab = t_tuple(vec![("a", TypeSig::Int), ("b", TypeSig::Bool)]);
    add(
        "tuple ok",
        raw_tuple(&[(b"a", raw_int(1)), (b"b", vec![3])]),
        Some(tt_ab.clone()),
    );
    add(
        "tuple unsorted fields",
        raw_tuple(&[(b"b", vec![3]), (b"a", raw_int(1))]),
        Some(tt_ab.clone()),
    );
    add(
        "tuple missing field",
        raw_tuple(&[(b"a", raw_int(1))]),
        Some(tt_ab.clone()),
    );
    add(
        "tuple extra field (sanitized)",
        raw_tuple(&[(b"a", raw_int(1)), (b"b", vec![3]), (b"c", raw_uint(5))]),
        Some(tt_ab.clone()),
    );
    add(
        "tuple extra field w/ bad value",
        raw_tuple(&[(b"a", raw_int(1)), (b"b", vec![3]), (b"c", raw_ascii(&[0]))]),
        Some(tt_ab.clone()),
    );
    add(
        "tuple extra field instead of b",
        raw_tuple(&[(b"a", raw_int(1)), (b"c", vec![3])]),
        Some(tt_ab.clone()),
    );
    add(
        "tuple duplicate field",
        raw_tuple(&[(b"a", raw_int(1)), (b"a", raw_int(2))]),
        Some(tt_ab.clone()),
    );
    add(
        "tuple duplicate + other",
        raw_tuple(&[(b"a", raw_int(1)), (b"a", raw_int(2)), (b"b", vec![3])]),
        Some(tt_ab.clone()),
    );
    add(
        "tuple wrong field type",
        raw_tuple(&[(b"a", vec![3]), (b"b", vec![3])]),
        Some(tt_ab.clone()),
    );
    add("tuple empty", raw_tuple(&[]), Some(tt_ab.clone()));
    add(
        "tuple len > MAX",
        raw(&[&[12], &be32(k::MAX_VALUE_SIZE + 1)]),
        None,
    );
    add(
        "tuple truncated",
        raw(&[&[12], &be32(3), &raw_name(b"a"), &raw_int(1)]),
        None,
    );
    for name in [
        &b""[..],
        b"1a",
        b"a b",
        b"+",
        b"++",
        b"<=",
        b">=",
        b"=>",
        b"<",
        b"a.b",
        b"-",
        b"*",
        b"/",
        b"a/b",
        b"ab?!",
        &[b'n'; 128],
        "é".as_bytes(),
        &[0xff],
    ] {
        add(
            &format!("tuple name {:?}", String::from_utf8_lossy(name)),
            raw_tuple(&[(name, raw_int(1))]),
            None,
        );
    }
    add(
        "tuple name len 129",
        raw(&[&[12], &be32(1), &[129], &[b'a'; 129], &raw_int(1)]),
        None,
    );
    add(
        "tuple vs list type",
        raw_tuple(&[(b"a", raw_int(1))]),
        Some(t_list(TypeSig::Int, 3)),
    );
    // lists
    let l3 = t_list(TypeSig::Int, 3);
    add(
        "list ok",
        raw_list(&[raw_int(1), raw_int(2)]),
        Some(l3.clone()),
    );
    add(
        "list too long for type",
        raw_list(&[raw_int(1), raw_int(2), raw_int(3), raw_int(4)]),
        Some(l3.clone()),
    );
    add(
        "list wrong elem type",
        raw_list(&[raw_int(1), raw_uint(2)]),
        Some(l3.clone()),
    );
    add(
        "list int+uint untyped",
        raw_list(&[raw_int(1), raw_uint(2)]),
        None,
    );
    add(
        "list truncated",
        raw(&[&[11], &be32(3), &raw_int(1)]),
        Some(l3.clone()),
    );
    add(
        "list len > MAX",
        raw(&[&[11], &be32(k::MAX_VALUE_SIZE + 1)]),
        None,
    );
    add("list empty vs list type", raw_list(&[]), Some(l3.clone()));
    add(
        "list empty vs (list 0 int)",
        raw_list(&[]),
        Some(t_list(TypeSig::Int, 0)),
    );
    add(
        "list vs tuple type",
        raw_list(&[raw_int(1)]),
        Some(tt_ab.clone()),
    );
    add(
        "list of tuples differing keys",
        raw_list(&[
            raw_tuple(&[(b"a", raw_int(1))]),
            raw_tuple(&[(b"b", raw_int(1))]),
        ]),
        None,
    );
    add(
        "list of tuples superset keys",
        raw_list(&[
            raw_tuple(&[(b"a", raw_int(1))]),
            raw_tuple(&[(b"a", raw_int(1)), (b"b", raw_int(1))]),
        ]),
        None,
    );
    add(
        "list of tuples subset keys",
        raw_list(&[
            raw_tuple(&[(b"a", raw_int(1)), (b"b", raw_int(1))]),
            raw_tuple(&[(b"a", raw_int(1))]),
        ]),
        None,
    );
    add(
        "list of tuples w/ extra key, typed",
        raw_list(&[raw_tuple(&[(b"a", raw_int(1)), (b"z", raw_int(1))])]),
        Some(t_list(t_tuple(vec![("a", TypeSig::Int)]), 2)),
    );
    add(
        "list (ok int) (err uint)",
        raw_list(&[raw(&[&[7], &raw_int(1)]), raw(&[&[8], &raw_uint(1)])]),
        Some(t_list(t_resp(TypeSig::Int, TypeSig::UInt), 2)),
    );
    add(
        "list (ok int) (ok uint)",
        raw_list(&[raw(&[&[7], &raw_int(1)]), raw(&[&[7], &raw_uint(1)])]),
        None,
    );
    add(
        "list none some",
        raw_list(&[vec![9], raw(&[&[10], &raw_int(1)])]),
        Some(t_list(t_opt(TypeSig::Int), 2)),
    );
    add(
        "list of buffers, one too long",
        raw_list(&[
            raw(&[&[2], &be32(1), &[1]]),
            raw(&[&[2], &be32(3), &[1, 2, 3]]),
        ]),
        Some(t_list(TypeSig::buffer(2).unwrap(), 2)),
    );
    // depth limits: untyped (16) vs typed/sanitized (32)
    for depth in [14usize, 15, 16, 17, 30, 31, 32, 33] {
        let mut b = vec![10u8; depth];
        b.extend(raw_int(1));
        let mut t = TypeSig::Int;
        for _ in 0..depth.min(31) {
            t = t_opt(t);
        }
        add(&format!("{depth} nested somes"), b.clone(), Some(t));
        let mut lb = vec![];
        for _ in 0..depth {
            lb.extend([11u8, 0, 0, 0, 1]);
        }
        lb.extend(raw_int(1));
        let mut lt = TypeSig::Int;
        for _ in 0..depth.min(31) {
            lt = t_list(lt, 1);
        }
        add(&format!("{depth} nested lists"), lb, Some(lt));
    }
    // response / optional with NoType from type_of
    let ok_t = k::type_of(&ok(Value::Int(1))).unwrap();
    add(
        "err uint vs type_of(ok 1)",
        raw(&[&[8], &raw_uint(1)]),
        Some(ok_t.clone()),
    );
    add(
        "ok int vs type_of(ok 1)",
        raw(&[&[7], &raw_int(1)]),
        Some(ok_t),
    );
    let none_t = k::type_of(&Value::none()).unwrap();
    add(
        "some vs type_of(none)",
        raw(&[&[10], &raw_int(1)]),
        Some(none_t.clone()),
    );
    add("none vs type_of(none)", vec![9], Some(none_t));
    add(
        "empty list vs type_of(empty list)",
        raw_list(&[]),
        Some(k::type_of(&list(vec![])).unwrap()),
    );
    add(
        "non-empty list vs type_of(empty list)",
        raw_list(&[raw_int(1)]),
        Some(k::type_of(&list(vec![])).unwrap()),
    );

    let mut accepted = 0;
    let total = cases.len();
    for (name, bytes, t) in &cases {
        if check_bytes(bytes, t.as_ref(), name) {
            accepted += 1;
        }
    }
    eprintln!(
        "malformed/mismatch cases: {total} ({accepted} accepted by both, {} rejected by both)",
        total - accepted
    );
}

#[test]
fn randomized_values_and_mutations_agree() {
    let mut r = Rng(0x9e37_79b9_7f4a_7c15);
    let mut accepted = 0usize;
    let mut total = 0usize;
    for iter in 0..5000 {
        let t = gen_type(&mut r, 4);
        let v = gen_value(&mut r, &t);
        check_value(&v, &format!("random value #{iter}"));
        let bytes = ser(&v);
        // declared (possibly wider) type must also accept; a different random type may not
        assert!(check_bytes(
            &bytes,
            Some(&t),
            &format!("random #{iter} declared type")
        ));
        let other_t = gen_type(&mut r, 3);
        check_bytes(
            &bytes,
            Some(&other_t),
            &format!("random #{iter} other type"),
        );
        for m in 0..12 {
            let mb = mutate(&mut r, &bytes);
            for (label, ty) in [("declared", Some(&t)), ("untyped", None)] {
                total += 1;
                if check_bytes(&mb, ty, &format!("random #{iter} mutation {m} {label}")) {
                    accepted += 1;
                }
            }
        }
    }
    eprintln!("random mutations: {total} ({accepted} accepted by both)");
}
