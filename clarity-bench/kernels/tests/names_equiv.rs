//! The hand-written name check (`ManualNames`) must accept exactly the strings that
//! clarity-types' `ClarityName` / `ContractName` (regex-based) accept, and agree with
//! the port's own `RegexNames`.

use clarity_types::{ClarityName, ContractName};
use kernels::consensus::{ManualNames, NameCheck, RegexNames, MAX_STRING_LEN};

/// `guarded_string!`: length bound, then the grammar.
fn manual(clarity: bool, s: &str) -> bool {
    s.len() <= MAX_STRING_LEN as usize
        && if clarity { ManualNames::is_clarity_name(s) } else { ManualNames::is_contract_name(s) }
}

fn check(s: &str) {
    let chain_clarity = ClarityName::try_from(s.to_string()).is_ok();
    let chain_contract = ContractName::try_from(s.to_string()).is_ok();
    assert_eq!(manual(true, s), chain_clarity, "ClarityName {s:?}");
    assert_eq!(manual(false, s), chain_contract, "ContractName {s:?}");
    if s.len() <= MAX_STRING_LEN as usize {
        assert_eq!(ManualNames::is_clarity_name(s), RegexNames::is_clarity_name(s), "clarity {s:?}");
        assert_eq!(ManualNames::is_contract_name(s), RegexNames::is_contract_name(s), "contract {s:?}");
    }
}

/// Characters that matter to the grammars, plus some that never match.
const ALPHABET: &[char] = &[
    'a', 'z', 'A', 'Z', '0', '9', '-', '_', '!', '?', '+', '<', '>', '=', '/', '*', '.', ' ', '\n', 'é', 'ß',
    '\u{0}', '$', '^', '|', '(',
];

#[test]
fn exhaustive_short_strings() {
    // every string of length 0..=4 over the alphabet (~475k strings)
    let mut count = 0;
    let mut current = vec![String::new()];
    for _ in 0..=4 {
        let mut next = vec![];
        for s in &current {
            check(s);
            count += 1;
            for c in ALPHABET {
                next.push(format!("{s}{c}"));
            }
        }
        current = next;
    }
    assert!(count > 400_000);
}

#[test]
fn every_char_in_every_position() {
    for c in (0u32..0x300).filter_map(char::from_u32) {
        for s in [format!("{c}"), format!("a{c}"), format!("{c}a"), format!("<{c}"), format!("a{c}b"), format!("{c}=")] {
            check(&s);
        }
    }
}

#[test]
fn length_boundaries_and_specials() {
    for n in 0..140 {
        check(&format!("a{}", "b".repeat(n)));
        check(&format!("a{}", "-".repeat(n)));
        check(&format!("a{}", "?".repeat(n)));
        check(&"<".repeat(n));
        check(&"_".repeat(n));
    }
    for s in ["__transient", "__transient_", "_transient", "__Transient", "__transient\n", "a__transient", "transient"] {
        check(s);
    }
}

#[test]
fn random_strings() {
    // xorshift, so the test is deterministic
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for _ in 0..200_000 {
        let len = (next() % 135) as usize;
        let s: String = (0..len).map(|_| ALPHABET[(next() % ALPHABET.len() as u64) as usize]).collect();
        check(&s);
        // mostly-valid names, mutated in one position
        let valid: String = std::iter::once('a')
            .chain((1..len.max(1)).map(|_| ALPHABET[(next() % 8) as usize]))
            .collect();
        check(&valid);
    }
}
