//! Embedded homoglyph confusable fold map — generated from the Unicode Security
//! Mechanisms (UTS #39) confusables data plus a curated overlay
//! (`argus_redact.specs.gen_confusables`). Parity-gated by
//! `tests/architecture/test_confusables_parity.py`.
//!
//! Cyrillic / Greek / Coptic look-alikes -> ASCII Latin, applied 1:1 by
//! `normalize::confusable` before the NFKC step.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ConfusableData {
    mappings: Vec<(char, char)>,
}

/// `char -> char` confusable fold map (source homoglyph -> ASCII Latin).
pub fn confusable_map() -> &'static HashMap<char, char> {
    static CELL: OnceLock<HashMap<char, char>> = OnceLock::new();
    CELL.get_or_init(|| {
        let data: ConfusableData = ron::from_str(include_str!("../data/confusables.ron"))
            .unwrap_or_else(|e| panic!("RON parse error in data/confusables.ron: {}", e));
        data.mappings.into_iter().collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_and_resolves_audit_examples() {
        let m = confusable_map();
        // The 7 audit examples that motivated the generated table.
        assert_eq!(m.get(&'\u{0405}'), Some(&'S'));
        assert_eq!(m.get(&'\u{0408}'), Some(&'J'));
        assert_eq!(m.get(&'\u{0455}'), Some(&'s'));
        assert_eq!(m.get(&'\u{0458}'), Some(&'j'));
        assert_eq!(m.get(&'\u{0501}'), Some(&'d'));
        assert_eq!(m.get(&'\u{04CF}'), Some(&'l'));
        assert_eq!(m.get(&'\u{03F3}'), Some(&'j'));
    }

    #[test]
    fn curated_mapping_preserved() {
        // A curated Cyrillic entry must still resolve to its hand-verified target.
        assert_eq!(confusable_map().get(&'\u{0432}'), Some(&'b')); // в -> b
        assert_eq!(confusable_map().get(&'\u{0430}'), Some(&'a')); // а -> a
    }

    #[test]
    fn ascii_not_in_map() {
        // Pure ASCII letters are never folded (the map is non-ASCII -> ASCII).
        assert_eq!(confusable_map().get(&'a'), None);
        assert_eq!(confusable_map().get(&'S'), None);
    }
}
