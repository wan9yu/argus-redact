//! Person-name detection pools (zh + en), embedded as RON and parsed once.
//!
//! ## SSOT contract
//!
//! These pools are the byte-faithful copy of the pure-Python sources
//! (`lang/zh/surnames.py`, `lang/zh/{not_names,common_words}.txt`,
//! `lang/en/{given_names,surnames}.py`). They are the future single source of
//! truth for the no-NER (fast-mode) person detector. A dropped or changed entry
//! would silently break detection, so the Python ↔ RON parity is gated by
//! `tests/detection/lang/test_person_data_parity.py` (frozen counts + sha256).
//!
//! - `surnames` is stored as the exact `SURNAMES` string, byte-for-byte (no
//!   reorder/dedup) — single-char surnames consumed as a char class.
//! - The list pools (`compound_surnames`, `not_names`, `common_words`,
//!   `given_names`, en `surnames`) are sorted in the RON for a deterministic
//!   file; order does not affect matching (all are membership lookups / a
//!   compound char-class alternation).

use std::collections::HashSet;
use std::sync::OnceLock;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ZhPersonData {
    surnames: String,
    compound_surnames: Vec<String>,
    not_names: Vec<String>,
    common_words: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct EnPersonData {
    given_names: Vec<String>,
    surnames: Vec<String>,
}

/// Pool-independent common-word lexicon (lowercased) for the en person
/// detector's "name-like leading token" corroboration signal. See
/// `data/en_common_words.ron` for the contract.
#[derive(Debug, Deserialize)]
struct EnCommonWords {
    words: Vec<String>,
}

macro_rules! embed_ron {
    ($fn_name:ident, $ty:ty, $path:literal) => {
        fn $fn_name() -> &'static $ty {
            static CELL: OnceLock<$ty> = OnceLock::new();
            CELL.get_or_init(|| {
                ron::from_str(include_str!($path))
                    .unwrap_or_else(|e| panic!(concat!("RON parse error in ", $path, ": {}"), e))
            })
        }
    };
}
embed_ron!(zh_data, ZhPersonData, "../data/zh_person.ron");
embed_ron!(en_data, EnPersonData, "../data/en_person.ron");
embed_ron!(en_common_words_data, EnCommonWords, "../data/en_common_words.ron");

// ── zh accessors ────────────────────────────────────────────────────────────

/// Single-char surnames as the exact `SURNAMES` string (byte-for-byte).
pub fn surnames_zh() -> &'static str {
    &zh_data().surnames
}

/// Compound (2-char) surnames pool, sorted (order does not affect matching).
pub fn compound_surnames_zh() -> &'static [String] {
    &zh_data().compound_surnames
}

/// Negative dict: surname-prefixed words that are NOT names (sorted pool).
pub fn not_names_zh() -> &'static [String] {
    &zh_data().not_names
}

/// High-frequency 2-char words for swallow detection (sorted pool).
pub fn common_words_zh() -> &'static [String] {
    &zh_data().common_words
}

/// Negative dict as a membership set.
pub fn not_names_zh_set() -> &'static HashSet<String> {
    static CELL: OnceLock<HashSet<String>> = OnceLock::new();
    CELL.get_or_init(|| zh_data().not_names.iter().cloned().collect())
}

/// Common words as a membership set.
pub fn common_words_zh_set() -> &'static HashSet<String> {
    static CELL: OnceLock<HashSet<String>> = OnceLock::new();
    CELL.get_or_init(|| zh_data().common_words.iter().cloned().collect())
}

// ── en accessors ────────────────────────────────────────────────────────────

/// English given-names pool, sorted (order does not affect matching).
pub fn given_names_en() -> &'static [String] {
    &en_data().given_names
}

/// English surnames pool, sorted (order does not affect matching).
pub fn surnames_en() -> &'static [String] {
    &en_data().surnames
}

/// English given-names as a membership set.
pub fn given_names_en_set() -> &'static HashSet<String> {
    static CELL: OnceLock<HashSet<String>> = OnceLock::new();
    CELL.get_or_init(|| en_data().given_names.iter().cloned().collect())
}

/// English surnames as a membership set.
pub fn surnames_en_set() -> &'static HashSet<String> {
    static CELL: OnceLock<HashSet<String>> = OnceLock::new();
    CELL.get_or_init(|| en_data().surnames.iter().cloned().collect())
}

/// English common-word lexicon (lowercased), sorted. The corroboration signal
/// uses [`common_words_en_set`]; this accessor exposes the raw pool (e.g. for a
/// data-parity / count test) mirroring `given_names_en` / `surnames_en`.
pub fn common_words_en() -> &'static [String] {
    &en_common_words_data().words
}

/// English common-word lexicon as a lowercased membership set. The en person
/// detector's name-like leading-token signal corroborates a bare surname when
/// the leading token's lowercased form is NOT in this set (and it is alphabetic,
/// length >= 2). Entries are authored lowercase in the RON, so membership tests
/// against an `to_ascii_lowercase()`-folded token are direct.
pub fn common_words_en_set() -> &'static HashSet<String> {
    static CELL: OnceLock<HashSet<String>> = OnceLock::new();
    CELL.get_or_init(|| en_common_words_data().words.iter().cloned().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pools_load_with_expected_cardinalities() {
        // Frozen counts mirror the embedded RON pools (see the parity gate
        // `EXPECTED_COUNTS`). The surname pools were grown for non-Anglo recall.
        assert_eq!(surnames_zh().chars().count(), 146);
        assert_eq!(compound_surnames_zh().len(), 16);
        assert_eq!(not_names_zh().len(), 7534);
        assert_eq!(common_words_zh().len(), 31257);
        assert_eq!(given_names_en().len(), 206);
        assert_eq!(surnames_en().len(), 643);
    }

    #[test]
    fn membership_sets_match_pool_lengths() {
        // Pools have no duplicates, so the set sizes equal the list lengths.
        assert_eq!(not_names_zh_set().len(), 7534);
        assert_eq!(common_words_zh_set().len(), 31257);
        assert_eq!(given_names_en_set().len(), 206);
        assert_eq!(surnames_en_set().len(), 643);
    }

    #[test]
    fn spot_members_present() {
        assert!(surnames_zh().starts_with("王李张"));
        assert!(surnames_zh().contains('欧'));
        assert!(compound_surnames_zh().iter().any(|s| s == "欧阳"));
        assert!(compound_surnames_zh().iter().any(|s| s == "司马"));
        assert!(given_names_en_set().contains("James"));
        assert!(given_names_en_set().contains("Mary"));
        assert!(surnames_en_set().contains("Smith"));
        assert!(surnames_en_set().contains("Nguyen"));
    }

    #[test]
    fn en_common_words_lexicon_loads_and_separates_names_from_places() {
        // Non-trivial curated lexicon (place/geo + common words).
        assert!(
            common_words_en().len() >= 600,
            "common_words_en too small: {}",
            common_words_en().len()
        );
        // No duplicates — set size equals the sorted pool length.
        assert_eq!(common_words_en_set().len(), common_words_en().len());
        // Place / common-word leading tokens ARE in the set (signal suppressed):
        for w in ["central", "lake", "park", "the", "new", "hyde"] {
            assert!(common_words_en_set().contains(w), "expected {w:?} in set");
        }
        // Name-like leading tokens are NOT in the set (signal corroborates):
        for w in ["marco", "wei", "mohammed", "aisha", "sanjay", "olga"] {
            assert!(!common_words_en_set().contains(w), "{w:?} must not be a common word");
        }
        // Lexicon is authored lowercase — uppercased forms are absent (membership
        // tests lowercase-fold the token first).
        assert!(!common_words_en_set().contains("Central"));
    }
}
