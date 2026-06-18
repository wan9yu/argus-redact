//! Cross-layer hint tables (kinship / command), embedded as RON and parsed once.
//!
//! ## SSOT contract
//!
//! These tables are the aggregated copy of the per-language hint sources
//! (`lang/<code>/hints.py` → `pure/hints.py`'s `_KINSHIP_EXACT`,
//! `_KINSHIP_PREFIXES`, `_COMMAND_PREFIXES`, `_COMMAND_SUFFIXES`,
//! `_COMMAND_PATTERNS`). They are the future single source of truth for the
//! `text_intent` / `self_reference_tier` hint logic. A dropped or changed entry
//! would silently break that logic, so the Python ↔ RON parity is gated by
//! `tests/architecture/test_hints_data_parity.py` (frozen counts + sha256).
//!
//! - The list/set pools (`kinship_exact`, `kinship_prefixes`, `command_prefixes`,
//!   `command_suffixes`) are sorted in the RON for a deterministic file; order
//!   does not affect matching (all consumers use `any(...)` / set membership).
//! - `command_patterns` stores each compiled pattern's source string plus whether
//!   `re.IGNORECASE` was set. The flag is captured per pattern (read from the
//!   Python `re.Pattern.flags`), never assumed — compilation wraps the source in
//!   `(?i:…)` IFF `ignorecase`, mirroring Python's `re.IGNORECASE` semantics.

use std::collections::HashSet;
use std::sync::OnceLock;

use fancy_regex::Regex;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct CommandPattern {
    pattern: String,
    ignorecase: bool,
}

#[derive(Debug, Deserialize)]
struct HintsData {
    kinship_exact: Vec<String>,
    kinship_prefixes: Vec<String>,
    command_prefixes: Vec<String>,
    command_suffixes: Vec<String>,
    command_patterns: Vec<CommandPattern>,
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
embed_ron!(hints_data, HintsData, "../data/hints.ron");

// ── Accessors ────────────────────────────────────────────────────────────────

/// Exact kinship phrases as a membership set (matches `_KINSHIP_EXACT`).
pub fn kinship_exact() -> &'static HashSet<String> {
    static CELL: OnceLock<HashSet<String>> = OnceLock::new();
    CELL.get_or_init(|| hints_data().kinship_exact.iter().cloned().collect())
}

/// Kinship prefixes (sorted; order does not affect `startswith` matching).
pub fn kinship_prefixes() -> &'static [String] {
    &hints_data().kinship_prefixes
}

/// Command-mode prefixes (sorted; order does not affect `startswith` matching).
pub fn command_prefixes() -> &'static [String] {
    &hints_data().command_prefixes
}

/// Command-mode suffixes (sorted; order does not affect `endswith` matching).
pub fn command_suffixes() -> &'static [String] {
    &hints_data().command_suffixes
}

/// Raw command-pattern `(source, ignorecase)` pairs as deserialized from the RON
/// (pre-compilation). Used by the data-parity gate to compare against Python's
/// `[(p.pattern, bool(p.flags & re.IGNORECASE))]` without depending on the
/// compiled-regex wrapping.
pub fn raw_command_patterns() -> &'static [(String, bool)] {
    static CELL: OnceLock<Vec<(String, bool)>> = OnceLock::new();
    CELL.get_or_init(|| {
        hints_data()
            .command_patterns
            .iter()
            .map(|cp| (cp.pattern.clone(), cp.ignorecase))
            .collect()
    })
}

/// Compiled command-mode regexes, built once. Each pattern is wrapped in
/// `(?i:…)` IFF its `ignorecase` flag is set, matching Python `re.IGNORECASE`.
pub fn command_patterns() -> &'static [Regex] {
    static CELL: OnceLock<Vec<Regex>> = OnceLock::new();
    CELL.get_or_init(|| {
        hints_data()
            .command_patterns
            .iter()
            .map(|cp| {
                let src = if cp.ignorecase {
                    format!("(?i:{})", cp.pattern)
                } else {
                    cp.pattern.clone()
                };
                Regex::new(&src).unwrap_or_else(|e| {
                    panic!("invalid command pattern {:?}: {}", cp.pattern, e)
                })
            })
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pools_load_with_expected_cardinalities() {
        // Frozen counts mirror the aggregated pure.hints tables (see parity gate).
        assert_eq!(kinship_exact().len(), 66);
        assert_eq!(kinship_prefixes().len(), 16);
        assert_eq!(command_prefixes().len(), 14);
        assert_eq!(command_suffixes().len(), 12);
        assert_eq!(command_patterns().len(), 5);
    }

    #[test]
    fn spot_members_present() {
        assert!(kinship_exact().contains("我妈"));
        assert!(kinship_exact().contains("我妈妈"));
        assert!(kinship_exact().contains("私の母"));
        assert!(kinship_prefixes().iter().any(|s| s == "my "));
        assert!(command_prefixes().iter().any(|s| s == "帮我"));
        assert!(command_suffixes().iter().any(|s| s == "してください"));
        assert!(!command_patterns().is_empty());
    }

    #[test]
    fn command_patterns_are_case_insensitive() {
        // All current command patterns carry re.IGNORECASE — a mixed-case input
        // should match (proves the (?i:…) wrap took effect).
        let any_match = command_patterns()
            .iter()
            .any(|re| re.is_match("PLEASE help me").unwrap_or(false));
        assert!(any_match);
    }
}
