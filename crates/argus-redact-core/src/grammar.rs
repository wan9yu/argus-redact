//! English grammar normalization for first-person pronoun replacement.
//!
//! Mirrors `pure/grammar.py` verbatim.

use fancy_regex::Regex;
use std::sync::LazyLock;

/// First-person pronouns that trigger grammar normalization.
pub const SELF_REF_PRONOUNS: &[&str] = &[
    "I", "me", "my", "mine", "myself", "we", "us", "our", "ours", "ourselves",
];

/// Returns `true` if `v` is a self-referential English pronoun.
pub fn is_self_ref(v: &str) -> bool {
    SELF_REF_PRONOUNS.contains(&v)
}

// Verb pairs: (first-person form, third-person form)
const VERB_PAIRS: &[(&str, &str)] = &[
    ("am", "is"),
    ("have", "has"),
    ("do", "does"),
    ("don't", "doesn't"),
];

/// Forward grammar rules: pseudonym + first-person verb → third-person verb.
/// Each entry is (compiled pattern, replacement string).
struct GrammarRule {
    pattern: Regex,
    replacement: String,
}

static GRAMMAR_RULES_EN: LazyLock<Vec<GrammarRule>> = LazyLock::new(|| {
    let mut rules = Vec::new();
    // Verb-pair rules: `(\b[A-Z]+-\d+) {first}\b` → `$1 {third}`
    for &(first, third) in VERB_PAIRS {
        rules.push(GrammarRule {
            pattern: Regex::new(&format!(r"(\b[A-Z]+-\d+) {}\b", first)).unwrap(),
            replacement: format!("$1 {}", third),
        });
    }
    // Contraction rules
    rules.push(GrammarRule {
        pattern: Regex::new(r"(\b[A-Z]+-\d+)'m\b").unwrap(),
        replacement: "$1 is".to_string(),
    });
    rules.push(GrammarRule {
        pattern: Regex::new(r"(\b[A-Z]+-\d+)'ve\b").unwrap(),
        replacement: "$1 has".to_string(),
    });
    rules
});

/// Reverse grammar rules: `\bI {third}\b` → `I {first}`.
static GRAMMAR_RESTORE_EN: LazyLock<Vec<GrammarRule>> = LazyLock::new(|| {
    VERB_PAIRS
        .iter()
        .map(|&(first, third)| GrammarRule {
            pattern: Regex::new(&format!(r"\bI {}\b", third)).unwrap(),
            replacement: format!("I {}", first),
        })
        .collect()
});

/// Fix English verb forms after first-person pronoun replacement.
///
/// Applies forward rules only if any value in `key_values` is a self-ref pronoun.
pub fn normalize_grammar_en(text: &str, key_values: &[String]) -> String {
    if !key_values.iter().any(|v| is_self_ref(v)) {
        return text.to_string();
    }
    let mut result = text.to_string();
    for rule in GRAMMAR_RULES_EN.iter() {
        result = rule
            .pattern
            .replace_all(&result, rule.replacement.as_str())
            .into_owned();
    }
    result
}

/// Reverse grammar normalization after restore.
pub fn restore_grammar_en(text: &str) -> String {
    let mut result = text.to_string();
    for rule in GRAMMAR_RESTORE_EN.iter() {
        result = rule
            .pattern
            .replace_all(&result, rule.replacement.as_str())
            .into_owned();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_with_self_ref() {
        let result = normalize_grammar_en("P-1 am happy", &["I".to_string()]);
        assert_eq!(result, "P-1 is happy");
    }

    #[test]
    fn test_normalize_no_self_ref_unchanged() {
        let result = normalize_grammar_en("P-1 am happy", &["Alice".to_string()]);
        assert_eq!(result, "P-1 am happy");
    }

    #[test]
    fn test_normalize_no_key_values_unchanged() {
        let result = normalize_grammar_en("P-1 am happy", &[]);
        assert_eq!(result, "P-1 am happy");
    }

    #[test]
    fn test_restore_grammar() {
        let result = restore_grammar_en("I is happy");
        assert_eq!(result, "I am happy");
    }

    #[test]
    fn test_normalize_contraction_m() {
        let result = normalize_grammar_en("P-1'm here", &["I".to_string()]);
        assert_eq!(result, "P-1 is here");
    }

    #[test]
    fn test_normalize_contraction_ve() {
        let result = normalize_grammar_en("P-1've done it", &["I".to_string()]);
        assert_eq!(result, "P-1 has done it");
    }

    #[test]
    fn test_normalize_have() {
        let result = normalize_grammar_en("P-1 have a cat", &["I".to_string()]);
        assert_eq!(result, "P-1 has a cat");
    }

    #[test]
    fn test_restore_have() {
        let result = restore_grammar_en("I has a cat");
        assert_eq!(result, "I have a cat");
    }

    #[test]
    fn test_normalize_do() {
        let result = normalize_grammar_en("P-1 do it", &["I".to_string()]);
        assert_eq!(result, "P-1 does it");
    }

    #[test]
    fn test_normalize_dont() {
        let result = normalize_grammar_en("P-1 don't know", &["I".to_string()]);
        assert_eq!(result, "P-1 doesn't know");
    }

    #[test]
    fn test_is_self_ref() {
        assert!(is_self_ref("I"));
        assert!(is_self_ref("me"));
        assert!(is_self_ref("we"));
        assert!(!is_self_ref("Alice"));
        assert!(!is_self_ref("i")); // case-sensitive
    }
}
