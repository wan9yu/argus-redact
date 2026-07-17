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

/// Reverse grammar rules: `\b{subject} {third}\b` → `{subject} {first-for-subject}`.
///
/// Covers both self-ref subjects that precede a verb: `I` (1st singular) and
/// `we` (1st plural). The copula differs per subject (`I am` vs `we are`);
/// `have`/`do`/`don't` are shared. Other `SELF_REF_PRONOUNS` values (`me`,
/// `my`, `mine`, `myself`, `us`, `our`, `ours`, `ourselves`) are object or
/// possessive forms, never clause subjects preceding these verbs, so no
/// rules are needed for them.
static GRAMMAR_RESTORE_EN: LazyLock<Vec<GrammarRule>> = LazyLock::new(|| {
    // (subject pronoun, third-person verb the forward rule produced, correct
    // first-person verb for that subject)
    const REVERSALS: &[(&str, &str, &str)] = &[
        ("I", "is", "am"),
        ("I", "has", "have"),
        ("I", "does", "do"),
        ("I", "doesn't", "don't"),
        ("we", "is", "are"),
        ("we", "has", "have"),
        ("we", "does", "do"),
        ("we", "doesn't", "don't"),
    ];
    REVERSALS
        .iter()
        .map(|&(subj, third, first)| GrammarRule {
            pattern: Regex::new(&format!(r"\b{} {}\b", subj, third)).unwrap(),
            replacement: format!("{} {}", subj, first),
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
    fn test_restore_grammar_we_is_to_are() {
        // "we" is 1st-person plural: its copula reversal is "are", not "am".
        let result = restore_grammar_en("we is happy");
        assert_eq!(result, "we are happy");
    }

    #[test]
    fn test_restore_we_have() {
        // "have" is shared between "I" and "we" — forward normalization turns
        // both into "has"; the reverse must land back on "have" either way.
        let result = restore_grammar_en("we has a cat");
        assert_eq!(result, "we have a cat");
    }

    #[test]
    fn test_restore_we_do() {
        let result = restore_grammar_en("we does it");
        assert_eq!(result, "we do it");
    }

    #[test]
    fn test_restore_we_dont() {
        let result = restore_grammar_en("we doesn't know");
        assert_eq!(result, "we don't know");
    }

    #[test]
    fn test_restore_we_already_correct_not_overcorrected() {
        // "we are"/"we have" are already correctly conjugated — no reverse
        // rule pattern matches them, so they must pass through unchanged.
        assert_eq!(restore_grammar_en("we are fine"), "we are fine");
        assert_eq!(restore_grammar_en("we have fun"), "we have fun");
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
