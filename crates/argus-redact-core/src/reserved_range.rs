//! Reserved-range PII scanner. Single source of truth for the reserved-range
//! patterns; Python consumers read them via `_core.reserved_range_patterns()`.
//!
//! Detects values that fall within the "reserved sub-ranges" used by the
//! realistic faker strategy, so that re-redacting LLM output (which already
//! contains fake values) can be detected and flagged.
//!
//! ## Char offsets
//!
//! `scan_for_pollution` returns `(start, end, type_name)` where `start`/`end`
//! are **character** (Unicode scalar) offsets, matching Python's `m.start()`/
//! `m.end()` on a `str`. Non-ASCII names (e.g. `张三`) therefore have
//! start/end that differ from byte offsets.

use std::collections::HashMap;
use std::sync::OnceLock;

use fancy_regex::Regex;

use crate::fakers::{
    hkid_reserved_letter, macau_reserved_lead, reserved_addresses_en, reserved_cities_zh,
    reserved_person_names_en, reserved_person_names_zh, twarc_reserved_prefix,
    twid_reserved_letter,
};

// ── Pattern builders ─────────────────────────────────────────────────────────

/// Build all reserved-range pattern entries in insertion order (the SSOT).
///
/// `overrides`: optional per-type alternation override. Empty slice → drop that type.
fn build_patterns(overrides: Option<&HashMap<String, Vec<String>>>) -> Vec<(String, String)> {
    // RESERVED_CITIES feeds the zh-address alternation, which derives its own
    // sorted district set (see build_address_zh_alternation).
    let cities = reserved_cities_zh();

    let hkid_letter = hkid_reserved_letter();
    let twid_letter = twid_reserved_letter();
    let macau_lead = macau_reserved_lead();
    let twarc_prefix = twarc_reserved_prefix();

    // Numeric / structural patterns (literals from Python).
    let numeric_patterns: &[(&str, String)] = &[
        // zh
        ("phone_zh", r"(?<!\d)19999\d{6}(?!\d)".to_string()),
        ("phone_landline_zh", r"(?<!\d)099-?\d{8}(?!\d)".to_string()),
        ("id_number_zh", r"(?<!\d)999\d{14}[\dX](?!\d)".to_string()),
        ("bank_card_zh", r"(?<!\d)999999\d{10}(?!\d)".to_string()),
        ("passport_zh", r"(?<![A-Z])[EG]99999\d{3}(?![0-9A-Z])".to_string()),
        (
            "hk_id_zh",
            format!(r"(?<![A-Z]){hkid_letter}\d{{6}}\((?:\d|X)\)"),
        ),
        (
            "tw_id_zh",
            format!(r"(?<![A-Za-z0-9]){twid_letter}\d{{9}}(?!\d)"),
        ),
        (
            "macau_id_zh",
            format!(r"(?<!\d){macau_lead}/\d{{6}}/\d(?!\d)"),
        ),
        (
            "taiwan_arc_zh",
            format!(r"(?<![A-Za-z0-9]){twarc_prefix}\d{{8}}(?!\d)"),
        ),
        ("license_plate_zh", r"[测领][A-Z]99999".to_string()),
    ];

    // Pool-derived patterns.
    let person_zh_pat = escaped_alternation(reserved_person_names_zh());
    let address_zh_pat = build_address_zh_alternation(cities);
    let person_en_pat = escaped_alternation(reserved_person_names_en());
    let address_en_pat = escaped_alternation(reserved_addresses_en());

    // EN-only numeric / structural patterns (RFC 5737 / Hollywood phone range).
    let en_numeric_patterns: &[(&str, &str)] = &[
        ("phone_en", r"\(555\)\s*555-01\d{2}"),
        ("ssn_en", r"(?<!\d)999-\d{2}-\d{4}(?!\d)"),
        ("credit_card_en", r"(?<!\d)999999\d{10}(?!\d)"),
    ];

    // Truly shared patterns (RFC documentation ranges, protocol-level).
    let truly_shared_patterns: &[(&str, &str)] = &[
        ("email_shared", r"@example\.(?:com|org|net)\b"),
        (
            "ipv4_shared",
            r"(?<!\d)(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}(?!\d)",
        ),
        ("ipv6_shared", r"\b2001:db8::[0-9a-fA-F]{1,4}\b"),
        (
            "mac_shared",
            r"(?<![0-9A-Fa-f:])00:00:5E:00:53:[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])",
        ),
    ];

    // Assemble in Python dict insertion order.
    let mut result: Vec<(String, String)> = Vec::new();

    for (name, pat) in numeric_patterns {
        push_with_override(&mut result, name, pat, overrides);
    }

    // person_zh (may be overridden to an alternation of specific names)
    push_with_override(&mut result, "person_zh", &person_zh_pat, overrides);
    // address_zh
    push_with_override(&mut result, "address_zh", &address_zh_pat, overrides);

    for (name, pat) in en_numeric_patterns {
        push_with_override(&mut result, name, pat, overrides);
    }

    // person_en
    push_with_override(&mut result, "person_en", &person_en_pat, overrides);
    // address_en
    push_with_override(&mut result, "address_en", &address_en_pat, overrides);

    for (name, pat) in truly_shared_patterns {
        push_with_override(&mut result, name, pat, overrides);
    }

    result
}

fn push_with_override(
    out: &mut Vec<(String, String)>,
    name: &str,
    default_pat: &str,
    overrides: Option<&HashMap<String, Vec<String>>>,
) {
    if let Some(ov) = overrides {
        if let Some(names) = ov.get(name) {
            if names.is_empty() {
                return; // disabled
            }
            out.push((name.to_string(), escaped_alternation(names)));
            return;
        }
    }
    out.push((name.to_string(), default_pat.to_string()));
}

/// Build `key1|key2|...` from already-ordered keys (escape each + join `|`).
///
/// Does ONLY escape + join — callers must establish their own ordering (e.g.
/// longest-first, insertion order) BEFORE calling, so the produced regex string
/// stays byte-identical. Shared by the reserved-range, restore, and
/// display-marker alternation builders.
pub(crate) fn escaped_alternation<S: AsRef<str>>(ordered_keys: &[S]) -> String {
    ordered_keys
        .iter()
        .map(|k| fancy_regex::escape(k.as_ref()).into_owned())
        .collect::<Vec<_>>()
        .join("|")
}

/// Like `escaped_alternation`, but wraps any **purely-numeric** key (all ASCII
/// digits) with `(?<!\d)…(?!\d)` digit boundaries. This stops a realistic
/// bare-number fake (e.g. a phone-shaped "19999123456") from matching INSIDE a
/// longer digit run ("199991234560") during restore — which would splice a real
/// original into an unrelated number. Mirrors the forward patterns' own digit
/// boundaries.
///
/// Only ALL-DIGIT keys are bounded — deliberately NARROW. Anything with a
/// non-digit char is left unbounded: prefixed pseudonyms ("P-83811") and masked
/// values ("138****5678") routinely abut digits from an adjacent token (e.g.
/// "P-83811138****5678"), so bounding them would break their restore. The
/// narrowness is the safe choice; a digit-bounded numeric fake with inner
/// separators (e.g. a landline "099-12345678") is not bounded, but that is an
/// accepted theoretical gap, not a reproduced leak.
pub(crate) fn escaped_alternation_digit_bounded<S: AsRef<str>>(ordered_keys: &[S]) -> String {
    ordered_keys
        .iter()
        .map(|k| {
            let k = k.as_ref();
            let esc = fancy_regex::escape(k).into_owned();
            let all_digits = !k.is_empty() && k.chars().all(|c| c.is_ascii_digit());
            if all_digits {
                format!(r"(?<!\d){esc}(?!\d)")
            } else {
                esc
            }
        })
        .collect::<Vec<_>>()
        .join("|")
}

/// Build `滨海市(district1|district2|...)` from reserved_cities.
fn build_address_zh_alternation(cities: &[(String, String, Vec<String>)]) -> String {
    // Collect unique districts (sorted), mirror Python `sorted({district ...})`.
    use std::collections::BTreeSet;
    let districts: BTreeSet<&str> = cities.iter().map(|(_, d, _)| d.as_str()).collect();
    let alt = districts
        .iter()
        .map(|d| fancy_regex::escape(d).into_owned())
        .collect::<Vec<_>>()
        .join("|");
    format!(r"滨海市(?:{alt})")
}

/// Build the combined named-group regex string from a pattern list.
fn build_combined_re(patterns: &[(String, String)]) -> String {
    patterns
        .iter()
        .map(|(name, pat)| format!("(?P<{name}>{pat})"))
        .collect::<Vec<_>>()
        .join("|")
}

// ── Default compiled regex (singleton) ───────────────────────────────────────

fn default_combined() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let patterns = build_patterns(None);
        let s = build_combined_re(&patterns);
        Regex::new(&s)
            .unwrap_or_else(|e| panic!("reserved_range: regex compile failed: {e}\nPattern: {s}"))
    })
}

// ── Char-offset helpers ───────────────────────────────────────────────────────

/// Convert a `&str` byte-offset range to char offsets.
///
/// `fancy_regex` (like the Rust `regex` crate) returns byte offsets; Python
/// returns char offsets. For ASCII-only text they're identical. For text with
/// multi-byte chars (e.g. `张三`) we must convert.
/// Amortized byte→char offset conversion for a SEQUENCE of positions.
///
/// The obvious `text[..byte_pos].chars().count()` rescans from byte 0 every
/// time, so converting both ends of every match in a document costs O(n) per
/// conversion — quadratic in the document length once the match count grows
/// with it (the English tokenizer converts two offsets per WORD, so this was
/// the dominant cost on any long English text, not just on match-dense edge
/// cases). The cursor remembers where it last stopped and walks the delta
/// instead, forward or backward, which makes a monotone sweep linear overall and
/// leaves an out-of-order access costing only the distance it actually moved.
///
/// Pure ASCII short-circuits: byte offset == char offset, so nothing is scanned.
pub(crate) struct CharOffsetCursor<'a> {
    text: &'a str,
    ascii: bool,
    byte: usize,
    chars: usize,
}

impl<'a> CharOffsetCursor<'a> {
    pub(crate) fn new(text: &'a str) -> Self {
        CharOffsetCursor { text, ascii: text.is_ascii(), byte: 0, chars: 0 }
    }

    /// The char offset of `byte_pos`, which must be a char boundary of the
    /// `text` this cursor was built from.
    pub(crate) fn char_offset(&mut self, byte_pos: usize) -> usize {
        if self.ascii {
            return byte_pos;
        }
        if byte_pos >= self.byte {
            self.chars += self.text[self.byte..byte_pos].chars().count();
        } else {
            self.chars -= self.text[byte_pos..self.byte].chars().count();
        }
        self.byte = byte_pos;
        self.chars
    }
}

/// Slice `text` by CHAR offsets `[start, end)` (Python `text[start:end]`).
/// Offsets are char indices; the text may hold multi-byte chars, so byte-slicing
/// would be wrong.
pub(crate) fn char_slice(text: &str, start: usize, end: usize) -> String {
    text.chars().skip(start).take(end.saturating_sub(start)).collect()
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Return the canonical `(name, regex)` pattern list — the same set that
/// `scan_for_pollution` uses when called with no overrides.
///
/// This is the single source of truth for all reserved-range patterns; Python
/// consumers should call this instead of maintaining a duplicate dict.
pub fn reserved_range_patterns() -> Vec<(String, String)> {
    build_patterns(None)
}

/// Scan `text` for reserved-range PII values.
///
/// Returns `Vec<(start_char, end_char, type_name)>`, where offsets are
/// **character** (Unicode scalar) indices — matching Python `m.start()`/`m.end()`.
///
/// `overrides` mirrors Python's `reserved_names` parameter: per-type alternation
/// override. `{"person_zh": []}` disables that type; `{"person_zh": ["张三"]}`
/// replaces the pool with only `["张三"]`.
pub fn scan_for_pollution(
    text: &str,
    overrides: Option<&HashMap<String, Vec<String>>>,
) -> Vec<(usize, usize, String)> {
    let re: &Regex = if overrides.is_none() {
        default_combined()
    } else {
        // Build a fresh regex for the overridden set (no caching needed for correctness;
        // callers with hot loops should cache at a higher level).
        return scan_with_overrides(text, overrides.unwrap());
    };

    collect_matches(re, text)
}

fn scan_with_overrides(
    text: &str,
    overrides: &HashMap<String, Vec<String>>,
) -> Vec<(usize, usize, String)> {
    let patterns = build_patterns(Some(overrides));
    if patterns.is_empty() {
        return vec![];
    }
    let s = build_combined_re(&patterns);
    match Regex::new(&s) {
        Ok(re) => collect_matches(&re, text),
        Err(_) => vec![],
    }
}

/// Extract `(start_char, end_char, matched_group_name)` for each match.
///
/// `fancy_regex` doesn't expose a `lastgroup` equivalent, so we iterate the
/// captures and pick the first non-None named group — which is the matched
/// alternative (all others are empty).
fn collect_matches(re: &Regex, text: &str) -> Vec<(usize, usize, String)> {
    let mut results = Vec::new();
    let mut cursor = CharOffsetCursor::new(text);
    let mut search_start = 0;
    while search_start <= text.len() {
        let caps = match re.captures_from_pos(text, search_start) {
            Ok(Some(c)) => c,
            _ => break,
        };
        // The full match span (group 0).
        let m0 = match caps.get(0) {
            Some(m) => m,
            None => break,
        };
        let start_char = cursor.char_offset(m0.start());
        let end_char = cursor.char_offset(m0.end());

        // Find the matched named group (lastgroup equivalent).
        let type_name = re
            .capture_names()
            .flatten()
            .find(|name| caps.name(name).is_some())
            .map(|s| s.to_string());

        if let Some(tname) = type_name {
            results.push((start_char, end_char, tname));
        }

        search_start = if m0.end() > m0.start() {
            m0.end()
        } else {
            m0.start() + 1
        };
    }
    results
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// The naive implementation the cursor replaced, kept as an ORACLE.
    fn naive_char_offset(text: &str, byte_pos: usize) -> usize {
        text[..byte_pos].chars().count()
    }

    #[test]
    fn cursor_matches_the_naive_conversion_on_a_monotone_sweep() {
        let text = "张三 says hi to 李四 at 北京市朝阳区, then emails a@b.io — 完毕";
        let mut cursor = CharOffsetCursor::new(text);
        for (byte_pos, _) in text.char_indices() {
            assert_eq!(cursor.char_offset(byte_pos), naive_char_offset(text, byte_pos));
        }
        assert_eq!(cursor.char_offset(text.len()), text.chars().count());
    }

    #[test]
    fn cursor_walks_backward_correctly() {
        // Call sites reset to byte 0 between patterns/names, and `patterns.rs`
        // shares ONE cursor across every pattern. A forward-only cursor is
        // silently wrong there, not merely slow.
        let text = "李四 a 王五 b 赵六";
        let boundaries: Vec<usize> = text.char_indices().map(|(i, _)| i).collect();
        let mut cursor = CharOffsetCursor::new(text);
        for &b in boundaries.iter().rev() {
            assert_eq!(cursor.char_offset(b), naive_char_offset(text, b));
        }
        // …and interleaved, jumping in both directions.
        for &b in [boundaries[5], boundaries[1], boundaries[7], boundaries[0], boundaries[3]].iter()
        {
            assert_eq!(cursor.char_offset(b), naive_char_offset(text, b));
        }
    }

    #[test]
    fn cursor_ascii_fast_path_is_identity() {
        let text = "plain ascii only, 12345";
        let mut cursor = CharOffsetCursor::new(text);
        for (byte_pos, _) in text.char_indices() {
            assert_eq!(cursor.char_offset(byte_pos), byte_pos);
        }
    }

    #[test]
    fn cursor_repeated_query_of_the_same_position_is_stable() {
        let text = "北京市朝阳区";
        let mut cursor = CharOffsetCursor::new(text);
        assert_eq!(cursor.char_offset(9), 3);
        assert_eq!(cursor.char_offset(9), 3);
        assert_eq!(cursor.char_offset(9), 3);
    }

    #[test]
    fn phone_zh_matches() {
        let hits = scan_for_pollution("call 19999123456 now", None);
        assert!(
            hits.iter().any(|(_, _, t)| t == "phone_zh"),
            "expected phone_zh hit, got: {hits:?}"
        );
    }

    #[test]
    fn email_shared_matches() {
        let hits = scan_for_pollution("send to a@example.com today", None);
        assert!(
            hits.iter().any(|(_, _, t)| t == "email_shared"),
            "expected email_shared hit, got: {hits:?}"
        );
    }

    #[test]
    fn person_zh_matches_zhang_san() {
        let hits = scan_for_pollution("联系张三吧", None);
        assert!(
            hits.iter().any(|(_, _, t)| t == "person_zh"),
            "expected person_zh hit, got: {hits:?}"
        );
    }

    #[test]
    fn person_zh_char_offsets() {
        // "联系张三吧" — 张三 starts at char 2, ends at char 4.
        let hits = scan_for_pollution("联系张三吧", None);
        let hit = hits.iter().find(|(_, _, t)| t == "person_zh").expect("person_zh");
        assert_eq!(hit.0, 2, "start char offset");
        assert_eq!(hit.1, 4, "end char offset");
    }

    #[test]
    fn id_number_zh_matches() {
        let hits = scan_for_pollution("id 999101199003077654 here", None);
        assert!(
            hits.iter().any(|(_, _, t)| t == "id_number_zh"),
            "expected id_number_zh hit, got: {hits:?}"
        );
    }

    #[test]
    fn real_phone_no_match() {
        let hits = scan_for_pollution("call 13912345678 now", None);
        assert!(hits.is_empty(), "expected no hits, got: {hits:?}");
    }

    #[test]
    fn multiple_types_in_one_text() {
        let text = "phone 19999123456 id 999101199003077654 card 9999990000000018";
        let hits = scan_for_pollution(text, None);
        let types: std::collections::HashSet<&str> =
            hits.iter().map(|(_, _, t)| t.as_str()).collect();
        assert!(types.contains("phone_zh"), "{types:?}");
        assert!(types.contains("id_number_zh"), "{types:?}");
        assert!(types.contains("bank_card_zh"), "{types:?}");
    }

    #[test]
    fn override_person_zh_disabled() {
        let mut ov = HashMap::new();
        ov.insert("person_zh".to_string(), vec![]);
        let hits = scan_for_pollution("联系张三吧", Some(&ov));
        assert!(
            hits.iter().all(|(_, _, t)| t != "person_zh"),
            "person_zh should be disabled, got: {hits:?}"
        );
    }

    #[test]
    fn override_person_zh_custom_names() {
        let mut ov = HashMap::new();
        ov.insert("person_zh".to_string(), vec!["虚构甲".to_string()]);
        // "张三" no longer in override list → not matched.
        let hits_zhangsan = scan_for_pollution("联系张三吧", Some(&ov));
        assert!(
            hits_zhangsan.iter().all(|(_, _, t)| t != "person_zh"),
            "张三 should not match with custom override: {hits_zhangsan:?}"
        );
        // "虚构甲" is in the override → should match.
        let hits_custom = scan_for_pollution("找虚构甲吧", Some(&ov));
        assert!(
            hits_custom.iter().any(|(_, _, t)| t == "person_zh"),
            "虚构甲 should match: {hits_custom:?}"
        );
    }

    #[test]
    fn address_zh_matches() {
        let hits = scan_for_pollution("住在滨海市东江区的123号", None);
        assert!(
            hits.iter().any(|(_, _, t)| t == "address_zh"),
            "expected address_zh hit, got: {hits:?}"
        );
    }

    #[test]
    fn phone_en_matches() {
        let hits = scan_for_pollution("call (555) 555-0123", None);
        assert!(
            hits.iter().any(|(_, _, t)| t == "phone_en"),
            "expected phone_en hit, got: {hits:?}"
        );
    }

    #[test]
    fn ipv4_shared_matches() {
        let hits = scan_for_pollution("from 192.0.2.1 to 203.0.113.50", None);
        assert!(
            hits.iter().any(|(_, _, t)| t == "ipv4_shared"),
            "expected ipv4_shared hit, got: {hits:?}"
        );
    }
}
