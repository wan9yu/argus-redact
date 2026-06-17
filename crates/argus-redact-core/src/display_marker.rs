//! Display marker module — adds a visible marker after fake values for human display.
//!
//! Mirrors `pure/display_marker.py` verbatim.

use std::sync::LazyLock;

use fancy_regex::Regex;

use crate::reserved_range::escaped_alternation;

/// Default display marker (U+24D5 CIRCLED LATIN SMALL LETTER F).
pub const DEFAULT_DISPLAY_MARKER: &str = "ⓕ";

/// Preset marker names and their corresponding marker strings.
pub const DISPLAY_MARKER_PRESETS: &[(&str, &str)] = &[
    ("circled_f", "ⓕ"),    // default, U+24D5
    ("superscript_s", "ˢ"), // U+02E2
    ("asterisk", "*"),
    ("chinese", "(假)"),
    ("none", ""),
];

/// Characters that may appear in any preset marker label.
///
/// Used by `restore()` to auto-detect and strip known preset markers attached
/// to keys when the caller omitted `display_marker=`. Custom markers (not in
/// DISPLAY_MARKER_PRESETS) are NOT included. Computed once at first access.
pub static PRESET_MARKER_CHARS: LazyLock<Vec<char>> = LazyLock::new(|| {
    let mut chars: Vec<char> = DISPLAY_MARKER_PRESETS
        .iter().flat_map(|(_, v)| v.chars()).filter(|c| *c != '\0').collect();
    let mut seen = std::collections::HashSet::new();
    chars.retain(|c| seen.insert(*c));
    chars
});

/// Resolve a marker preset name or literal string. `None` → default.
pub fn resolve_marker(marker: Option<&str>) -> String {
    match marker {
        None => DEFAULT_DISPLAY_MARKER.to_string(),
        Some(m) => {
            for &(name, value) in DISPLAY_MARKER_PRESETS {
                if name == m {
                    return value.to_string();
                }
            }
            m.to_string()
        }
    }
}

/// Append `marker` after each fake value (element of `key_fakes`) in `text`.
///
/// Idempotent — values already followed by the marker are not double-marked.
/// Uses longest-first alternation to avoid prefix collisions.
pub fn mark_for_display(text: &str, key_fakes: &[String], marker: Option<&str>) -> String {
    let m = resolve_marker(marker);
    if m.is_empty() || key_fakes.is_empty() {
        return text.to_string();
    }

    // Sort longest-first to avoid prefix collisions (e.g. "张" matching inside "张明").
    let mut sorted_fakes: Vec<&str> = key_fakes.iter().map(|s| s.as_str()).collect();
    sorted_fakes.sort_by(|a, b| b.len().cmp(&a.len()));

    let pattern_str = escaped_alternation(&sorted_fakes);

    let re = Regex::new(&pattern_str).expect("display_marker: invalid regex");
    let m_clone = m.clone();

    let mut result = String::with_capacity(text.len() + text.len() / 4);
    let mut last_end = 0;

    for mat in re.find_iter(text) {
        let mat = mat.expect("display_marker: regex error");
        result.push_str(&text[last_end..mat.start()]);
        result.push_str(mat.as_str());
        // Idempotency check: if already followed by the marker, don't add it.
        let after = &text[mat.end()..];
        if !after.starts_with(&m_clone) {
            result.push_str(&m_clone);
        }
        last_end = mat.end();
    }
    result.push_str(&text[last_end..]);
    result
}

/// Remove `marker` from `text`.
pub fn strip_display_markers(text: &str, marker: Option<&str>) -> String {
    let m = resolve_marker(marker);
    if m.is_empty() {
        return text.to_string();
    }
    text.replace(&m, "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_marker_none_gives_default() {
        assert_eq!(resolve_marker(None), "ⓕ");
    }

    #[test]
    fn test_resolve_marker_preset_circled_f() {
        assert_eq!(resolve_marker(Some("circled_f")), "ⓕ");
    }

    #[test]
    fn test_resolve_marker_preset_superscript_s() {
        assert_eq!(resolve_marker(Some("superscript_s")), "ˢ");
    }

    #[test]
    fn test_resolve_marker_preset_asterisk() {
        assert_eq!(resolve_marker(Some("asterisk")), "*");
    }

    #[test]
    fn test_resolve_marker_preset_chinese() {
        assert_eq!(resolve_marker(Some("chinese")), "(假)");
    }

    #[test]
    fn test_resolve_marker_preset_none() {
        assert_eq!(resolve_marker(Some("none")), "");
    }

    #[test]
    fn test_resolve_marker_literal() {
        assert_eq!(resolve_marker(Some("★")), "★");
    }

    #[test]
    fn test_preset_marker_chars_contains_default() {
        let chars = &*PRESET_MARKER_CHARS;
        assert!(chars.contains(&'ⓕ'));
    }

    #[test]
    fn test_preset_marker_chars_contains_all_non_empty() {
        let chars = &*PRESET_MARKER_CHARS;
        // "ⓕ", "ˢ", "*", "(", "假", ")" — all chars from non-empty presets
        assert!(chars.contains(&'ⓕ'));
        assert!(chars.contains(&'ˢ'));
        assert!(chars.contains(&'*'));
    }

    #[test]
    fn test_mark_for_display_basic() {
        let fakes = vec!["P-1".to_string()];
        let result = mark_for_display("call P-1 now", &fakes, None);
        assert_eq!(result, "call P-1ⓕ now");
    }

    #[test]
    fn test_mark_for_display_idempotent() {
        let fakes = vec!["P-1".to_string()];
        let once = mark_for_display("call P-1 now", &fakes, None);
        let twice = mark_for_display(&once, &fakes, None);
        assert_eq!(once, twice, "mark_for_display must be idempotent");
    }

    #[test]
    fn test_mark_for_display_empty_marker() {
        let fakes = vec!["P-1".to_string()];
        let result = mark_for_display("call P-1 now", &fakes, Some("none"));
        assert_eq!(result, "call P-1 now");
    }

    #[test]
    fn test_mark_for_display_empty_fakes() {
        let result = mark_for_display("call P-1 now", &[], None);
        assert_eq!(result, "call P-1 now");
    }

    #[test]
    fn test_strip_display_markers_basic() {
        let result = strip_display_markers("call P-1ⓕ now", None);
        assert_eq!(result, "call P-1 now");
    }

    #[test]
    fn test_strip_display_markers_empty_marker() {
        let result = strip_display_markers("call P-1 now", Some("none"));
        assert_eq!(result, "call P-1 now");
    }

    #[test]
    fn test_strip_round_trip() {
        let fakes = vec!["P-1".to_string()];
        let marked = mark_for_display("call P-1 now", &fakes, None);
        let stripped = strip_display_markers(&marked, None);
        assert_eq!(stripped, "call P-1 now");
    }

    #[test]
    fn test_mark_longest_first_no_prefix_collision() {
        // "张明" should not be matched as "张" + leftover when both are fakes
        let fakes = vec!["张".to_string(), "张明".to_string()];
        let result = mark_for_display("张明 and 张", &fakes, None);
        // "张明" gets marked as one unit, "张" gets marked separately
        assert_eq!(result, "张明ⓕ and 张ⓕ");
    }

    #[test]
    fn test_mark_custom_marker() {
        let fakes = vec!["Alice".to_string()];
        let result = mark_for_display("Hello Alice!", &fakes, Some("asterisk"));
        assert_eq!(result, "Hello Alice*!");
    }

    #[test]
    fn test_strip_custom_marker() {
        let result = strip_display_markers("Hello Alice*!", Some("asterisk"));
        assert_eq!(result, "Hello Alice!");
    }
}
