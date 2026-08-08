//! Display marker module — adds a visible marker after fake values for human display.
//!
//! Mirrors `pure/display_marker.py` verbatim.

use std::sync::LazyLock;


use crate::sharded::{Bound, ShardedMatcher};

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

    // The matcher sorts longest-first itself, which is what avoids prefix
    // collisions (e.g. "张" matching inside "张明") — and, because BOTH halves of
    // the mark/strip pair get their ordering from the same constructor, the two
    // can no longer drift apart.
    let matcher = ShardedMatcher::new(key_fakes, Bound::None).expect("display_marker: invalid regex");
    let m_clone = m.clone();

    let mut result = String::with_capacity(text.len() + text.len() / 4);
    let mut last_end = 0;

    for (start, end) in matcher.find_iter(text) {
        result.push_str(&text[last_end..start]);
        result.push_str(&text[start..end]);
        // Idempotency check: if already followed by the marker, don't add it.
        let after = &text[end..];
        if !after.starts_with(&m_clone) {
            result.push_str(&m_clone);
        }
        last_end = end;
    }
    result.push_str(&text[last_end..]);
    result
}

/// Remove `marker` from `text`.
///
/// Global — every occurrence of `marker` anywhere in `text` is removed. Safe
/// only when there is no key to scope against (e.g. an empty-key restore).
/// When a key IS available, use `strip_display_markers_scoped` instead: a
/// marker character can legitimately appear in unrelated text (markdown
/// `**bold**`, a masked value's internal `*`), and a global replace would
/// destroy it.
pub fn strip_display_markers(text: &str, marker: Option<&str>) -> String {
    let m = resolve_marker(marker);
    if m.is_empty() {
        return text.to_string();
    }
    text.replace(&m, "")
}

/// Remove `marker` from `text`, but ONLY where it immediately trails one of
/// `key_fakes` — the exact positions `mark_for_display` would have added it.
///
/// This is the precise inverse of `mark_for_display`: it mirrors the same
/// longest-first fake alternation, so a marker is stripped only right after a
/// matched fake token, never anywhere else in `text`. Unrelated occurrences of
/// the marker character (unconnected markdown, a masked value's internal
/// characters, etc.) are left untouched.
pub fn strip_display_markers_scoped(text: &str, key_fakes: &[String], marker: Option<&str>) -> String {
    let m = resolve_marker(marker);
    if m.is_empty() || key_fakes.is_empty() {
        return text.to_string();
    }

    // Same constructor as mark_for_display, therefore the same longest-first
    // ordering, therefore the same token match at any given position.
    let matcher = ShardedMatcher::new(key_fakes, Bound::None).expect("display_marker: invalid regex");

    let mut result = String::with_capacity(text.len());
    let mut last_end = 0;

    for (_start, end) in matcher.find_iter(text) {
        // Copy everything up to and including the matched fake verbatim — this
        // preserves any marker characters that are part of the fake itself
        // (e.g. a masked value like "138****5678").
        result.push_str(&text[last_end..end]);
        last_end = end;
        // Strip the marker only if it immediately follows this fake match —
        // the one spot mark_for_display would have inserted it.
        let after = &text[last_end..];
        if after.starts_with(&m) {
            last_end += m.len();
        }
    }
    result.push_str(&text[last_end..]);
    result
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

    // ── strip_display_markers_scoped ────────────────────────────────────

    #[test]
    fn test_scoped_strip_preserves_unrelated_asterisks() {
        // Global strip would destroy "**bold**" and mangle the masked value
        // "138****5678". Scoped strip must only remove the marker trailing
        // the key fake, leaving everything else verbatim.
        let fakes = vec!["138****5678".to_string()];
        let text = "See **bold** and note*. Reach 138****5678*";
        let result = strip_display_markers_scoped(text, &fakes, Some("asterisk"));
        assert_eq!(result, "See **bold** and note*. Reach 138****5678");
    }

    #[test]
    fn test_scoped_strip_round_trip_is_inverse_of_mark() {
        let fakes = vec!["P-1".to_string()];
        let marked = mark_for_display("call P-1 now", &fakes, None);
        let stripped = strip_display_markers_scoped(&marked, &fakes, None);
        assert_eq!(stripped, "call P-1 now");
    }

    #[test]
    fn test_scoped_strip_leaves_unrelated_marker_elsewhere() {
        let fakes = vec!["Alice".to_string()];
        let text = "Alice* said *hi* to Bob";
        let result = strip_display_markers_scoped(text, &fakes, Some("asterisk"));
        assert_eq!(result, "Alice said *hi* to Bob");
    }

    #[test]
    fn test_scoped_strip_empty_fakes_is_noop() {
        let result = strip_display_markers_scoped("call P-1* now", &[], Some("asterisk"));
        assert_eq!(result, "call P-1* now");
    }

    #[test]
    fn test_scoped_strip_no_marker_present_is_noop() {
        let fakes = vec!["P-1".to_string()];
        let result = strip_display_markers_scoped("call P-1 now", &fakes, None);
        assert_eq!(result, "call P-1 now");
    }
}
