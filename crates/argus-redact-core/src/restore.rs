use std::collections::HashMap;
use fancy_regex::Regex;

use crate::display_marker::{preset_marker_chars, strip_display_markers};
use crate::grammar::{is_self_ref, restore_grammar_en};

#[derive(Debug)]
pub struct RestoreError(pub String);
impl std::fmt::Display for RestoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", self.0) }
}

/// Restore redacted text by replacing pseudonyms with originals.
/// Keys sorted by length descending to prevent partial matches.
/// Single-pass replacement prevents re-scanning of replaced content.
pub fn restore(text: &str, key: &HashMap<String, String>) -> Result<String, RestoreError> {
    if key.is_empty() || text.is_empty() {
        return Ok(text.to_string());
    }

    // Sort keys by length descending (longest first)
    let mut keys: Vec<&String> = key.keys().collect();
    keys.sort_by(|a, b| b.len().cmp(&a.len()));

    // Build alternation pattern from escaped keys
    let escaped: Vec<String> = keys.iter().map(|k| fancy_regex::escape(k).into_owned()).collect();
    let pattern_str = escaped.join("|");

    let re = Regex::new(&pattern_str)
        .map_err(|e| RestoreError(format!("Invalid restore pattern: {e}")))?;

    // Single-pass replacement
    let mut result = String::with_capacity(text.len());
    let mut last_end = 0;

    let mut search_start = 0;
    while search_start <= text.len() {
        let m = match re.find_from_pos(text, search_start) {
            Ok(Some(m)) => m,
            Ok(None) => break,
            Err(_) => break,
        };

        result.push_str(&text[last_end..m.start()]);
        if let Some(replacement) = key.get(m.as_str()) {
            result.push_str(replacement);
        } else {
            result.push_str(m.as_str());
        }
        last_end = m.end();
        search_start = if m.end() > m.start() { m.end() } else { m.start() + 1 };
    }
    result.push_str(&text[last_end..]);

    Ok(result)
}

/// Full restore path: alias merge + decoration-marker inline sub + core substitution + grammar.
///
/// Mirrors `pure/restore.py:restore()` logic (lines 121–205):
/// 1. If `display_marker` is Some → strip that marker from text.
/// 2. If key empty → return text.
/// 3. Alias merge: build flat lookup = key ∪ {alias → key[fake]'s original}.
/// 4. Auto-detect decoration markers (only when display_marker is None): compile
///    `(key_alt)(PRESET_MARKER_CHARS+)`, replace each match with `value + markers`.
/// 5. Core substitution (longest-first).
/// 6. If any key VALUE is self-ref → `restore_grammar_en(result)`.
pub fn restore_full(
    text: &str,
    key: &HashMap<String, String>,
    aliases: Option<&HashMap<String, Vec<String>>>,
    display_marker: Option<&str>,
) -> Result<String, RestoreError> {
    // Step 1: strip explicit display marker.
    let text_owned: String;
    let text = if let Some(dm) = display_marker {
        text_owned = strip_display_markers(text, Some(dm));
        text_owned.as_str()
    } else {
        text
    };

    // Step 2: empty key fast-path.
    if key.is_empty() {
        return Ok(text.to_string());
    }

    // Step 3: alias merge — build flat lookup.
    let flat: HashMap<String, String> = if let Some(alias_map) = aliases {
        let mut m: HashMap<String, String> = key.clone();
        for (fake, alias_list) in alias_map {
            if let Some(original) = key.get(fake) {
                for alias in alias_list {
                    m.entry(alias.clone()).or_insert_with(|| original.clone());
                }
            }
        }
        m
    } else {
        key.clone()
    };

    // Step 4: auto-detect decoration markers (only when display_marker is None).
    let text_owned2: String;
    let text: &str = if display_marker.is_none() {
        let chars = preset_marker_chars();
        if !chars.is_empty() && !flat.is_empty() {
            // Build character class string for preset marker chars.
            let char_class: String = chars
                .iter()
                .map(|c| fancy_regex::escape(&c.to_string()).into_owned())
                .collect::<Vec<_>>()
                .join("");

            // Build longest-first alternation of all flat keys.
            let mut sorted_keys: Vec<&String> = flat.keys().collect();
            sorted_keys.sort_by(|a, b| b.len().cmp(&a.len()));
            let keys_alt = sorted_keys
                .iter()
                .map(|k| fancy_regex::escape(k).into_owned())
                .collect::<Vec<_>>()
                .join("|");

            let pattern_str = format!("({})([{}]+)", keys_alt, char_class);
            match Regex::new(&pattern_str) {
                Ok(re) => {
                    // Replace each match with value + trailing markers.
                    let mut result = String::with_capacity(text.len());
                    let mut last_end = 0;
                    let mut search_start = 0;
                    while search_start <= text.len() {
                        let m = match re.find_from_pos(text, search_start) {
                            Ok(Some(m)) => m,
                            Ok(None) => break,
                            Err(_) => break,
                        };
                        result.push_str(&text[last_end..m.start()]);
                        // Re-run captures to get group 1 and 2.
                        let caps = re.captures(&text[m.start()..]).ok().flatten();
                        if let Some(caps) = caps {
                            let g1 = caps.get(1).map(|c| c.as_str()).unwrap_or("");
                            let g2 = caps.get(2).map(|c| c.as_str()).unwrap_or("");
                            let replacement = flat.get(g1).map(|v| v.as_str()).unwrap_or(g1);
                            result.push_str(replacement);
                            result.push_str(g2);
                        } else {
                            result.push_str(m.as_str());
                        }
                        last_end = m.end();
                        search_start = if m.end() > m.start() { m.end() } else { m.start() + 1 };
                    }
                    result.push_str(&text[last_end..]);
                    text_owned2 = result;
                    text_owned2.as_str()
                }
                Err(_) => text,
            }
        } else {
            text
        }
    } else {
        text
    };

    // Step 5: core substitution over flat lookup.
    let result = restore(text, &flat)?;

    // Step 6: grammar restore if any value is self-ref.
    let result = if key.values().any(|v| is_self_ref(v)) {
        restore_grammar_en(&result)
    } else {
        result
    };

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_key_first() {
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "Alice".to_string());
        k.insert("P-12".to_string(), "Bob".to_string());
        assert_eq!(restore("see P-12 and P-1", &k).unwrap(), "see Bob and Alice");
    }

    #[test]
    fn empty_key_noop() {
        let k = HashMap::new();
        assert_eq!(restore("hello", &k).unwrap(), "hello");
    }

    // ── restore_full tests ──────────────────────────────────────────────

    #[test]
    fn full_basic_round_trip() {
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "张三".to_string());
        let result = restore_full("P-1 ok", &k, None, None).unwrap();
        assert_eq!(result, "张三 ok");
    }

    #[test]
    fn full_alias_maps_to_original() {
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "张三".to_string());
        let mut aliases: HashMap<String, Vec<String>> = HashMap::new();
        aliases.insert("P-1".to_string(), vec!["Zhang San".to_string()]);
        let result = restore_full("Zhang San came home", &k, Some(&aliases), None).unwrap();
        assert_eq!(result, "张三 came home");
    }

    #[test]
    fn full_decoration_marker_preserved() {
        // "P-1ⓕ" → "张三ⓕ" (marker stays attached to restored value)
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "张三".to_string());
        let result = restore_full("call P-1ⓕ now", &k, None, None).unwrap();
        assert_eq!(result, "call 张三ⓕ now");
    }

    #[test]
    fn full_explicit_display_marker_stripped() {
        // When display_marker is passed explicitly, it is stripped rather than preserved.
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "张三".to_string());
        let result = restore_full("call P-1ⓕ now", &k, None, Some("ⓕ")).unwrap();
        assert_eq!(result, "call 张三 now");
    }

    #[test]
    fn full_self_ref_grammar_applied() {
        // key has value "I" (self-ref) → grammar restore runs.
        // Forward normalization would have turned "I am" → "P-1 is",
        // so restore should turn "I is ok" → "I am ok".
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "I".to_string());
        let result = restore_full("I is ok", &k, None, None).unwrap();
        assert_eq!(result, "I am ok");
    }

    #[test]
    fn full_longest_first_no_prefix_corruption() {
        // "张" vs "张明" — longer key must match first.
        let mut k = HashMap::new();
        k.insert("张".to_string(), "Alice".to_string());
        k.insert("张明".to_string(), "Bob".to_string());
        let result = restore_full("张明 and 张", &k, None, None).unwrap();
        assert_eq!(result, "Bob and Alice");
    }

    #[test]
    fn full_empty_key_returns_text_unchanged() {
        let k = HashMap::new();
        let result = restore_full("hello world", &k, None, None).unwrap();
        assert_eq!(result, "hello world");
    }

    #[test]
    fn full_alias_for_absent_fake_silently_skipped() {
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "张三".to_string());
        // alias for a fake NOT in key
        let mut aliases: HashMap<String, Vec<String>> = HashMap::new();
        aliases.insert("P-99".to_string(), vec!["Stranger".to_string()]);
        let result = restore_full("Stranger came by", &k, Some(&aliases), None).unwrap();
        assert_eq!(result, "Stranger came by");
    }
}
