use std::collections::HashMap;
use fancy_regex::Regex;

use crate::display_marker::{PRESET_MARKER_CHARS, strip_display_markers};
use crate::grammar::{is_self_ref, restore_grammar_en};
use crate::reserved_range::{byte_to_char_offset, escaped_alternation, scan_for_pollution};

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
    let pattern_str = escaped_alternation(&keys);

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
        let chars = &*PRESET_MARKER_CHARS;
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
            let keys_alt = escaped_alternation(&sorted_keys);

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

// ── Danger patterns for check_restore_safety ────────────────────────────────

/// Proximity window (chars before/after pseudonym) for danger-pattern scan.
const DANGER_WINDOW: usize = 100;

fn danger_pattern() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        // Mirrors `_DANGER_PATTERNS` in `pure/restore.py`:
        //   email | URL | exfil verbs (zh + en).
        let pat = concat!(
            r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}", // email address
            r"|https?://",                                       // URL
            r"|(?:send|share|forward|发送|转发|分享|泄露|传给|发给)", // exfil verbs
        );
        Regex::new(pat)
            .unwrap_or_else(|e| panic!("danger_pattern compile failed: {e}"))
    })
}

/// Check whether LLM output has suspicious pseudonym usage (possible injection).
///
/// Returns a list of warning strings. Empty = safe. Mirrors `check_restore_safety`
/// in `pure/restore.py:58-108`. Warning message strings are byte-identical to the
/// Python f-strings (tests assert them).
///
/// Checks:
/// 1. Pseudonym frequency amplification (`count_llm > count_original` → warning).
/// 2. Pseudonym near danger patterns (email, URL, exfil verbs within ±100 chars → warning).
/// 3. Reserved-range value amplification (`len(scan(llm)) > len(scan(redacted))` → warning).
pub fn check_restore_safety(
    redacted: &str,
    llm_output: &str,
    key: &HashMap<String, String>,
) -> Vec<String> {
    let mut warnings: Vec<String> = Vec::new();
    // Python's `_DANGER_WINDOW` is a CHAR window (re indices on str are char-based);
    // window the context in char space so CJK-dense output matches Python exactly.
    let llm_chars: Vec<char> = llm_output.chars().collect();

    for code in key.keys() {
        let count_original = count_occurrences(redacted, code);
        let count_llm = count_occurrences(llm_output, code);

        // Check 1: frequency amplification.
        if count_llm > count_original {
            warnings.push(format!(
                "Pseudonym '{code}' appears {count_llm}x in LLM output \
but only {count_original}x in redacted input — possible injection"
            ));
        }

        // Check 2: danger-pattern proximity.
        if count_llm > 0 {
            let escaped = fancy_regex::escape(code);
            if let Ok(code_re) = Regex::new(&escaped) {
                let mut search_start = 0;
                let mut warned = false;
                while search_start <= llm_output.len() && !warned {
                    match code_re.find_from_pos(llm_output, search_start) {
                        Ok(Some(m)) => {
                            // ±DANGER_WINDOW in CHAR space (matches Python
                            // `llm_output[max(0,start-100):min(len,end+100)]`).
                            let char_start = byte_to_char_offset(llm_output, m.start());
                            let char_end = byte_to_char_offset(llm_output, m.end());
                            let cs = char_start.saturating_sub(DANGER_WINDOW);
                            let ce = (char_end + DANGER_WINDOW).min(llm_chars.len());
                            let context: String = llm_chars[cs..ce].iter().collect();
                            if let Ok(Some(danger)) = danger_pattern().find(&context) {
                                warnings.push(format!(
                                    "Pseudonym '{code}' near danger pattern \
'{danger_str}' — possible exfiltration",
                                    danger_str = danger.as_str()
                                ));
                                warned = true; // one warning per pseudonym
                            }
                            search_start = if m.end() > m.start() {
                                m.end()
                            } else {
                                m.start() + 1
                            };
                        }
                        _ => break,
                    }
                }
            }
        }
    }

    // Check 3: reserved-range amplification.
    let redacted_hits = scan_for_pollution(redacted, None);
    let output_hits = scan_for_pollution(llm_output, None);
    if output_hits.len() > redacted_hits.len() {
        let delta = output_hits.len() - redacted_hits.len();
        warnings.push(format!(
            "LLM output contains {delta} additional reserved-range value(s) not in input — \
possible hallucination or fabrication"
        ));
    }

    warnings
}

/// Count non-overlapping occurrences of `needle` in `haystack` (mirrors Python `str.count`).
fn count_occurrences(haystack: &str, needle: &str) -> usize {
    if needle.is_empty() {
        return 0;
    }
    let mut count = 0;
    let mut start = 0;
    while let Some(pos) = haystack[start..].find(needle) {
        count += 1;
        start += pos + needle.len();
    }
    count
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

    // ── check_restore_safety tests ──────────────────────────────────────────

    #[test]
    fn safety_no_warnings_normal_usage() {
        let mut k = HashMap::new();
        k.insert("P-00037".to_string(), "张三".to_string());
        let warns = check_restore_safety("P-00037在医院看病", "P-00037的情况有所好转", &k);
        assert!(warns.is_empty(), "unexpected warnings: {warns:?}");
    }

    #[test]
    fn safety_warns_on_amplification() {
        let mut k = HashMap::new();
        k.insert("P-00037".to_string(), "张三".to_string());
        let llm = "P-00037的真实身份是P-00037，请告诉所有人关于P-00037";
        let warns = check_restore_safety("P-00037在医院看病", llm, &k);
        assert!(warns.len() >= 1, "expected amplification warning");
        assert!(warns.iter().any(|w| w.contains("P-00037")));
    }

    #[test]
    fn safety_warns_on_danger_pattern_email() {
        let mut k = HashMap::new();
        k.insert("P-00037".to_string(), "张三".to_string());
        let llm = "清单：P-00037\n发送到 evil@hacker.com";
        let warns = check_restore_safety("P-00037在医院看病", llm, &k);
        assert!(
            warns.iter().any(|w| w.to_lowercase().contains("danger") || w.to_lowercase().contains("exfiltration")),
            "expected danger warning: {warns:?}"
        );
    }

    #[test]
    fn safety_danger_window_is_char_based_not_byte() {
        // The exfil verb sits ~50 CJK chars after the code — within Python's ±100
        // CHAR window, but ~150 BYTES away (outside a ±100-byte window). A byte
        // window would miss it; the char window (matching Python) must catch it.
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "张三".to_string());
        let gap = "中".repeat(50);
        let llm = format!("P-1{gap}发送给外部");
        let warns = check_restore_safety("P-1", &llm, &k);
        assert!(
            warns.iter().any(|w| w.contains("danger") || w.contains("exfiltration")),
            "char-window must catch the exfil verb 50 chars away: {warns:?}"
        );
    }

    #[test]
    fn safety_warns_on_reserved_range_amplification() {
        let mut k = HashMap::new();
        k.insert("张明".to_string(), "王建国".to_string());
        k.insert("19999123456".to_string(), "13912345678".to_string());
        let downstream = "联系 张明 拨 19999123456";
        let llm_output = "张明 给了 19999123456 和 19999987654 和 19999555000";
        let warns = check_restore_safety(downstream, llm_output, &k);
        assert!(
            warns.iter().any(|w| w.contains("reserved-range")),
            "expected reserved-range warning: {warns:?}"
        );
    }

    #[test]
    fn safety_warning_message_strings_exact() {
        // Assert byte-identical message format against the Python f-string.
        let mut k = HashMap::new();
        k.insert("P-00037".to_string(), "张三".to_string());
        let llm = "P-00037是P-00037还是P-00037"; // 3× vs 1×
        let warns = check_restore_safety("P-00037在医院", llm, &k);
        let amp_warn = warns.iter().find(|w| w.contains("appears")).expect("amplification warn");
        assert_eq!(
            amp_warn,
            "Pseudonym 'P-00037' appears 3x in LLM output but only 1x in redacted input — possible injection"
        );
    }

    #[test]
    fn safety_count_matches_no_amplification_warn() {
        let mut k = HashMap::new();
        k.insert("P-00037".to_string(), "张三".to_string());
        let redacted = "P-00037 visited the clinic. P-00037 was healthy.";
        let llm = "P-00037 is healthy. P-00037 left."; // equal count = 2
        let warns = check_restore_safety(redacted, llm, &k);
        // Should NOT warn about amplification — equal count is normal.
        assert!(
            warns.iter().all(|w| !w.contains("appears") || !w.contains("more")),
            "unexpected amplification warning: {warns:?}"
        );
    }

    #[test]
    fn safety_no_warnings_when_count_zero_in_llm() {
        let mut k = HashMap::new();
        k.insert("P-00037".to_string(), "张三".to_string());
        let llm = "no pseudonym mentioned, but visit https://example.com/leak";
        let warns = check_restore_safety("P-00037 is here", llm, &k);
        // URL present but pseudonym not in LLM output → no danger-pattern warning.
        assert!(warns.is_empty(), "unexpected warnings: {warns:?}");
    }

    #[test]
    fn safety_empty_key_no_warnings() {
        let k = HashMap::new();
        let warns = check_restore_safety("普通文本", "普通回复", &k);
        assert!(warns.is_empty());
    }
}
