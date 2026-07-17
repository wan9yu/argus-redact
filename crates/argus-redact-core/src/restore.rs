use std::collections::HashMap;
use fancy_regex::Regex;

use crate::display_marker::strip_display_markers_scoped;
use crate::grammar::{is_self_ref, restore_grammar_en};
use crate::reserved_range::{
    byte_to_char_offset, escaped_alternation_digit_bounded, scan_for_pollution,
};

#[derive(Debug)]
pub struct RestoreError(pub String);
impl std::fmt::Display for RestoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", self.0) }
}

/// Restore redacted text by replacing pseudonyms with originals.
/// Keys sorted by length descending to prevent partial matches.
/// Single-pass replacement prevents re-scanning of replaced content.
pub fn restore(text: &str, key: &HashMap<String, String>) -> Result<String, RestoreError> {
    restore_tracking_self_ref(text, key).map(|(result, _spans)| result)
}

/// Same single-pass substitution as `restore()`, but additionally records the
/// BYTE-offset span (in the OUTPUT string) of every self-referential pronoun
/// value (`is_self_ref`, e.g. "I") it splices in. These spans let
/// `restore_full` scope the reverse grammar fix to just the neighbourhood of
/// an actual pronoun restoration instead of a whole-text pass — see
/// `apply_grammar_scoped`.
///
/// The recorded offsets are exactly the start/end of the pushed replacement
/// text, so they always land on a valid UTF-8 char boundary: no separate
/// byte→char conversion is needed to slice `result` at them later.
fn restore_tracking_self_ref(
    text: &str,
    key: &HashMap<String, String>,
) -> Result<(String, Vec<(usize, usize)>), RestoreError> {
    if key.is_empty() || text.is_empty() {
        return Ok((text.to_string(), Vec::new()));
    }

    // Sort keys by length descending (longest first)
    let mut keys: Vec<&String> = key.keys().collect();
    keys.sort_by(|a, b| b.len().cmp(&a.len()));

    // Build alternation pattern from escaped keys (digit-bounded so a numeric
    // key cannot match inside a longer number).
    let pattern_str = escaped_alternation_digit_bounded(&keys);

    let re = Regex::new(&pattern_str)
        .map_err(|e| RestoreError(format!("Invalid restore pattern: {e}")))?;

    // Single-pass replacement
    let mut result = String::with_capacity(text.len());
    let mut last_end = 0;
    let mut self_ref_spans: Vec<(usize, usize)> = Vec::new();

    let mut search_start = 0;
    while search_start <= text.len() {
        let m = match re.find_from_pos(text, search_start) {
            Ok(Some(m)) => m,
            Ok(None) => break,
            Err(_) => break,
        };

        result.push_str(&text[last_end..m.start()]);
        if let Some(replacement) = key.get(m.as_str()) {
            let span_start = result.len();
            result.push_str(replacement);
            if is_self_ref(replacement) {
                self_ref_spans.push((span_start, result.len()));
            }
        } else {
            result.push_str(m.as_str());
        }
        last_end = m.end();
        search_start = if m.end() > m.start() { m.end() } else { m.start() + 1 };
    }
    result.push_str(&text[last_end..]);

    Ok((result, self_ref_spans))
}

/// Chars to scan past a restored self-ref pronoun for a verb to fix. Covers
/// the longest reverse rule ("I doesn't", 9 chars for the full "I doesn't"
/// phrase) plus slack for the `\b` boundary — generous enough to catch the
/// verb, tight enough to stay well short of an unrelated sentence further along.
const GRAMMAR_FIX_WINDOW_CHARS: usize = 12;

/// Apply `restore_grammar_en` ONLY inside the neighbourhood of each recorded
/// self-ref-pronoun restoration span, leaving the rest of `text` byte-for-byte
/// untouched elsewhere. A whole-text `restore_grammar_en` call would also "fix"
/// an unrelated "I is" that happens to already be in the surrounding text —
/// text this restoration never touched — corrupting it into "I am". Scoping
/// to a window that starts at the restored pronoun and runs a few chars past
/// it avoids that: the fix only ever fires where a pronoun was JUST restored.
///
/// Each span's own window is `[span.start, span.end + GRAMMAR_FIX_WINDOW_CHARS
/// chars]`. When the next span's window OVERLAPS the current accumulated
/// window (its start falls at or before the current window's end), the two
/// windows are MERGED — extended to the max of both windows' ends — rather
/// than the next span being skipped. Skipping would silently drop the
/// grammar fix for a second restoration that lies close to (but isn't fully
/// covered by) an earlier restoration's window: the first window can reach
/// past the second span's start without reaching far enough to cover the
/// second span's own trailing verb. Merging guarantees every restored
/// pronoun's trailing verb is inside some window, each region processed
/// exactly once — no double-application, no corruption, no missed fix.
fn apply_grammar_scoped(text: &str, spans: &[(usize, usize)]) -> String {
    if spans.is_empty() {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    // The current maximal merged window, accumulated across spans whose
    // windows overlap or touch.
    let mut window: Option<(usize, usize)> = None;

    for &(start, end) in spans {
        let this_window_end = advance_chars(text, end, GRAMMAR_FIX_WINDOW_CHARS).min(text.len());
        match window {
            None => window = Some((start, this_window_end)),
            Some((win_start, win_end)) => {
                if start <= win_end {
                    // Overlapping/adjacent: extend the accumulated window
                    // to cover both spans' trailing verbs.
                    window = Some((win_start, win_end.max(this_window_end)));
                } else {
                    // No overlap: flush the finished window, then start a
                    // new one for this span.
                    out.push_str(&text[cursor..win_start]);
                    out.push_str(&restore_grammar_en(&text[win_start..win_end]));
                    cursor = win_end;
                    window = Some((start, this_window_end));
                }
            }
        }
    }
    if let Some((win_start, win_end)) = window {
        out.push_str(&text[cursor..win_start]);
        out.push_str(&restore_grammar_en(&text[win_start..win_end]));
        cursor = win_end;
    }
    out.push_str(&text[cursor..]);
    out
}

/// Advance up to `n_chars` UTF-8 chars past byte offset `from` in `s`,
/// returning the resulting byte offset. Always lands on a char boundary
/// (unlike `from + n_chars`, which would panic or slice mid-character on
/// multi-byte text) — char-safe equivalent of `from + n_chars` bytes.
fn advance_chars(s: &str, from: usize, n_chars: usize) -> usize {
    let mut end = from;
    for (offset, ch) in s[from..].char_indices().take(n_chars) {
        end = from + offset + ch.len_utf8();
    }
    end
}

/// Full restore path: alias merge + core substitution + grammar.
///
/// 1. If `display_marker` is Some → strip that marker from text.
/// 2. If key empty → return text.
/// 3. Alias merge: build flat lookup = key ∪ {alias → key[fake]'s original}.
/// 4. Core substitution (`restore`, single-pass longest-first), tracking the
///    span of every self-ref pronoun value it substitutes in.
/// 5. `restore_grammar_en` runs ONLY in the neighbourhood of those spans (see
///    `apply_grammar_scoped`) — never as a whole-text pass.
///
/// Decoration markers (`ⓕ`, `(假)`, `ˢ`, `*`) need no dedicated pass: a marker
/// trailing a key is ordinary non-key text, so the single `restore` pass leaves
/// it verbatim right after the restored value (e.g. `"P-1ⓕ"` → `"<value>ⓕ"`).
pub fn restore_full(
    text: &str,
    key: &HashMap<String, String>,
    aliases: Option<&HashMap<String, Vec<String>>>,
    display_marker: Option<&str>,
) -> Result<String, RestoreError> {
    // Step 1: strip explicit display marker — scoped to this key's fakes
    // only. A global strip would remove the marker character everywhere in
    // `text`, destroying unrelated content that happens to contain it (e.g.
    // markdown `**bold**`, or a masked value's internal `*`). Scoping to the
    // same longest-first fake alternation `mark_for_display` uses makes the
    // strip land exactly where the mark was added, nowhere else.
    let text_owned: String;
    let text = if let Some(dm) = display_marker {
        let key_fakes: Vec<String> = key.keys().cloned().collect();
        text_owned = strip_display_markers_scoped(text, &key_fakes, Some(dm));
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

    // Step 4: core substitution over the flat lookup.
    //
    // No separate decoration-marker pass runs here. `restore` is a single
    // left-to-right longest-key-match pass that replaces each source span
    // exactly once and advances PAST each replacement (never re-scanning the
    // value it just emitted). A trailing marker is non-key text, so it survives
    // verbatim after the restored value — the same result the old marker pass
    // produced, minus its hazard: that pass wrote `value + markers` into a
    // buffer this scan then re-read, so under a CHAINED key map (a value that is
    // itself another key) the value got replaced a SECOND time — a cross-entity
    // disclosure. Folding the marker handling into the single no-rescan pass
    // closes that double-replace by construction.
    let (result, self_ref_spans) = restore_tracking_self_ref(text, &flat)?;

    // Step 5: grammar restore, scoped to the neighbourhood of each restored
    // self-ref pronoun. `apply_grammar_scoped` is a no-op (returns `result`
    // unchanged) when `self_ref_spans` is empty, i.e. when no key value was a
    // self-ref pronoun OR none of them actually got substituted into `text`.
    let result = apply_grammar_scoped(&result, &self_ref_spans);

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
        // key has value "I" (self-ref) → grammar restore runs on the restored
        // pronoun. Forward normalization would have turned "I am" → "P-1 is",
        // so restoring "P-1 is ok" → "I is ok" → grammar-fixed to "I am ok".
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "I".to_string());
        let result = restore_full("P-1 is ok", &k, None, None).unwrap();
        assert_eq!(result, "I am ok");
    }

    #[test]
    fn full_self_ref_grammar_scoped_not_whole_text() {
        // A global grammar fix would ALSO mangle an
        // unrelated "I is" that this restoration never touched. Only the
        // restored "P-1" → "I" plus its own following verb gets fixed; "The
        // letter I is silent." is untouched text and must survive verbatim.
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "I".to_string());
        let result =
            restore_full("P-1 is here. The letter I is silent.", &k, None, None).unwrap();
        assert_eq!(result, "I am here. The letter I is silent.");
    }

    #[test]
    fn full_two_close_together_self_ref_restorations_both_get_fixed() {
        // Two separate "I" restorations close together: the first grammar
        // window (12 chars past the first restored "I") reaches byte 13 of
        // the output — far enough to cover the *second* restored "I" itself,
        // but NOT its own trailing "is". The old overlap-SKIP logic dropped
        // the second span entirely because its start (12) fell inside the
        // first window's range (< 13), even though that window never
        // actually fixed its verb. Merging windows instead of skipping must
        // fix both restorations' verbs.
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "I".to_string());
        k.insert("P-2".to_string(), "I".to_string());
        let text = format!("P-1 is{}P-2 is right", " ".repeat(8));
        let result = restore_full(&text, &k, None, None).unwrap();
        let expected = format!("I am{}I am right", " ".repeat(8));
        assert_eq!(result, expected);
    }

    #[test]
    fn full_self_ref_no_actual_substitution_leaves_text_unchanged() {
        // The key has a self-ref value, but the redacted-form token ("P-1")
        // never appears in this text — no substitution happens, so the
        // grammar fix must not fire either (nothing was actually restored).
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "I".to_string());
        let result = restore_full("I is ok", &k, None, None).unwrap();
        assert_eq!(result, "I is ok");
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

    #[test]
    fn full_bare_marker_char_does_not_cause_double_replacement() {
        // A bare '(' (a single char of the "(假)" preset) following a key is
        // ordinary non-key text: the single-pass restore must leave it verbatim
        // after the restored value, never treat it as a marker that re-triggers
        // a replacement of the value (which would disclose a DIFFERENT entity's
        // original — a cross-entity leak). key: 张三→李明, 李明→王芳. "张三(经理)"
        // must restore to "李明(经理)" (single-pass-correct), NOT "王芳(经理)".
        let mut k = HashMap::new();
        k.insert("张三".to_string(), "李明".to_string());
        k.insert("李明".to_string(), "王芳".to_string());
        let result = restore_full("张三(经理)", &k, None, None).unwrap();
        assert_eq!(result, "李明(经理)");
    }

    #[test]
    fn full_complete_marker_does_not_cause_chained_double_replacement_zh() {
        // Residual of the bare-char fix: a COMPLETE marker following a key must
        // not let the key be replaced twice under a CHAINED map (where a value
        // emitted for one key is itself another key). key: 张三→李明, 李明→王芳.
        // "张三(假)" must restore to "李明(假)" (single-pass-correct), NOT
        // "王芳(假)" (李明 re-scanned and re-replaced — a cross-entity leak).
        let mut k = HashMap::new();
        k.insert("张三".to_string(), "李明".to_string());
        k.insert("李明".to_string(), "王芳".to_string());
        let result = restore_full("张三(假)", &k, None, None).unwrap();
        assert_eq!(result, "李明(假)");
    }

    #[test]
    fn full_complete_marker_does_not_cause_chained_double_replacement_pseudonym() {
        // Same chained-map double-replace, with the circled-f marker and a
        // pseudonym chain: P-1→P-2, P-2→SECRET. "P-1ⓕ" must restore to "P-2ⓕ"
        // (single-pass-correct), NOT "SECRETⓕ" (P-2 re-scanned and re-replaced).
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "P-2".to_string());
        k.insert("P-2".to_string(), "SECRET".to_string());
        let result = restore_full("P-1ⓕ", &k, None, None).unwrap();
        assert_eq!(result, "P-2ⓕ");
    }

    #[test]
    fn full_complete_chinese_marker_still_stripped_to_value() {
        // The full "(假)" preset marker must still be recognized and preserved
        // after the restored value (proves the fix narrows to whole markers, not
        // that it disables marker handling).
        let mut k = HashMap::new();
        k.insert("P-1".to_string(), "张三".to_string());
        let result = restore_full("call P-1(假) now", &k, None, None).unwrap();
        assert_eq!(result, "call 张三(假) now");
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
    fn safety_reserved_range_delta_in_message() {
        // The reserved-range warning embeds the EXACT count of EXTRA hits
        // (`output_hits - redacted_hits`). Pins the subtraction: input has 1
        // reserved-range value, output has 3 → delta must be reported as 2.
        // A mutant flipping the operands (`redacted - output`) would underflow
        // (panic) or report a wrong delta; a mutant zeroing it would say "0".
        let mut k = HashMap::new();
        k.insert("张明".to_string(), "王建国".to_string());
        k.insert("19999123456".to_string(), "13912345678".to_string());
        let downstream = "联系 张明 拨 19999123456"; // 1 reserved-range value
        let llm = "张明 给了 19999123456 和 19999987654 和 19999555000"; // 3 reserved-range values
        let warns = check_restore_safety(downstream, llm, &k);
        let rr_warn = warns
            .iter()
            .find(|w| w.contains("reserved-range"))
            .expect("reserved-range warning");
        assert_eq!(
            rr_warn,
            "LLM output contains 2 additional reserved-range value(s) not in input — \
possible hallucination or fabrication"
        );
    }

    #[test]
    fn restore_numeric_key_respects_digit_boundary() {
        // A numeric key (e.g. a realistic phone-shaped fake) must not match
        // inside a longer digit run — otherwise restore splices a real original
        // into an unrelated number. key 19999123456→13912345678: the longer
        // token "199991234560" must stay literal, not become "139123456780".
        let mut k = HashMap::new();
        k.insert("19999123456".to_string(), "13912345678".to_string());
        assert_eq!(restore("199991234560", &k).unwrap(), "199991234560");
        // The exact, digit-bounded token still restores normally.
        assert_eq!(
            restore("call 19999123456 now", &k).unwrap(),
            "call 13912345678 now"
        );
    }

    #[test]
    fn restore_repeated_needle_advance() {
        // A repeated needle that exactly tiles the haystack pins the
        // count_occurrences / single-pass advance arithmetic: every "AA" must
        // be replaced, not just the first (an off-by-one in the advance would
        // drop or double-count occurrences). "AAAA" → two "AA" → "XX".
        let mut k = HashMap::new();
        k.insert("AA".to_string(), "X".to_string());
        assert_eq!(restore("AAAA", &k).unwrap(), "XX");
        // And inside surrounding text (advance past the match, not past start).
        assert_eq!(restore("zAAyAAz", &k).unwrap(), "zXyXz");
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
