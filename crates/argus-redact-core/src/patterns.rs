use std::collections::HashMap;
use std::sync::{Arc, Mutex, LazyLock};

use fancy_regex::{Regex, RegexBuilder};

use crate::reserved_range::CharOffsetCursor;
use crate::types::PatternMatch;
use crate::validators::resolve_validator;

/// A regex pattern config (binding converts PyDict -> this).
pub struct PatternConfig {
    pub type_: String,
    pub pattern: String,
    pub check_context: bool,
    pub group: Option<String>,
    pub validator: Option<String>,
}

#[derive(Debug)]
pub struct PatternError(pub String);
impl std::fmt::Display for PatternError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", self.0) }
}

// Regex cache — compiled once, reused across calls
static REGEX_CACHE: LazyLock<Mutex<HashMap<String, Arc<Regex>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// fancy-regex backtracking budget per scan. The built-in patterns — including
/// the zh `organization` / `school` alternations — are ~O(N) in the input,
/// which is itself bounded by [`crate::MAX_INPUT_SIZE`] (1 MiB). They are NOT
/// super-linear: there is no catastrophic backtracking. The budget is not a
/// guard against exponential blow-up; it is sized so a SINGLE `find` can scan a
/// full-size no-match (or partial-suffix) CJK region without a false abort.
///
/// Such a scan accumulates many *linear* backtrack steps: at each of ~350K char
/// positions the `{2,12}` prefix tries several lengths before the suffix
/// alternation fails. The atomic suffix groups (`(?>…)`) cut the per-position
/// constant by not re-trying the ordered, longest-first alternation. The
/// worst-case legitimate 1 MiB input (CJK prose with an unterminated suffix
/// fragment) needs ~13M steps measured empirically; this value is ~5× that for
/// headroom across platforms. The library default (1M) aborts such legitimate
/// input. The [`PatternError`] from an exceeded budget is surfaced (fail
/// closed), not silently swallowed, so the finite limit still bounds any future
/// pattern that genuinely misbehaves.
const BACKTRACK_LIMIT: usize = 64_000_000;

fn get_regex(pattern: &str) -> Result<Arc<Regex>, PatternError> {
    let mut cache = REGEX_CACHE.lock().unwrap();
    if let Some(re) = cache.get(pattern) {
        return Ok(Arc::clone(re));
    }
    let re = RegexBuilder::new(pattern)
        .backtrack_limit(BACKTRACK_LIMIT)
        .build()
        .map_err(|e| PatternError(format!("Invalid regex: {e}")))?;
    let arc = Arc::new(re);
    cache.insert(pattern.to_string(), Arc::clone(&arc));
    Ok(arc)
}

// Context words before a number that suggest it's NOT PII
static FALSE_POSITIVE_PREFIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:version|ver|v\.|order\s*#|product\s*code|serial\s*#|isbn|sku|calculate|计算|订单号|编号|版本|序列号)\s*$"
    ).unwrap()
});

// Arithmetic/code context after a number
static FALSE_POSITIVE_SUFFIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*[/\*\+\-=%\^](?:\s*\d)").unwrap()
});

// Context window in characters. Call sites multiply by 3 — the max UTF-8 byte
// length of a char — when widening byte ranges, so the slice covers ≥15 chars.
const CONTEXT_WINDOW: usize = 15;

/// Find the nearest char boundary at or before `pos`.
///
/// Mutation note: the `i > 0` loop guard's `> → >=` survivor is equivalent — index
/// 0 is ALWAYS a char boundary, so `!is_char_boundary(0)` is false and the loop
/// stops at 0 whether the guard tests `i > 0` or `i >= 0` (and the `i -= 1` never
/// underflows). The `i -= 1` body mutated to `+= 1` / `/= 1` makes the loop never
/// reach a lower boundary (it diverges or stalls) → cargo-mutants reports those as
/// TIMEOUT (= caught), and `char_boundary_helpers_on_multibyte` pins the correct
/// direction on HEAD.
fn floor_char_boundary(text: &str, pos: usize) -> usize {
    if pos >= text.len() { return text.len(); }
    let mut i = pos;
    while i > 0 && !text.is_char_boundary(i) { i -= 1; }
    i
}

/// Find the nearest char boundary at or after `pos`.
///
/// Mutation note: the `i < text.len()` guard's `< → <=` survivor is equivalent —
/// `text.len()` is always a char boundary, so the loop stops at `len` either way.
/// The `i += 1` body mutated to `-= 1` / `*= 1` diverges → TIMEOUT (= caught).
fn ceil_char_boundary(text: &str, pos: usize) -> usize {
    if pos >= text.len() { return text.len(); }
    let mut i = pos;
    while i < text.len() && !text.is_char_boundary(i) { i += 1; }
    i
}

fn looks_like_false_positive(text: &str, start: usize, end: usize) -> bool {
    let before_start = floor_char_boundary(text, start.saturating_sub(CONTEXT_WINDOW * 3));
    let start_safe = floor_char_boundary(text, start);
    let before = &text[before_start..start_safe];
    let end_safe = ceil_char_boundary(text, end);
    let after_end = ceil_char_boundary(text, std::cmp::min(end + CONTEXT_WINDOW * 3, text.len()));
    let after = &text[end_safe..after_end];

    FALSE_POSITIVE_PREFIX.is_match(before).unwrap_or(false)
        || FALSE_POSITIVE_SUFFIX.is_match(after).unwrap_or(false)
}

/// Run all regex patterns against text, return sorted matches.
///
/// Each pattern config has: type_, pattern.
/// Optional: check_context (bool), group (str), validator (str).
/// If `validator` names a known validator, it runs inline: a failing value is
/// still returned but tagged `confidence = 0.3` (a near-miss) for the caller to
/// route. Unknown validator names are a no-op (handled by the Python path).
pub fn match_patterns(text: &str, patterns: &[PatternConfig]) -> Result<Vec<PatternMatch>, PatternError> {
    if text.len() > crate::MAX_INPUT_SIZE {
        return Err(PatternError(format!(
            "input too large: {} bytes exceeds MAX_INPUT_SIZE {}",
            text.len(),
            crate::MAX_INPUT_SIZE
        )));
    }
    if text.is_empty() || patterns.is_empty() {
        return Ok(vec![]);
    }

    let mut results: Vec<PatternMatch> = Vec::new();
    // ONE cursor for the whole scan. Matches within a pattern arrive in
    // increasing byte order, and the reset to 0 at the next pattern costs the
    // cursor only the walk back — never a fresh O(n) rescan per match.
    let mut cursor = CharOffsetCursor::new(text);

    for pat in patterns {
        let re = get_regex(&pat.pattern)?;

        // fancy-regex find_iter returns Result<Match>
        let mut search_start = 0;
        while search_start <= text.len() {
            let m = match re.find_from_pos(text, search_start) {
                Ok(Some(m)) => m,
                Ok(None) => break,
                Err(e) => {
                    return Err(PatternError(format!(
                        "pattern scan aborted (backtrack/overflow): {e}"
                    )))
                }
            };

            let mut matched = m.as_str().to_string();
            let mut start = m.start();
            let mut end = m.end();
            // Mutation note: the search-advance comparison/arithmetic here and the
            // group-offset `m.start() + grp.{start,end}()` below have cargo-mutants
            // survivors (cargo-mutants runs only the Rust unit tests). The Rust unit
            // tests `multiple_non_overlapping_matches_advance_correctly` /
            // `named_group_offsets_are_match_relative` cover the common cases, and the
            // remainder (e.g. `end > start` → `end == start`, which re-scans on every
            // multi-match input) is covered end-to-end by the Python detection golden
            // suite — VERIFIED: applying that mutation fails
            // `tests/detection/test_patterns.py::…test_should_sort_by_position_when_multiple_matches`
            // (and 16 others). The `> → >=` / `+ → -` variants that only diverge on
            // ZERO-WIDTH matches are unreachable from the built-in patterns (none can
            // match empty), so they are equivalent for the production pattern set.
            search_start = if end > start { end } else { start + 1 };

            // Extract named group if specified (the validator must see the group text).
            if let Some(ref group_name) = pat.group {
                if let Ok(Some(caps)) = re.captures(&text[m.start()..]) {
                    if let Some(grp) = caps.name(group_name) {
                        matched = grp.as_str().to_string();
                        start = m.start() + grp.start();
                        end = m.start() + grp.end();
                    }
                }
            }

            // Run the validator once (if any): Some(true)=passed, Some(false)=failed, None=no/unknown validator.
            let validator_passed = match pat.validator {
                Some(ref name) => resolve_validator(name).map(|f| f(&matched)),
                None => None,
            };
            let confidence = if validator_passed == Some(false) { 0.3 } else { 1.0 };

            // FALSE_POSITIVE context suppression is skipped ONLY for checksum-validated matches:
            // a Luhn/MOD11-valid value is real PII, not a version/serial, and must not be suppressed
            // by attacker-influenceable surrounding text (a prepended "version"/"计算" or an appended
            // " - 0" used to evade redaction). Non-validated/near-miss matches keep the heuristic,
            // which discriminates e.g. a real IP from a "1.2.3.4" version string.
            if pat.check_context && validator_passed != Some(true) && looks_like_false_positive(text, start, end) {
                continue;
            }

            // Convert byte offsets to char offsets (Python uses char positions)
            let char_start = cursor.char_offset(start);
            let char_end = cursor.char_offset(end);

            results.push(PatternMatch {
                text: matched,
                type_: pat.type_.clone(),
                start: char_start,
                end: char_end,
                confidence,
                layer: 0,
            });
        }
    }

    results.sort_by_key(|r| r.start);
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn matches_and_char_offsets() {
        let cfg = PatternConfig { type_: "phone".into(), pattern: r"\d{3}".into(), check_context: false, group: None, validator: None };
        let out = match_patterns("ab 123 cd", &[cfg]).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].text, "123");
        assert_eq!((out[0].start, out[0].end), (3, 6));
    }
    #[test]
    fn check_context_suppresses_fp() {
        // 订单号 is a FALSE_POSITIVE_PREFIX trigger. With validator: None there is
        // no checksum confirmation, so the FP heuristic applies and the match in
        // this context IS suppressed (the precision guard for format-ambiguous
        // types, e.g. a phone-shaped 订单号 / order number).
        let cfg = PatternConfig { type_: "phone".into(), pattern: r"\d{3}".into(), check_context: true, group: None, validator: None };
        let out = match_patterns("订单号123", &[cfg]).unwrap();
        assert_eq!(out.len(), 0, "订单号 prefix should suppress a no-validator FP match");
    }
    #[test]
    fn check_context_suppresses_near_miss() {
        // 订单号 is a FALSE_POSITIVE_PREFIX trigger. The ssn validator FAILS on
        // "000-..." (invalid area), so this is a confidence-0.3 near-miss — not a
        // checksum-confirmed value — and a near-miss in an FP context IS suppressed.
        let cfg = PatternConfig {
            type_: "ssn".into(), pattern: r"\d{3}-\d{2}-\d{4}".into(),
            check_context: true, group: None, validator: Some("ssn".into()),
        };
        let out = match_patterns("订单号000-12-3456", &[cfg]).unwrap();
        assert_eq!(out.len(), 0, "订单号 prefix should suppress a failing near-miss");
    }
    #[test]
    fn check_context_does_not_suppress_validated_match() {
        // A checksum-validated match (ssn validator PASSES on 123-45-6789) in an FP
        // context is NOT suppressed: attacker-influenceable surrounding text (here a
        // 订单号 prefix) must not evade redaction of a value confirmed real by a validator.
        let cfg = PatternConfig {
            type_: "ssn".into(), pattern: r"\d{3}-\d{2}-\d{4}".into(),
            check_context: true, group: None, validator: Some("ssn".into()),
        };
        let out = match_patterns("订单号123-45-6789", &[cfg]).unwrap();
        assert_eq!(out.len(), 1, "订单号 prefix must NOT suppress a validator-passing match");
        assert_eq!(out[0].confidence, 1.0);
        assert_eq!(out[0].text, "123-45-6789");
    }
    #[test]
    fn validator_failure_becomes_near_miss() {
        // ssn validator: 000 area is invalid → confidence 0.3, still returned
        let cfg = PatternConfig {
            type_: "ssn".into(), pattern: r"\d{3}-\d{2}-\d{4}".into(),
            check_context: false, group: None, validator: Some("ssn".into()),
        };
        let out = match_patterns("x 000-12-3456 y", &[cfg]).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].confidence, 0.3);
    }
    #[test]
    fn validator_pass_keeps_confidence_one() {
        let cfg = PatternConfig {
            type_: "ssn".into(), pattern: r"\d{3}-\d{2}-\d{4}".into(),
            check_context: false, group: None, validator: Some("ssn".into()),
        };
        let out = match_patterns("x 123-45-6789 y", &[cfg]).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].confidence, 1.0);
    }
    #[test]
    fn rejects_oversized_input() {
        let big = "a".repeat(crate::MAX_INPUT_SIZE + 1);
        let pats = vec![PatternConfig {
            type_: "x".into(), pattern: "a".into(), check_context: false, group: None, validator: None,
        }];
        assert!(match_patterns(&big, &pats).is_err());
    }

    // ── Mutation-kill guards (cargo-mutants survivors) ───────────────────────

    #[test]
    fn pattern_error_display_passes_through_message() {
        // PatternError's Display (L22) must render the wrapped message verbatim, not
        // an empty/default string. Mutating the body to `Ok(Default::default())`
        // would format to "" — the assertion on the message text kills it.
        let e = PatternError("boom: bad regex".to_string());
        assert_eq!(format!("{e}"), "boom: bad regex");
        assert!(!format!("{e}").is_empty());
    }

    #[test]
    fn input_at_exact_max_size_is_ok() {
        // L114 `text.len() > MAX_INPUT_SIZE`: a text of EXACTLY MAX bytes must be
        // accepted (strict `>`). `>=` would reject it. 1 MiB of ASCII, a pattern
        // that finds nothing → Ok([]).
        let text = "a".repeat(crate::MAX_INPUT_SIZE);
        let pats = vec![PatternConfig {
            type_: "x".into(), pattern: "Z".into(), check_context: false, group: None, validator: None,
        }];
        let out = match_patterns(&text, &pats).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn empty_text_short_circuits_before_scan() {
        // L121 `text.is_empty() || patterns.is_empty()`: empty text returns [] WITHOUT
        // entering the scan loop. Mutating `||` to `&&` would let an empty text fall
        // through to the loop, where a zero-width pattern (`a*`) matches the empty
        // string at 0..0 and leaks a spurious empty match. HEAD returns [].
        let pats = vec![PatternConfig {
            type_: "x".into(), pattern: "a*".into(), check_context: false, group: None, validator: None,
        }];
        assert!(match_patterns("", &pats).unwrap().is_empty());
        // Symmetric guard: non-empty text + empty pattern list also returns [].
        assert!(match_patterns("abc", &[]).unwrap().is_empty());
    }

    #[test]
    fn multiple_non_overlapping_matches_advance_correctly() {
        // match_patterns search advance (L146 `if end > start { end } else { start+1 }`).
        // Three non-overlapping `\d{3}` matches must all be found, sorted by start,
        // with correct char offsets. A mutated advance (`==`/`+`→`-`/`*`) re-scans,
        // skips, or mis-offsets the later matches.
        let cfg = PatternConfig {
            type_: "num".into(), pattern: r"\d{3}".into(),
            check_context: false, group: None, validator: None,
        };
        let out = match_patterns("a123 b456 c789", &[cfg]).unwrap();
        let got: Vec<(String, usize, usize)> =
            out.iter().map(|m| (m.text.clone(), m.start, m.end)).collect();
        assert_eq!(
            got,
            vec![
                ("123".to_string(), 1, 4),
                ("456".to_string(), 6, 9),
                ("789".to_string(), 11, 14),
            ]
        );
    }

    #[test]
    fn named_group_offsets_are_match_relative() {
        // match_patterns named-group extraction (L153-154 `start = m.start() + grp.start()`).
        // The group `(?P<g>\d+)` inside `#(?P<g>\d+)` must report the GROUP span
        // (the digits), offset from the MATCH start. Mutating the `+` (to `-`/`*`)
        // mis-locates the group span. The `#` ensures match.start != group.start so
        // the offset arithmetic is actually exercised.
        let cfg = PatternConfig {
            type_: "id".into(), pattern: r"#(?P<g>\d+)".into(),
            check_context: false, group: Some("g".into()), validator: None,
        };
        let out = match_patterns("xx #4321 yy", &[cfg]).unwrap();
        assert_eq!(out.len(), 1);
        // The match is "#4321" at 3..8; the group is "4321" at 4..8.
        assert_eq!(out[0].text, "4321");
        assert_eq!((out[0].start, out[0].end), (4, 8));
    }

    #[test]
    fn char_boundary_helpers_on_multibyte() {
        // floor_char_boundary / ceil_char_boundary walk to the nearest UTF-8 char
        // boundary. "中x": 中 is bytes 0..3, x is byte 3. Bytes 1 and 2 are INTERIOR
        // (not boundaries). These pin the loop direction (`-=`/`+=`), the `i > 0` /
        // `i < len` guards, and the early `pos >= len` returns:
        let t = "中x"; // len 4 bytes
        assert_eq!(t.len(), 4);
        // floor: interior byte 1/2 walks DOWN to 0; a real boundary stays put.
        assert_eq!(floor_char_boundary(t, 1), 0);
        assert_eq!(floor_char_boundary(t, 2), 0);
        assert_eq!(floor_char_boundary(t, 3), 3); // boundary (start of 'x')
        assert_eq!(floor_char_boundary(t, 0), 0);
        assert_eq!(floor_char_boundary(t, 99), 4); // pos >= len → len
        // ceil: interior byte 1/2 walks UP to 3 (next boundary).
        assert_eq!(ceil_char_boundary(t, 1), 3);
        assert_eq!(ceil_char_boundary(t, 2), 3);
        assert_eq!(ceil_char_boundary(t, 3), 3); // already a boundary
        assert_eq!(ceil_char_boundary(t, 0), 0);
        assert_eq!(ceil_char_boundary(t, 99), 4); // pos >= len → len
    }

    #[test]
    fn looks_like_false_positive_prefix_and_suffix() {
        // looks_like_false_positive (L94-104): a FALSE_POSITIVE_PREFIX in the BEFORE
        // window OR a FALSE_POSITIVE_SUFFIX in the AFTER window flags a number as a
        // non-PII (version/serial/arithmetic) context. Multi-byte CJK ("版本") in the
        // window also exercises the floor/ceil boundary slicing on non-ASCII.
        //   - prefix "version " before "1.2.3.4" → flagged.
        let t1 = "version 1.2.3.4 rest";
        assert!(looks_like_false_positive(t1, 8, 15)); // "1.2.3.4"
        //   - CJK prefix "版本" before the number → flagged (boundary slicing on CJK).
        let t2 = "版本1234567";
        // "1234567" starts after the two 3-byte CJK chars (byte 6).
        assert!(looks_like_false_positive(t2, 6, 13));
        //   - arithmetic suffix " / 2" after the number → flagged.
        let t3 = "12345 / 2";
        assert!(looks_like_false_positive(t3, 0, 5));
        //   - a plain number in neutral context is NOT flagged.
        assert!(!looks_like_false_positive("call 4155551234 now", 5, 15));
    }

    #[test]
    fn false_positive_before_window_width_is_three_times() {
        // L95 `CONTEXT_WINDOW * 3` sizes the BEFORE window. The prefix pattern is
        // `$`-anchored (matches at the END of `before`), so the window WIDTH decides
        // whether a distant trigger word is still captured. "version" + 25 spaces +
        // "1.2.3.4" places the trigger ~32 chars before the number: inside the `*3`
        // (= 45) window → flagged. Mutating `*` to `+` (15 + 3 = 18) would NARROW the
        // window below 32 and drop the trigger → NOT flagged. (The AFTER-window
        // `* 3` on L99 is, by contrast, equivalent: the suffix pattern is
        // `^`-anchored at the START of `after`, so widening/narrowing its end never
        // changes the match — those survivors cannot be killed by any input.)
        let t = format!("version{}1.2.3.4", " ".repeat(25));
        let numstart = t.find("1.2.3.4").unwrap();
        assert!(looks_like_false_positive(&t, numstart, numstart + 7));
    }
}

