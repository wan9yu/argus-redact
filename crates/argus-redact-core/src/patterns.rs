use std::collections::HashMap;
use std::sync::{Arc, Mutex, LazyLock};

use fancy_regex::{Regex, RegexBuilder};

use crate::cancel::{poll_abort, CancelFlag, DetectError};
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

// ── Structural pre-filter ────────────────────────────────────────────────────
//
// A pattern that begins or ends with a *negative boundary lookaround* (e.g. the
// checksum/structured-ID patterns `(?<!\d)…(?!\d)`) forces fancy-regex onto its
// backtracking VM for the WHOLE scan, which has no literal/class prefilter and so
// re-tests every byte position — ~15× slower than the (non-fancy) regex fast path
// on a no-match haystack. Since these patterns cross-load into every language
// (`language_neutral`), that per-position cost is paid on every scan even when the
// text has no candidate at all.
//
// A negative lookaround is a zero-width assertion; consuming ONE char that
// satisfies the same class — or the string edge via `^`/`$` — is an EXACT
// existence-equivalent. So `(?<!\d)BODY(?!\d)` becomes `(?:^|\D)BODY(?:\D|$)`,
// which contains no lookaround and takes the fast path. The rewrite is used ONLY
// as a gate: it is a *necessary condition* for the original to match, so
//   * prefilter finds nothing  ⇒  original matches nothing  ⇒  skip the pattern;
//   * prefilter finds something ⇒  fall through to the EXACT original scan.
// The emitted matches therefore never change — this only elides scans that were
// provably going to find nothing.
//
// The tables list only single-class boundary tokens (longest first, so
// `strip_prefix`/`strip_suffix` picks the most specific). A pattern whose affix
// isn't listed — or whose body still holds a lookaround after the affix is peeled
// — gets no prefilter and scans exactly as before.
const LEADING_LOOKBEHINDS: &[(&str, &str)] = &[
    (r"(?<![A-Za-z0-9])", r"(?:^|[^A-Za-z0-9])"),
    (r"(?<![0-9A-Fa-f:.-])", r"(?:^|[^0-9A-Fa-f:.-])"),
    (r"(?<![A-Z0-9])", r"(?:^|[^A-Z0-9])"),
    (r"(?<![A-Za-z])", r"(?:^|[^A-Za-z])"),
    (r"(?<![:\w])", r"(?:^|[^:\w])"),
    (r"(?<![A-Z])", r"(?:^|[^A-Z])"),
    (r"(?<!\d)", r"(?:^|\D)"),
    (r"(?<!\w)", r"(?:^|\W)"),
];
const TRAILING_LOOKAHEADS: &[(&str, &str)] = &[
    (r"(?![A-Za-z0-9])", r"(?:[^A-Za-z0-9]|$)"),
    (r"(?![0-9A-Fa-f:.-])", r"(?:[^0-9A-Fa-f:.-]|$)"),
    (r"(?![A-Z0-9])", r"(?:[^A-Z0-9]|$)"),
    (r"(?![A-Za-z])", r"(?:[^A-Za-z]|$)"),
    (r"(?!\d)", r"(?:\D|$)"),
    (r"(?!\w)", r"(?:\W|$)"),
];

/// Rewrite a boundary-lookaround pattern into an equivalent lookaround-free
/// existence gate, or `None` if the pattern has no recognized boundary affix, its
/// body still contains a lookaround (the gate would gain nothing), or peeling the
/// affix leaves an empty body.
fn prefilter_source(pattern: &str) -> Option<String> {
    let mut body = pattern;
    let mut prefix = "";
    for (tok, repl) in LEADING_LOOKBEHINDS {
        if let Some(rest) = body.strip_prefix(tok) {
            body = rest;
            prefix = repl;
            break;
        }
    }
    let mut suffix = "";
    for (tok, repl) in TRAILING_LOOKAHEADS {
        if let Some(rest) = body.strip_suffix(tok) {
            body = rest;
            suffix = repl;
            break;
        }
    }
    if (prefix.is_empty() && suffix.is_empty()) || body.is_empty() {
        return None;
    }
    // A lookaround still inside the body would keep the gate on the slow path.
    // (`(?<name>` named groups and `(?:`/`(?P<` are fine — only the assertions
    // `(?<!`, `(?<=`, `(?=`, `(?!` disqualify.)
    if body.contains("(?<!")
        || body.contains("(?<=")
        || body.contains("(?=")
        || body.contains("(?!")
    {
        return None;
    }
    Some(format!("{prefix}{body}{suffix}"))
}

// Prefilter regexes, compiled once and reused. `None` = this pattern has no
// (worthwhile) prefilter; cached too, so the rewrite is attempted only once.
static PREFILTER_CACHE: LazyLock<Mutex<HashMap<String, Option<Arc<Regex>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn get_prefilter(pattern: &str) -> Option<Arc<Regex>> {
    if let Some(entry) = PREFILTER_CACHE.lock().unwrap().get(pattern) {
        return entry.clone();
    }
    let built = prefilter_source(pattern).and_then(|src| {
        RegexBuilder::new(&src)
            .backtrack_limit(BACKTRACK_LIMIT)
            .build()
            .ok()
            .map(Arc::new)
    });
    PREFILTER_CACHE
        .lock()
        .unwrap()
        .insert(pattern.to_string(), built.clone());
    built
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
    // Never-cancel wrapper: `cancel = None` makes the loop-top poll a no-op, so the
    // output is byte-identical to the pre-cancellation scan. The `Aborted` arm is
    // therefore unreachable — the poll can only fire when a flag is present.
    match match_patterns_impl(text, patterns, true, None) {
        Ok(v) => Ok(v),
        Err(DetectError::Pattern(e)) => Err(e),
        Err(DetectError::Aborted) => {
            unreachable!("match_patterns passes cancel=None; the abort poll cannot fire")
        }
    }
}

/// Cancellable base scan. Identical to [`match_patterns`] but polls the supplied
/// [`CancelFlag`] at the top of each pattern's scan; a tripped flag returns
/// [`DetectError::Aborted`]. `cancel = None` is exactly [`match_patterns`]'s
/// behaviour (a no-op poll), and the error carries a `Pattern(_)` for every scan
/// error. Threaded through `detect_l1_cancellable`'s base scan and fan-out.
pub fn match_patterns_cancellable(
    text: &str,
    patterns: &[PatternConfig],
    cancel: Option<&CancelFlag>,
) -> Result<Vec<PatternMatch>, DetectError> {
    match_patterns_impl(text, patterns, true, cancel)
}

/// Inner scan. `use_prefilter` gates the structural pre-filter skip; production
/// always passes `true`. The differential tests pass `false` to obtain the
/// prefilter-free reference and assert the two are byte-identical. `cancel` is the
/// cooperative-cancellation signal (`None` = never cancel — the poll is a no-op).
fn match_patterns_impl(
    text: &str,
    patterns: &[PatternConfig],
    use_prefilter: bool,
    cancel: Option<&CancelFlag>,
) -> Result<Vec<PatternMatch>, DetectError> {
    if text.len() > crate::MAX_INPUT_SIZE {
        return Err(PatternError(format!(
            "input too large: {} bytes exceeds MAX_INPUT_SIZE {}",
            text.len(),
            crate::MAX_INPUT_SIZE
        ))
        .into());
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
        // Cooperative-cancellation poll, ABOVE the prefilter block so a
        // prefilter-skipped pattern is still a poll boundary. Err-only: a tripped
        // flag returns `Err(DetectError::Aborted)`, never a partial `Ok`.
        poll_abort!(cancel);

        // Cheap structural pre-filter (see `prefilter_source`): a lookaround-free
        // necessary condition. A miss proves the original cannot match anywhere in
        // `text`, so skip it; a hit (or no prefilter) falls through to the exact
        // original scan below, so emitted matches are byte-identical. An `Err` from
        // the prefilter is never used to skip (fail open to the real scan).
        if use_prefilter {
            if let Some(pf) = get_prefilter(&pat.pattern) {
                if matches!(pf.find(text), Ok(None)) {
                    continue;
                }
            }
        }

        let re = get_regex(&pat.pattern)?;

        // ONE `captures_from_pos` yields BOTH the whole-match span (group 0) and
        // any named group, in ABSOLUTE offsets — so a grouped pattern needs no
        // second `captures` run over a match-relative slice and no `m.start() +`
        // rebasing (mirrors `reserved_range::collect_matches`). Using group 0's
        // span keeps the whole-match search advance byte-identical to the old
        // `find_from_pos`; the leftmost match at/after `search_start` is the same
        // either way, capture groups only add the group offsets.
        let mut search_start = 0;
        while search_start <= text.len() {
            let caps = match re.captures_from_pos(text, search_start) {
                Ok(Some(c)) => c,
                Ok(None) => break,
                Err(e) => {
                    return Err(PatternError(format!(
                        "pattern scan aborted (backtrack/overflow): {e}"
                    ))
                    .into())
                }
            };
            // Group 0 is the whole match — always present on a successful capture.
            let m0 = caps.get(0).expect("capture group 0 present on every match");

            let mut matched = m0.as_str().to_string();
            let mut start = m0.start();
            let mut end = m0.end();
            // Advance from the FULL-match span (group 0), BEFORE the named-group
            // narrowing below overwrites start/end — same order as the old code.
            //
            // Mutation note: this search-advance comparison/arithmetic has
            // cargo-mutants survivors (cargo-mutants runs only the Rust unit tests).
            // `multiple_non_overlapping_matches_advance_correctly` covers the common
            // case; the remainder (e.g. `end > start` → `end == start`, which
            // re-scans on every multi-match input) is covered end-to-end by the
            // Python detection golden suite — VERIFIED: applying that mutation fails
            // `tests/detection/test_patterns.py::…test_should_sort_by_position_when_multiple_matches`
            // (and 16 others). The `> → >=` / `+ → -` variants that only diverge on
            // ZERO-WIDTH matches are unreachable from the built-in patterns (none can
            // match empty), so they are equivalent for the production pattern set.
            search_start = if end > start { end } else { start + 1 };

            // Narrow to the named group if specified (the validator must see the
            // group text). Its offsets are ABSOLUTE, so no rebasing —
            // `named_group_offsets_are_match_relative` pins the resulting span.
            if let Some(ref group_name) = pat.group {
                if let Some(grp) = caps.name(group_name) {
                    matched = grp.as_str().to_string();
                    start = grp.start();
                    end = grp.end();
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

    // ── Structural prefilter ─────────────────────────────────────────────────

    #[test]
    fn prefilter_source_rewrites_known_boundary_affixes() {
        // The four language-neutral checksum/structured-ID patterns all rewrite to
        // a lookaround-free equivalent gate.
        assert_eq!(
            prefilter_source(r"(?<!\d)\d{3}\.?\d{3}\.?\d{3}-?\d{2}(?!\d)").as_deref(),
            Some(r"(?:^|\D)\d{3}\.?\d{3}\.?\d{3}-?\d{2}(?:\D|$)")
        );
        assert_eq!(
            prefilter_source(r"(?<![A-Za-z])[A-Z]{5}\d{4}[A-Z](?![A-Za-z])").as_deref(),
            Some(r"(?:^|[^A-Za-z])[A-Z]{5}\d{4}[A-Z](?:[^A-Za-z]|$)")
        );
        // Leading-only and trailing-only are both valid.
        assert_eq!(
            prefilter_source(r"(?<!\d)\d{11}").as_deref(),
            Some(r"(?:^|\D)\d{11}")
        );
        assert_eq!(
            prefilter_source(r"\d{4}-\d{4}(?!\d)").as_deref(),
            Some(r"\d{4}-\d{4}(?:\D|$)")
        );
    }

    #[test]
    fn prefilter_source_declines_when_not_worthwhile() {
        // No boundary affix at all → no gate.
        assert_eq!(prefilter_source(r"\d{3}-\d{4}"), None);
        // A lookaround still in the body would keep the gate on the slow path → decline.
        assert_eq!(prefilter_source(r"(?<!\d)foo(?=bar)baz(?!\d)"), None);
        assert_eq!(prefilter_source(r"(?<!\d)(?<=x)\d{4}(?!\d)"), None);
        // A named group in the body is NOT a lookaround and must not disqualify.
        assert!(prefilter_source(r"(?<!\d)(?P<g>\d{4})(?!\d)").is_some());
        // Peeling the affix must leave a non-empty body.
        assert_eq!(prefilter_source(r"(?<!\d)"), None);
    }

    /// Deterministic reference: run the scan with the prefilter DISABLED.
    fn reference(text: &str, pats: &[PatternConfig]) -> Vec<(String, String, usize, usize, f64)> {
        match_patterns_impl(text, pats, false, None)
            .unwrap()
            .into_iter()
            .map(|m| (m.type_, m.text, m.start, m.end, m.confidence))
            .collect()
    }

    /// Same, prefilter ENABLED (production path).
    fn gated(text: &str, pats: &[PatternConfig]) -> Vec<(String, String, usize, usize, f64)> {
        match_patterns_impl(text, pats, true, None)
            .unwrap()
            .into_iter()
            .map(|m| (m.type_, m.text, m.start, m.end, m.confidence))
            .collect()
    }

    fn all_builtin_configs() -> Vec<PatternConfig> {
        let mut out = Vec::new();
        for lang in ["shared", "zh", "en", "ja", "ko", "de", "uk", "in", "br"] {
            for p in crate::data::builtin_patterns(lang) {
                out.push(PatternConfig {
                    type_: p.type_.clone(),
                    pattern: p.pattern.clone(),
                    check_context: p.check_context,
                    group: p.group.clone(),
                    validator: p.validator.clone(),
                });
            }
        }
        out
    }

    #[test]
    fn prefilter_is_byte_identical_on_boundary_edge_cases() {
        // Cases chosen to stress every way a boundary gate could diverge from the
        // original: exact-length IDs, over-long runs (gate must still skip), IDs at
        // string start/end (the ^/$ arm), IDs flanked by digits/letters, separated
        // forms, and two structured IDs back to back sharing a boundary.
        let pats = all_builtin_configs();
        let cases = [
            "",
            "no pii here at all",
            "529.982.247-25",                       // valid CPF, bare
            "CPF 529.982.247-25 end",               // CPF mid-string
            "52998224725",                          // valid CPF, no separators
            "5299822472599999",                     // CPF digits inside a longer run
            "11.222.333/0001-81",                   // valid CNPJ
            "1234 5678 9018",                       // valid My Number
            "123456789012345678",                   // 18-digit run (id-shaped, over-long for cpf/cnpj/my)
            "4111111111111111",                     // 16-digit card
            "ABCPD1234E",                           // valid PAN, bare
            "xABCPD1234Ex",                         // PAN flanked by letters (must NOT match)
            "529.982.247-2511.222.333/0001-81",     // two IDs adjacent
            "客户手机13812345678，身份证110101199003074610",
            "version 1.2.3.4 order 000-12-3456",    // FP-context + failing SSN near-miss
        ];
        for text in cases {
            assert_eq!(
                gated(text, &pats),
                reference(text, &pats),
                "prefilter diverged on {text:?}"
            );
        }
    }

    #[test]
    fn prefilter_is_byte_identical_on_randomized_inputs() {
        // A deterministic LCG produces strings over an alphabet rich in the bytes the
        // boundary patterns care about (digits, upper/lower letters, the ID
        // separators, and a CJK char), so many candidate spans and boundaries arise.
        // The prefilter-gated scan must equal the prefilter-free reference on every
        // one — any divergence means the gate changed detection output.
        let pats = all_builtin_configs();
        let alphabet: Vec<char> =
            "0123456789ABCDEFabcdef .-/:XYZ王".chars().collect();
        let mut state: u64 = 0x9E3779B97F4A7C15;
        let mut next = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (state >> 33) as usize
        };
        for _ in 0..1500 {
            let len = next() % 40;
            let s: String = (0..len).map(|_| alphabet[next() % alphabet.len()]).collect();
            assert_eq!(
                gated(&s, &pats),
                reference(&s, &pats),
                "prefilter diverged on random input {s:?}"
            );
        }
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

    // ── Cooperative cancellation (base scan) ─────────────────────────────────

    #[test]
    fn match_patterns_cancellable_none_equals_match_patterns() {
        // cancel = None must be byte-identical to the never-cancel wrapper.
        let cfg = || PatternConfig {
            type_: "num".into(),
            pattern: r"\d{3}".into(),
            check_context: false,
            group: None,
            validator: None,
        };
        let text = "a123 b456 c789";
        let a = match_patterns(text, &[cfg()]).unwrap();
        let b = match_patterns_cancellable(text, &[cfg()], None).unwrap();
        let key = |m: &PatternMatch| (m.text.clone(), m.start, m.end, m.confidence);
        assert_eq!(
            a.iter().map(key).collect::<Vec<_>>(),
            b.iter().map(key).collect::<Vec<_>>()
        );
    }

    #[test]
    fn match_patterns_cancellable_untripped_flag_is_byte_identical() {
        // A present-but-untripped flag changes nothing.
        let cfg = PatternConfig {
            type_: "num".into(),
            pattern: r"\d{3}".into(),
            check_context: false,
            group: None,
            validator: None,
        };
        let flag = CancelFlag::new();
        let out = match_patterns_cancellable("a123 b456", &[cfg], Some(&flag)).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].text, "123");
        assert_eq!(out[1].text, "456");
    }

    #[test]
    fn match_patterns_cancellable_pre_tripped_aborts_before_any_match() {
        // A pre-tripped flag aborts at the top of the first pattern's scan — before
        // any match is assembled — so the result is Err(Aborted), never Ok(partial).
        let cfg = PatternConfig {
            type_: "num".into(),
            pattern: r"\d{3}".into(),
            check_context: false,
            group: None,
            validator: None,
        };
        let flag = CancelFlag::new();
        flag.cancel();
        let out = match_patterns_cancellable("a123 b456 c789", &[cfg], Some(&flag));
        assert!(matches!(out, Err(DetectError::Aborted)));
    }
}

