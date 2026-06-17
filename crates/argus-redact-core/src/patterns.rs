use std::collections::HashMap;
use std::sync::{Arc, Mutex, LazyLock};

use fancy_regex::Regex;

use crate::reserved_range::byte_to_char_offset;
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

fn get_regex(pattern: &str) -> Result<Arc<Regex>, PatternError> {
    let mut cache = REGEX_CACHE.lock().unwrap();
    if let Some(re) = cache.get(pattern) {
        return Ok(Arc::clone(re));
    }
    let re = Regex::new(pattern).map_err(|e| {
        PatternError(format!("Invalid regex: {e}"))
    })?;
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
fn floor_char_boundary(text: &str, pos: usize) -> usize {
    if pos >= text.len() { return text.len(); }
    let mut i = pos;
    while i > 0 && !text.is_char_boundary(i) { i -= 1; }
    i
}

/// Find the nearest char boundary at or after `pos`.
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
    if text.is_empty() || patterns.is_empty() {
        return Ok(vec![]);
    }

    let mut results: Vec<PatternMatch> = Vec::new();

    for pat in patterns {
        let re = get_regex(&pat.pattern)?;

        // fancy-regex find_iter returns Result<Match>
        let mut search_start = 0;
        while search_start <= text.len() {
            let m = match re.find_from_pos(text, search_start) {
                Ok(Some(m)) => m,
                Ok(None) => break,
                Err(_) => break,
            };

            let mut matched = m.as_str().to_string();
            let mut start = m.start();
            let mut end = m.end();
            search_start = if end > start { end } else { start + 1 };

            if pat.check_context && looks_like_false_positive(text, start, end) {
                continue;
            }

            // Extract named group if specified
            if let Some(ref group_name) = pat.group {
                if let Ok(Some(caps)) = re.captures(&text[m.start()..]) {
                    if let Some(grp) = caps.name(group_name) {
                        matched = grp.as_str().to_string();
                        start = m.start() + grp.start();
                        end = m.start() + grp.end();
                    }
                }
            }

            // Convert byte offsets to char offsets (Python uses char positions)
            let char_start = byte_to_char_offset(text, start);
            let char_end = byte_to_char_offset(text, end);

            let confidence = match pat.validator {
                Some(ref name) => match resolve_validator(name) {
                    Some(f) if !f(&matched) => 0.3, // validator failed → near-miss
                    _ => 1.0,                        // passed, or unknown name (no-op)
                },
                None => 1.0,
            };

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
        // "订单号123" — 订单号 is a FALSE_POSITIVE_PREFIX trigger
        let cfg = PatternConfig { type_: "phone".into(), pattern: r"\d{3}".into(), check_context: true, group: None, validator: None };
        let out = match_patterns("订单号123", &[cfg]).unwrap();
        assert_eq!(out.len(), 0, "订单号 prefix should suppress the match");
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
}
