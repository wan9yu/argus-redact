use std::collections::HashMap;
use std::sync::{Arc, Mutex, LazyLock};

use pyo3::prelude::*;
use pyo3::types::PyDict;
use fancy_regex::Regex;

use crate::types::PatternMatch;

// Regex cache — compiled once, reused across calls
static REGEX_CACHE: LazyLock<Mutex<HashMap<String, Arc<Regex>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn get_regex(pattern: &str) -> PyResult<Arc<Regex>> {
    let mut cache = REGEX_CACHE.lock().unwrap();
    if let Some(re) = cache.get(pattern) {
        return Ok(Arc::clone(re));
    }
    let re = Regex::new(pattern).map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("Invalid regex: {e}"))
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
/// Each pattern dict must have: type, label, pattern.
/// Optional: check_context (bool), group (str).
/// Note: validate callbacks are NOT run here — caller must filter.
#[pyfunction]
#[pyo3(signature = (text, patterns))]
pub fn match_patterns(text: &str, patterns: Vec<Bound<'_, PyDict>>) -> PyResult<Vec<PatternMatch>> {
    if text.is_empty() || patterns.is_empty() {
        return Ok(vec![]);
    }

    let mut results: Vec<PatternMatch> = Vec::new();

    for pat in &patterns {
        let pattern_str: String = pat
            .get_item("pattern")?
            .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err("pattern"))?
            .extract()?;
        let type_str: String = pat
            .get_item("type")?
            .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err("type"))?
            .extract()?;
        let check_context: bool = pat
            .get_item("check_context")
            .ok()
            .flatten()
            .map(|v| v.extract().unwrap_or(false))
            .unwrap_or(false);
        let group: Option<String> = pat
            .get_item("group")
            .ok()
            .flatten()
            .and_then(|v| v.extract().ok());
        let _has_validate: bool = pat
            .get_item("validate")
            .ok()
            .flatten()
            .map(|v| !v.is_none())
            .unwrap_or(false);

        let re = get_regex(&pattern_str)?;

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

            if check_context && looks_like_false_positive(text, start, end) {
                continue;
            }

            // Extract named group if specified
            if let Some(ref group_name) = group {
                if let Ok(Some(caps)) = re.captures(&text[m.start()..]) {
                    if let Some(grp) = caps.name(group_name) {
                        matched = grp.as_str().to_string();
                        start = m.start() + grp.start();
                        end = m.start() + grp.end();
                    }
                }
            }

            // Convert byte offsets to char offsets (Python uses char positions)
            let char_start = text[..start].chars().count();
            let char_end = text[..end].chars().count();

            results.push(PatternMatch {
                text: matched,
                type_: type_str.clone(),
                start: char_start,
                end: char_end,
                confidence: 1.0,
                layer: 0,
            });
        }
    }

    results.sort_by_key(|r| r.start);
    Ok(results)
}
