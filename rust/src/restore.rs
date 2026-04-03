use std::collections::HashMap;
use pyo3::prelude::*;
use fancy_regex::Regex;

/// Restore redacted text by replacing pseudonyms with originals.
/// Keys sorted by length descending to prevent partial matches.
/// Single-pass replacement prevents re-scanning of replaced content.
#[pyfunction]
#[pyo3(signature = (text, key))]
pub fn restore(text: &str, key: HashMap<String, String>) -> PyResult<String> {
    if key.is_empty() || text.is_empty() {
        return Ok(text.to_string());
    }

    // Sort keys by length descending (longest first)
    let mut keys: Vec<&String> = key.keys().collect();
    keys.sort_by(|a, b| b.len().cmp(&a.len()));

    // Build alternation pattern from escaped keys
    let escaped: Vec<String> = keys.iter().map(|k| fancy_regex::escape(k).into_owned()).collect();
    let pattern_str = escaped.join("|");

    let re = Regex::new(&pattern_str).map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("Invalid restore pattern: {e}"))
    })?;

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
