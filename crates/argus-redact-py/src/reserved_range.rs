use std::collections::HashMap;

use pyo3::prelude::*;

use argus_redact_core::scan_for_pollution as core_scan;

/// Scan `text` for reserved-range PII values.
///
/// Returns a list of `(start_char, end_char, type_name)` tuples (char offsets).
/// `overrides` is an optional dict mapping type name → list of name strings.
/// Pass `{"person_zh": []}` to disable that type; pass `{"person_zh": ["张三"]}`
/// to replace the pool. Mirrors `pure/reserved_range_scanner.scan_for_pollution`.
#[pyfunction]
#[pyo3(signature = (text, overrides=None))]
pub fn scan_for_pollution(
    text: &str,
    overrides: Option<HashMap<String, Vec<String>>>,
) -> Vec<(usize, usize, String)> {
    core_scan(text, overrides.as_ref())
}
