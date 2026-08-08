use std::collections::HashMap;

use pyo3::prelude::*;

use argus_redact_core::reserved_range_patterns as core_reserved_range_patterns;
use argus_redact_core::scan_for_pollution as core_scan;

/// Return the canonical `(name, regex)` pattern list used by the reserved-range scanner.
///
/// This is the Rust SSOT for all reserved-range patterns. Python consumers should
/// call this instead of maintaining a duplicate `_RESERVED_RANGE_PATTERNS` dict.
///
/// Returns a list of `(name, regex)` tuples in canonical insertion order.
#[pyfunction]
pub fn reserved_range_patterns() -> Vec<(String, String)> {
    core_reserved_range_patterns()
}

/// Scan `text` for reserved-range PII values.
///
/// Returns a list of `(start_char, end_char, type_name)` tuples (char offsets).
/// `overrides` is an optional dict mapping type name → list of name strings.
/// Pass `{"person_zh": []}` to disable that type; pass `{"person_zh": ["张三"]}`
/// to replace the pool. Mirrors `pure/reserved_range_scanner.scan_for_pollution`.
#[pyfunction]
#[pyo3(signature = (text, overrides=None))]
pub fn scan_for_pollution(
    py: Python<'_>,
    text: &str,
    overrides: Option<HashMap<String, Vec<String>>>,
) -> Vec<(usize, usize, String)> {
    py.detach(|| core_scan(text, overrides.as_ref()))
}
