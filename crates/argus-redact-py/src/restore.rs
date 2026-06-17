use std::collections::HashMap;

use pyo3::prelude::*;

use argus_redact_core::check_restore_safety as core_check_safety;
use argus_redact_core::restore_full as core_restore_full;

/// Restore redacted text by replacing pseudonyms with originals (simple 2-arg form).
/// Kept for back-compat; new callers should prefer `restore` with keyword args.
#[pyfunction]
#[pyo3(signature = (text, key, aliases=None, display_marker=None))]
pub fn restore(
    text: &str,
    key: HashMap<String, String>,
    aliases: Option<HashMap<String, Vec<String>>>,
    display_marker: Option<String>,
) -> PyResult<String> {
    // Route through restore_full when extras are provided (or always, for consistency).
    core_restore_full(
        text,
        &key,
        aliases.as_ref(),
        display_marker.as_deref(),
    )
    .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

/// Check whether LLM output has suspicious pseudonym usage (possible injection).
///
/// Returns a list of warning strings. Empty list = safe.
/// Mirrors `pure/restore.check_restore_safety`.
#[pyfunction]
#[pyo3(signature = (redacted, llm_output, key))]
pub fn check_restore_safety(
    redacted: &str,
    llm_output: &str,
    key: HashMap<String, String>,
) -> Vec<String> {
    core_check_safety(redacted, llm_output, &key)
}
