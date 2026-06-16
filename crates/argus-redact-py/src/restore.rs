use std::collections::HashMap;

use pyo3::prelude::*;

use argus_redact_core::restore as core_restore;
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

/// Low-level 2-argument restore (plain key substitution only, no alias/grammar).
/// Exposed so Python code can call the bare substitution core when needed.
#[pyfunction]
#[pyo3(name = "restore_core", signature = (text, key))]
pub fn restore_core(text: &str, key: HashMap<String, String>) -> PyResult<String> {
    core_restore(text, &key).map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}
