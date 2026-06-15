use std::collections::HashMap;

use pyo3::prelude::*;

use argus_redact_core::restore as core_restore;

/// Restore redacted text by replacing pseudonyms with originals.
#[pyfunction]
#[pyo3(signature = (text, key))]
pub fn restore(text: &str, key: HashMap<String, String>) -> PyResult<String> {
    core_restore(text, &key).map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}
