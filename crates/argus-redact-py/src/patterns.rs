use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use crate::types::PyPatternMatch;
use argus_redact_core::{match_patterns as core_match, PatternConfig};
use argus_redact_core::builtin_patterns as core_builtin;

/// Run all regex patterns against text, return sorted matches.
///
/// Each pattern dict must have: type, pattern.
/// Optional: check_context (bool), group (str).
/// Note: validate callbacks are NOT run here — caller must filter.
#[pyfunction]
#[pyo3(signature = (text, patterns))]
pub fn match_patterns(
    py: Python<'_>,
    text: &str,
    patterns: Vec<Bound<'_, PyDict>>,
) -> PyResult<Vec<PyPatternMatch>> {
    let mut configs = Vec::with_capacity(patterns.len());
    for pat in &patterns {
        let pattern: String = pat
            .get_item("pattern")?
            .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err("pattern"))?
            .extract()?;
        let type_: String = pat
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
        let validator: Option<String> = pat
            .get_item("validator")
            .ok()
            .flatten()
            .and_then(|v| v.extract().ok());
        configs.push(PatternConfig { type_, pattern, check_context, group, validator });
    }

    // The dict extraction above needs the lock; the scan itself does not.
    let out = py
        .detach(|| core_match(text, &configs))
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    Ok(out.into_iter().map(PyPatternMatch::from).collect())
}

/// Return built-in pattern dicts for a language (SSOT in the core crate).
#[pyfunction]
pub fn builtin_patterns(py: Python<'_>, lang: &str) -> PyResult<Py<PyList>> {
    let list = PyList::empty(py);
    for p in core_builtin(lang) {
        let d = PyDict::new(py);
        d.set_item("type", &p.type_)?;
        d.set_item("label", &p.label)?;
        d.set_item("pattern", &p.pattern)?;
        d.set_item("description", &p.description)?;
        if p.check_context { d.set_item("check_context", true)?; }
        if let Some(g) = &p.group { d.set_item("group", g)?; }
        if let Some(v) = &p.validator { d.set_item("validator", v)?; }
        if p.language_neutral { d.set_item("language_neutral", true)?; }
        list.append(d)?;
    }
    Ok(list.into())
}
