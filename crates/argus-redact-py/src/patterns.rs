use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::types::PyPatternMatch;
use argus_redact_core::{match_patterns as core_match, PatternConfig};

/// Run all regex patterns against text, return sorted matches.
///
/// Each pattern dict must have: type, pattern.
/// Optional: check_context (bool), group (str).
/// Note: validate callbacks are NOT run here — caller must filter.
#[pyfunction]
#[pyo3(signature = (text, patterns))]
pub fn match_patterns(text: &str, patterns: Vec<Bound<'_, PyDict>>) -> PyResult<Vec<PyPatternMatch>> {
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
        configs.push(PatternConfig { type_, pattern, check_context, group });
    }

    let out = core_match(text, &configs)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    Ok(out.into_iter().map(PyPatternMatch::from).collect())
}
