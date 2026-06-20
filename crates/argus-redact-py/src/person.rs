use pyo3::prelude::*;

use crate::types::PyPatternMatch;
use argus_redact_core::{PatternMatch as CorePM, SCORE_THRESHOLD};

/// Detect zh person names. Mirrors `lang.zh.person.detect_person_names`.
///
/// `pii_entities` feeds the proximity / self_reference signals (start/end/type
/// read by the scorer). `known_names` get confidence 1.0. `threshold` defaults
/// to `SCORE_THRESHOLD` (0.8). `None` from Python behaves like the Python
/// detector's default (empty slice / 0.8).
#[pyfunction]
#[pyo3(signature = (text, pii_entities=None, known_names=None, threshold=None))]
pub fn detect_person_names_zh(
    text: &str,
    pii_entities: Option<Vec<PyPatternMatch>>,
    known_names: Option<Vec<String>>,
    threshold: Option<f64>,
) -> Vec<PyPatternMatch> {
    let pii: Vec<CorePM> = pii_entities
        .unwrap_or_default()
        .iter()
        .map(CorePM::from)
        .collect();
    let known = known_names.unwrap_or_default();
    let threshold = threshold.unwrap_or(SCORE_THRESHOLD);
    argus_redact_core::person_zh::detect_person_names(text, &pii, &known, threshold)
        .into_iter()
        .map(PyPatternMatch::from)
        .collect()
}

/// Detect en person names. Mirrors `lang.en.person.detect_person_names`.
///
/// Param order mirrors `detect_person_names_zh`: `pii_entities` feeds the
/// bare-surname proximity gate, `known_names` get confidence 1.0, `threshold`
/// defaults to `SCORE_THRESHOLD` (0.8). `None` from Python behaves like the
/// detector's default (empty slice / 0.8).
#[pyfunction]
#[pyo3(signature = (text, pii_entities=None, known_names=None, threshold=None))]
pub fn detect_person_names_en(
    text: &str,
    pii_entities: Option<Vec<PyPatternMatch>>,
    known_names: Option<Vec<String>>,
    threshold: Option<f64>,
) -> Vec<PyPatternMatch> {
    let pii: Vec<CorePM> = pii_entities
        .unwrap_or_default()
        .iter()
        .map(CorePM::from)
        .collect();
    let known = known_names.unwrap_or_default();
    let threshold = threshold.unwrap_or(SCORE_THRESHOLD);
    argus_redact_core::person_en::detect_person_names(text, &pii, &known, threshold)
        .into_iter()
        .map(PyPatternMatch::from)
        .collect()
}
