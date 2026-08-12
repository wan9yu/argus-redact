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
    py: Python<'_>,
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
    py.detach(|| argus_redact_core::person_zh::detect_person_names(text, &pii, &known, threshold))
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
    py: Python<'_>,
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
    py.detach(|| argus_redact_core::person_en::detect_person_names(text, &pii, &known, threshold))
        .into_iter()
        .map(PyPatternMatch::from)
        .collect()
}

/// Evidence-gate externally-supplied English `person` candidate spans (e.g. L2
/// spaCy NER) through the L1 scorer, SINGLE-SOURCED in
/// `person_en::score_person_candidate`. `candidates` are `(start, end)` CHAR-offset
/// spans into `text`; the returned bool list is positionally aligned with
/// `candidates` — `True` means KEEP (its evidence score `>= threshold`).
///
/// `pii_entities` supply the bare-surname proximity signal (`self_reference`
/// entries are dropped Rust-side); `threshold` defaults to `SCORE_THRESHOLD`
/// (0.8), `None` from Python behaving like that default. This keeps BOTH the
/// title / name-like / proximity scoring AND the keep/drop threshold a single
/// source in Rust — the Python L2 glue only drops the `False`-masked spans, with
/// zero duplicated scoring.
#[pyfunction]
#[pyo3(signature = (text, candidates, pii_entities=None, threshold=None))]
pub fn score_person_candidates_en(
    py: Python<'_>,
    text: &str,
    candidates: Vec<(usize, usize)>,
    pii_entities: Option<Vec<PyPatternMatch>>,
    threshold: Option<f64>,
) -> Vec<bool> {
    let pii: Vec<CorePM> = pii_entities
        .unwrap_or_default()
        .iter()
        .map(CorePM::from)
        .collect();
    let threshold = threshold.unwrap_or(SCORE_THRESHOLD);
    py.detach(|| {
        // Collect the whole-text char slice ONCE and score every candidate span
        // against it, instead of re-materializing `text.chars()` per candidate.
        let text_chars: Vec<char> = text.chars().collect();
        candidates
            .into_iter()
            .map(|(start, end)| {
                argus_redact_core::person_en::score_person_candidate_chars(
                    &text_chars,
                    start,
                    end,
                    &pii,
                ) >= threshold
            })
            .collect()
    })
}
