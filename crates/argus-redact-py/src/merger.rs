use pyo3::prelude::*;

use crate::types::PyPatternMatch;
use argus_redact_core::{
    merge_entities as core_merge, merge_entities_with_text as core_merge_with_text,
    PatternMatch as CorePM,
};

/// Deduplicate overlapping entity spans. Longer spans win; same length → higher confidence wins.
#[pyfunction]
pub fn merge_entities(entities: Vec<PyPatternMatch>) -> Vec<PyPatternMatch> {
    let core: Vec<CorePM> = entities.iter().map(CorePM::from).collect();
    core_merge(core).into_iter().map(PyPatternMatch::from).collect()
}

/// Priority-aware merge: `self_reference` spans win overlaps and split the loser
/// (text-driven trim). Port of the public `pure/merger.merge_entities(entities, text)`.
#[pyfunction]
pub fn merge_entities_with_text(entities: Vec<PyPatternMatch>, text: &str) -> Vec<PyPatternMatch> {
    let core: Vec<CorePM> = entities.iter().map(CorePM::from).collect();
    core_merge_with_text(core, text)
        .into_iter()
        .map(PyPatternMatch::from)
        .collect()
}
