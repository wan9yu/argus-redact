use pyo3::prelude::*;

use crate::types::PyPatternMatch;
use argus_redact_core::{merge_entities as core_merge, PatternMatch as CorePM};

/// Deduplicate overlapping entity spans. Longer spans win; same length → higher confidence wins.
#[pyfunction]
pub fn merge_entities(entities: Vec<PyPatternMatch>) -> Vec<PyPatternMatch> {
    let core: Vec<CorePM> = entities.iter().map(CorePM::from).collect();
    core_merge(core).into_iter().map(PyPatternMatch::from).collect()
}
