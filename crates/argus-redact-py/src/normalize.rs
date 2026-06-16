use pyo3::prelude::*;
use argus_redact_core::{normalize_text as core_norm, map_spans_to_original as core_map};

#[pyfunction]
pub fn normalize_text(text: &str) -> (String, Option<Vec<usize>>) {
    core_norm(text)
}

#[pyfunction]
#[pyo3(signature = (spans, offset_map, original_len))]
pub fn map_spans_to_original(
    spans: Vec<(usize, usize)>,
    offset_map: Option<Vec<usize>>,
    original_len: usize,
) -> Vec<(usize, usize)> {
    core_map(&spans, offset_map.as_deref(), original_len)
}
