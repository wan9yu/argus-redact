use pyo3::prelude::*;

use argus_redact_core::{
    mark_for_display as core_mark,
    strip_display_markers as core_strip,
    resolve_marker as core_resolve,
    PRESET_MARKER_CHARS,
};

/// Append `marker` after each fake value (element of `key_fakes`) in `text`.
///
/// Idempotent — values already followed by the marker are not double-marked.
#[pyfunction]
pub fn mark_for_display(text: &str, key_fakes: Vec<String>, marker: Option<String>) -> String {
    core_mark(text, &key_fakes, marker.as_deref())
}

/// Remove `marker` from `text`.
#[pyfunction]
pub fn strip_display_markers(text: &str, marker: Option<String>) -> String {
    core_strip(text, marker.as_deref())
}

/// Resolve a marker preset name or literal string. `None` → default.
#[pyfunction]
pub fn resolve_marker(marker: Option<String>) -> String {
    core_resolve(marker.as_deref())
}

/// Characters that may appear in any preset marker label.
#[pyfunction]
pub fn preset_marker_chars() -> Vec<char> {
    PRESET_MARKER_CHARS.clone()
}
