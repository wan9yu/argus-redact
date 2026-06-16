use pyo3::prelude::*;

use argus_redact_core::{
    normalize_grammar_en as core_normalize, restore_grammar_en as core_restore,
};

/// Fix English verb forms after first-person pronoun replacement.
///
/// `key_values` is the list of values from the redaction key dict.
/// If none is a self-referential pronoun, returns `text` unchanged.
#[pyfunction]
pub fn normalize_grammar_en(text: &str, key_values: Vec<String>) -> String {
    core_normalize(text, &key_values)
}

/// Reverse grammar normalization after restore.
#[pyfunction]
pub fn restore_grammar_en(text: &str) -> String {
    core_restore(text)
}
