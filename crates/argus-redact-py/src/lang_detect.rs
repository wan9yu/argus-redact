use pyo3::prelude::*;
use argus_redact_core::detect_languages as core_detect;

#[pyfunction]
pub fn detect_languages(text: &str) -> Vec<String> {
    core_detect(text)
}
