use pyo3::prelude::*;

mod types;
mod patterns;
mod merger;
mod restore;
mod pseudonym;
mod lang_detect;
mod normalize;

/// argus-redact Rust core — high-performance pure functions over argus-redact-core.
#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<types::PyPatternMatch>()?;
    m.add_function(wrap_pyfunction!(patterns::match_patterns, m)?)?;
    m.add_function(wrap_pyfunction!(patterns::builtin_patterns, m)?)?;
    m.add_function(wrap_pyfunction!(merger::merge_entities, m)?)?;
    m.add_function(wrap_pyfunction!(restore::restore, m)?)?;
    m.add_class::<pseudonym::PyPseudonymGenerator>()?;
    m.add_function(wrap_pyfunction!(lang_detect::detect_languages, m)?)?;
    m.add_function(wrap_pyfunction!(normalize::normalize_text, m)?)?;
    m.add_function(wrap_pyfunction!(normalize::map_spans_to_original, m)?)?;
    Ok(())
}
