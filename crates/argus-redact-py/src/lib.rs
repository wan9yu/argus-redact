use pyo3::prelude::*;

mod types;
mod patterns;
mod merger;
mod restore;
mod pseudonym;

/// argus-redact Rust core — high-performance pure functions over argus-redact-core.
#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<types::PyPatternMatch>()?;
    m.add_function(wrap_pyfunction!(patterns::match_patterns, m)?)?;
    m.add_function(wrap_pyfunction!(patterns::builtin_patterns, m)?)?;
    m.add_function(wrap_pyfunction!(merger::merge_entities, m)?)?;
    m.add_function(wrap_pyfunction!(restore::restore, m)?)?;
    m.add_class::<pseudonym::PyPseudonymGenerator>()?;
    Ok(())
}
