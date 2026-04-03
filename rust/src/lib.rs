use pyo3::prelude::*;

mod types;
mod patterns;
mod merger;
mod restore;

/// argus-redact Rust core — high-performance pure functions
#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<types::PatternMatch>()?;
    m.add_function(wrap_pyfunction!(patterns::match_patterns, m)?)?;
    m.add_function(wrap_pyfunction!(merger::merge_entities, m)?)?;
    m.add_function(wrap_pyfunction!(restore::restore, m)?)?;
    Ok(())
}
