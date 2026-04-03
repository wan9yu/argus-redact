use pyo3::prelude::*;

mod types;
mod patterns;

/// argus-redact Rust core — high-performance pure functions
#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<types::PatternMatch>()?;
    m.add_function(wrap_pyfunction!(patterns::match_patterns, m)?)?;
    Ok(())
}
