use pyo3::prelude::*;

mod types;
mod patterns;
mod merger;
mod restore;
mod pseudonym;
mod lang_detect;
mod normalize;
mod grammar;
mod display_marker;
mod reserved_range;
mod replace;

/// argus-redact Rust core — high-performance pure functions over argus-redact-core.
#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<types::PyPatternMatch>()?;
    m.add_function(wrap_pyfunction!(patterns::match_patterns, m)?)?;
    m.add_function(wrap_pyfunction!(patterns::builtin_patterns, m)?)?;
    m.add_function(wrap_pyfunction!(merger::merge_entities, m)?)?;
    m.add_function(wrap_pyfunction!(restore::restore, m)?)?;
    m.add_function(wrap_pyfunction!(restore::check_restore_safety, m)?)?;
    m.add_class::<pseudonym::PyPseudonymGenerator>()?;
    m.add_function(wrap_pyfunction!(lang_detect::detect_languages, m)?)?;
    m.add_function(wrap_pyfunction!(normalize::normalize_text, m)?)?;
    m.add_function(wrap_pyfunction!(normalize::map_spans_to_original, m)?)?;
    m.add_function(wrap_pyfunction!(grammar::normalize_grammar_en, m)?)?;
    m.add_function(wrap_pyfunction!(grammar::restore_grammar_en, m)?)?;
    m.add_function(wrap_pyfunction!(display_marker::mark_for_display, m)?)?;
    m.add_function(wrap_pyfunction!(display_marker::strip_display_markers, m)?)?;
    m.add_function(wrap_pyfunction!(display_marker::resolve_marker, m)?)?;
    m.add_function(wrap_pyfunction!(display_marker::preset_marker_chars, m)?)?;
    m.add_function(wrap_pyfunction!(reserved_range::scan_for_pollution, m)?)?;
    m.add_function(wrap_pyfunction!(replace::replace, m)?)?;
    Ok(())
}
