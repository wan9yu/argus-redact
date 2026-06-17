use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// `_core.resolve_salt` — resolve the effective HMAC salt bytes from the Python
/// salt object (`int | bytes | None`).
///
/// Additive `_core` export delegating to `argus_redact_core::seed::resolve_salt`
/// via the shared `int|bytes|None → Salt` parser. Mirrors
/// `pure/replacer._resolve_salt`: bytes → as-is, int → 8-byte big-endian
/// (signed), `None` → `ARGUS_REDACT_PSEUDONYM_SALT` env var, else `ValueError`.
#[pyfunction]
#[pyo3(signature = (salt=None))]
pub fn resolve_salt<'py>(
    py: Python<'py>,
    salt: Option<&Bound<'py, PyAny>>,
) -> PyResult<Bound<'py, PyBytes>> {
    let parsed = crate::replace::parse_salt(salt)?;
    let bytes = argus_redact_core::seed::resolve_salt(parsed.as_ref())
        .map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &bytes))
}

/// `_core.type_seed_offset` — stable per-type integer offset for seed derivation.
///
/// Additive `_core` export of `argus_redact_core::seed::type_seed_offset`:
/// `SHA256(type_)[:4]` big-endian `% 10_000`. Mirrors
/// `pure/replacer._type_seed_offset` (stable across processes, unlike Python's
/// `hash()`).
#[pyfunction]
pub fn type_seed_offset(type_: &str) -> u32 {
    argus_redact_core::seed::type_seed_offset(type_)
}
