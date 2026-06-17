use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::collections::HashSet;

/// `_core.generate_unique_fake` — resolve a built-in faker by name and run the
/// re-roll loop until a unique fake is produced.
///
/// * `faker_name` — one of the registry names accepted by
///   `argus_redact_core::fakers::resolve_faker` (e.g. `"fake_phone_reserved"`).
/// * `value`      — the original PII value being replaced.
/// * `type_`      — entity type label (e.g. `"phone"`), used for seed derivation.
/// * `salt`       — resolved salt bytes (e.g. from `_core.resolve_salt`).
/// * `used`       — set of fakes already in use; the loop re-rolls until the
///   generated fake is not in this set and is not equal to `value`.
///
/// Returns `(fake: str, aliases: list[str])`.
///
/// Raises `ValueError` if `faker_name` is not a known built-in, or if the
/// re-roll loop exhausts its attempt budget.
#[pyfunction]
pub fn generate_unique_fake(
    faker_name: &str,
    value: &str,
    type_: &str,
    salt: &Bound<'_, PyBytes>,
    used: HashSet<String>,
) -> PyResult<(String, Vec<String>)> {
    let faker = argus_redact_core::fakers::resolve_faker(faker_name)
        .ok_or_else(|| PyValueError::new_err(format!("unknown faker: {faker_name}")))?;
    argus_redact_core::fakers::generate_unique_fake(faker, value, type_, salt.as_bytes(), &used)
        .map_err(PyValueError::new_err)
}

/// `_core.builtin_faker_name` — resolve the built-in faker name for a
/// `(type, lang)` pair, or `None` if no built-in faker is registered for it.
///
/// SSOT for built-in faker resolution (transcribed from the
/// `register(PIITypeDef(...))` calls in `specs/{zh,en,shared}.py`). Custom
/// fakers are NOT covered — they are invoked via the `PyFakerFactory` callback.
#[pyfunction]
pub fn builtin_faker_name(type_: &str, lang: &str) -> Option<&'static str> {
    argus_redact_core::fakers::builtin_faker_name(type_, lang)
}

/// `_core.builtin_faker_names` — the set of built-in faker function names (the
/// values produced by [`builtin_faker_name`]) as a Python list. Mirrors the
/// Python `_builtin_faker_names()` name-set.
#[pyfunction]
pub fn builtin_faker_names() -> Vec<&'static str> {
    argus_redact_core::fakers::builtin_faker_names().to_vec()
}
