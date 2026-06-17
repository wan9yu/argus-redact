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
