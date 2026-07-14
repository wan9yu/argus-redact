use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use std::collections::HashSet;

use argus_redact_core::masks::{
    mask_landline as core_mask_landline, mask_name as core_mask_name,
    mask_value as core_mask_value, resolve_collision as core_resolve_collision,
};

/// Apply mask strategy: show `visible_prefix` + `visible_suffix` chars, mask middle.
///
/// Delegates to `argus_redact_core::masks::mask_value`.
/// Per-type defaults (when both visible args are 0): phone(3,4), bank_card(6,4),
/// credit_card(6,4), id_number(4,4), email (special local+@domain rule).
#[pyfunction]
pub fn mask_value(
    value: &str,
    entity_type: &str,
    visible_prefix: usize,
    visible_suffix: usize,
) -> String {
    core_mask_value(value, entity_type, visible_prefix, visible_suffix)
}

/// Chinese name mask: 张* / 李** / 欧阳**.
///
/// Delegates to `argus_redact_core::masks::mask_name`.
#[pyfunction]
pub fn mask_name(value: &str) -> String {
    core_mask_name(value)
}

/// Landline mask: keep area code + last 3 digits, star the middle.
///
/// Delegates to `argus_redact_core::masks::mask_landline`.
#[pyfunction]
pub fn mask_landline(value: &str) -> String {
    core_mask_landline(value)
}

/// Append a circled-digit (or numeric) suffix to avoid label collisions.
///
/// Accepts a Python `set[str]` as `used`; PyO3 extracts it as `HashSet<String>`.
/// Delegates to `argus_redact_core::masks::resolve_collision`. On suffix
/// saturation the core returns `Err`, surfaced here as a catchable `ValueError`
/// (never an uncatchable `PanicException`).
#[pyfunction]
pub fn resolve_collision(label: &str, used: HashSet<String>) -> PyResult<String> {
    core_resolve_collision(label, &used).map_err(PyValueError::new_err)
}
