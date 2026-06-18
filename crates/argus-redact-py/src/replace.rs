use std::collections::{HashMap, HashSet};

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

use argus_redact_core::replace::{
    replace as core_replace, FakerFactory, FakerResolution, PseudoFactory, ReplaceArgs, TypeInfo,
};
use argus_redact_core::seed::Salt;
use argus_redact_core::PatternMatch as CorePM;

use crate::pseudonym::PyRandomSource;
use crate::shake_rng::PyShakeRng;
use crate::types::PyPatternMatch;

/// Factory minting [`PyRandomSource`] per (prefix, seed). Mirrors how
/// `PyPseudonymGenerator::new` builds its source so the `replace` orchestrator's
/// pseudonym generators reproduce the exact same Mersenne-Twister stream,
/// preserving the frozen `P-NNNNN` codes.
pub(crate) struct PyPseudoFactory;

impl PseudoFactory for PyPseudoFactory {
    type Source = PyRandomSource;
    fn make(&self, seed: Option<u64>) -> PyRandomSource {
        PyRandomSource::for_seed(seed)
    }
}

/// Looks up the registered custom Python `faker_reserved` callable by type and
/// invokes it with a `_core.ShakeRng` built from the attempt's master_key. The
/// re-roll loop lives in core; this produces one `(fake, aliases)` per call.
///
/// Matches the Python signature `faker_reserved(value, rng) -> (str, list[str])`
/// (`pure/replacer.py`), so the `_core.ShakeRng` hands the callable the same
/// deterministic SHAKE stream the Rust engine uses for built-in fakers.
pub(crate) struct PyFakerFactory {
    /// type name -> Python callable.
    pub(crate) fakers: HashMap<String, Py<PyAny>>,
}

impl FakerFactory for PyFakerFactory {
    fn call_faker(
        &self,
        type_: &str,
        value: &str,
        master_key: &[u8],
    ) -> Result<(String, Vec<String>), String> {
        let faker = self
            .fakers
            .get(type_)
            .ok_or_else(|| format!("no custom faker registered for type '{type_}'"))?;
        Python::attach(|py| {
            let rng = Bound::new(py, PyShakeRng::new_from_bytes(master_key))
                .map_err(|e| e.to_string())?;
            let res = faker
                .bind(py)
                .call1((value, rng))
                .map_err(|e| e.to_string())?;
            let (fake, aliases): (String, Vec<String>) = res
                .extract()
                .map_err(|e| format!("faker_reserved must return (str, list[str]): {e}"))?;
            Ok((fake, aliases))
        })
    }
}

/// Parse the Python salt object (`int | bytes | None`) into a core [`Salt`].
pub(crate) fn parse_salt(salt: Option<&Bound<'_, PyAny>>) -> PyResult<Option<Salt>> {
    match salt {
        None => Ok(None),
        Some(obj) => {
            if obj.is_none() {
                return Ok(None);
            }
            if let Ok(b) = obj.cast::<PyBytes>() {
                return Ok(Some(Salt::Bytes(b.as_bytes().to_vec())));
            }
            if let Ok(b) = obj.cast::<pyo3::types::PyByteArray>() {
                return Ok(Some(Salt::Bytes(b.to_vec())));
            }
            // `bool` is an int subclass in Python; checking int last is fine
            // since salt is documented as int|bytes|None.
            if let Ok(i) = obj.extract::<i64>() {
                return Ok(Some(Salt::Int(i)));
            }
            Err(pyo3::exceptions::PyTypeError::new_err(
                "salt must be int, bytes, or None",
            ))
        }
    }
}

/// Parse one per-type info dict into a [`TypeInfo`].
fn parse_type_info(d: &Bound<'_, PyDict>) -> PyResult<TypeInfo> {
    let get_str = |k: &str| -> Option<String> {
        d.get_item(k)
            .ok()
            .flatten()
            .and_then(|v| if v.is_none() { None } else { v.extract::<String>().ok() })
    };
    let get_bool = |k: &str| -> bool {
        d.get_item(k)
            .ok()
            .flatten()
            .and_then(|v| v.extract::<bool>().ok())
            .unwrap_or(false)
    };
    let get_usize = |k: &str| -> usize {
        d.get_item(k)
            .ok()
            .flatten()
            .and_then(|v| v.extract::<usize>().ok())
            .unwrap_or(0)
    };
    // Fold the existing dict fields into FakerResolution, preserving the old
    // dispatch precedence: faker_name (built-in) wins, then custom_faker, then
    // none. The Python dict shape is unchanged (still `faker_name`/`custom_faker`).
    let faker_resolution = if let Some(name) = get_str("faker_name") {
        FakerResolution::Builtin(name)
    } else if get_bool("custom_faker") {
        FakerResolution::Custom
    } else {
        FakerResolution::None
    };
    Ok(TypeInfo {
        strategy: get_str("strategy").unwrap_or_else(|| "remove".to_string()),
        default_strategy: get_str("default_strategy").unwrap_or_else(|| "remove".to_string()),
        prefix: get_str("prefix").unwrap_or_default(),
        prefix_overridden: get_bool("prefix_overridden"),
        faker_resolution,
        replacement: get_str("replacement"),
        label: get_str("label"),
        default_category_label: get_str("default_category_label").unwrap_or_default(),
        visible_prefix: get_usize("visible_prefix"),
        visible_suffix: get_usize("visible_suffix"),
    })
}

/// Build the per-type `{type_name: TypeInfo}` map from the Python `type_info`
/// dict. Shared by `_core.replace` and `_core.redact_l1` so the two bindings
/// adapt the Python `_build_type_info` shape identically (no field drift).
pub(crate) fn build_info_map(
    type_info: &Bound<'_, PyDict>,
) -> PyResult<HashMap<String, TypeInfo>> {
    let mut info_map: HashMap<String, TypeInfo> = HashMap::with_capacity(type_info.len());
    for (k, v) in type_info.iter() {
        let type_name: String = k.extract()?;
        let d = v.cast::<PyDict>().map_err(|_| {
            pyo3::exceptions::PyTypeError::new_err(format!(
                "type_info['{type_name}'] must be a dict"
            ))
        })?;
        info_map.insert(type_name, parse_type_info(d)?);
    }
    Ok(info_map)
}

/// Build the `{type_name: callable}` custom-faker map from the optional Python
/// `custom_fakers` dict. Shared by `_core.replace` and `_core.redact_l1`.
pub(crate) fn build_faker_factory(
    custom_fakers: Option<&Bound<'_, PyDict>>,
) -> PyResult<PyFakerFactory> {
    let mut fakers: HashMap<String, Py<PyAny>> = HashMap::new();
    if let Some(d) = custom_fakers {
        for (k, v) in d.iter() {
            let type_name: String = k.extract()?;
            fakers.insert(type_name, v.unbind());
        }
    }
    Ok(PyFakerFactory { fakers })
}

/// `(redacted, key, aliases, keep_downgraded)` — the [`replace`] return shape.
type ReplaceOut = (String, HashMap<String, String>, HashMap<String, Vec<String>>, bool);

/// Single-pass replace orchestrator (Rust).
///
/// Mirrors `pure/replacer.replace`. Returns
/// `(redacted, key, aliases, keep_downgraded)` — the Python wrapper turns the
/// `keep_downgraded` flag into the `SecurityWarning` (it already pre-checks the
/// downgrade condition to build the warning message, so the flag is a safety
/// cross-check rather than the sole signal).
#[pyfunction]
#[pyo3(signature = (
    text, entities, *, salt=None, key=None, type_info,
    person_prefix="P", org_prefix="O", unified_prefix=None, keep_whitelist,
    custom_fakers=None
))]
#[allow(clippy::too_many_arguments)]
pub fn replace(
    text: &str,
    entities: Vec<PyPatternMatch>,
    salt: Option<&Bound<'_, PyAny>>,
    key: Option<HashMap<String, String>>,
    type_info: &Bound<'_, PyDict>,
    person_prefix: &str,
    org_prefix: &str,
    unified_prefix: Option<&str>,
    keep_whitelist: HashSet<String>,
    custom_fakers: Option<&Bound<'_, PyDict>>,
) -> PyResult<ReplaceOut> {
    let salt = parse_salt(salt)?;

    let core_entities: Vec<CorePM> = entities.iter().map(CorePM::from).collect();

    // Build the per-type info map.
    let info_map = build_info_map(type_info)?;

    // Build the custom-faker map: {type_name: callable}. Empty when no custom
    // fakers are registered (the common path), so we pass `None` to core.
    let py_faker_factory = build_faker_factory(custom_fakers)?;
    let faker_arg: Option<&dyn FakerFactory> = if py_faker_factory.fakers.is_empty() {
        None
    } else {
        Some(&py_faker_factory)
    };

    let factory = PyPseudoFactory;
    let result = core_replace(
        ReplaceArgs {
            text,
            entities: &core_entities,
            salt: salt.as_ref(),
            key: key.as_ref(),
            type_info: &info_map,
            person_prefix,
            org_prefix,
            unified_prefix,
            keep_whitelist: &keep_whitelist,
        },
        &factory,
        faker_arg,
    )
    .map_err(pyo3::exceptions::PyValueError::new_err)?;

    Ok((result.redacted, result.key, result.aliases, result.keep_downgraded))
}
