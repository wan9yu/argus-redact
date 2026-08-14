use std::collections::{HashMap, HashSet};

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

use argus_redact_core::replace::{
    replace as core_replace, FakerFactory, FakerResolution, PseudoFactory, ReplaceArgs,
    ReplaceSession, TypeInfo,
};
use argus_redact_core::seed::Salt;
use argus_redact_core::typeinfo::{
    build_type_info as core_build_type_info, Config as CoreConfig, EntityConfig, RegistryDefault,
    RegistryDefaults as CoreRegistryDefaults,
};
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

/// A single shared factory instance so a [`StructuredRedactor`]'s owned
/// [`ReplaceSession`] can borrow it for `'static`. `PyPseudoFactory` is a
/// zero-sized unit struct (no per-instance state — every `make` mints a fresh
/// [`PyRandomSource`] from the seed), so a process-wide `static` is exact.
static PY_FACTORY: PyPseudoFactory = PyPseudoFactory;

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

impl PyFakerFactory {
    /// The `Option<&dyn FakerFactory>` the core `replace` / `redact_l1` / session
    /// take: `Some(self)` iff a custom faker is registered, else `None` (the common
    /// path — core then skips the custom-faker overlay entirely). One SSOT for the
    /// "empty map → None" selection, shared by the one-shot [`replace`], the
    /// [`StructuredRedactor`] session, and `redact_l1`.
    pub(crate) fn as_arg(&self) -> Option<&dyn FakerFactory> {
        (!self.fakers.is_empty()).then_some(self as &dyn FakerFactory)
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

/// Read an optional string field from a `PyDict`: `None` when the key is absent OR
/// present-but-`None`, otherwise the extracted `str` (and `None` if the value is
/// present but not a string). The "None → absent" extraction shared verbatim by
/// [`parse_type_info`], [`parse_config`], and [`parse_registry_defaults`].
fn opt_str(d: &Bound<'_, PyDict>, key: &str) -> Option<String> {
    d.get_item(key)
        .ok()
        .flatten()
        .and_then(|v| if v.is_none() { None } else { v.extract::<String>().ok() })
}

/// Parse one per-type info dict into a [`TypeInfo`].
fn parse_type_info(d: &Bound<'_, PyDict>) -> PyResult<TypeInfo> {
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
    let faker_resolution = if let Some(name) = opt_str(d, "faker_name") {
        FakerResolution::Builtin(name)
    } else if get_bool("custom_faker") {
        FakerResolution::Custom
    } else {
        FakerResolution::None
    };
    Ok(TypeInfo {
        strategy: opt_str(d, "strategy").unwrap_or_else(|| "remove".to_string()),
        default_strategy: opt_str(d, "default_strategy").unwrap_or_else(|| "remove".to_string()),
        prefix: opt_str(d, "prefix").unwrap_or_default(),
        prefix_overridden: get_bool("prefix_overridden"),
        faker_resolution,
        replacement: opt_str(d, "replacement"),
        label: opt_str(d, "label"),
        default_category_label: opt_str(d, "default_category_label").unwrap_or_default(),
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

/// `(redacted, key, aliases, signals)` — the [`replace`] return shape.
/// `signals` is a Python dict carrying `keep_downgraded` (bool) and
/// `mask_collisions` (list[str]) in one slot rather than two trailing
/// positional elements.
type ReplaceOut = (
    String,
    HashMap<String, String>,
    HashMap<String, Vec<String>>,
    Py<PyDict>,
);

/// Single-pass replace orchestrator (Rust).
///
/// Mirrors `pure/replacer.replace`. Returns `(redacted, key, aliases,
/// signals)` where `signals = {"keep_downgraded": bool, "mask_collisions":
/// list[str]}`. The Python wrapper turns the `keep_downgraded` flag into the
/// `SecurityWarning` (it already pre-checks the downgrade condition to build
/// the warning message, so the flag is a safety cross-check rather than the
/// sole signal). Likewise, `mask_collisions` (one entry per mask-family
/// collision `resolve_collision` actually disambiguated) drives a second
/// `SecurityWarning` + a `mask_collision` `security_event` — see
/// `ReplaceResult::mask_collisions` (core `replace.rs`).
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
    let faker_arg = py_faker_factory.as_arg();

    let factory = PyPseudoFactory;

    // Build the core call once; the two arms below differ only in whether they
    // hold the GIL while it runs.
    let run = |faker: Option<&dyn FakerFactory>| {
        core_replace(
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
            faker,
        )
    };

    // `type_info` carries the GIL token this call runs under; grab it once for
    // the detach and the later `signals` build.
    let py = type_info.py();

    // Release the GIL for the CPU-bound replace on the common no-custom-faker
    // path. There the whole pass is pure Rust — masks, built-in realistic fakers,
    // and the seeded MT19937 pseudonym stream — so holding the lock only serialises
    // unrelated callers and (over HTTP) freezes the server event loop on a large
    // input. Detaching restores the 504 deadline / disconnect / shutdown guards.
    //
    // The only Python touchpoint reachable on this no-faker path is the UNSEEDED
    // `secrets.randbelow` draw (salt=None), and `PyRandomSource::randbelow`
    // re-attaches via `Python::attach` for each draw, so it is safe inside the
    // detached region.
    //
    // When a custom Python faker is registered (`faker_arg` is Some) the pass can
    // call back into arbitrary Python, so run ATTACHED (hold the GIL) — the safe
    // choice, and a custom faker is not the attacker-reachable large-input path.
    let result = match faker_arg {
        Some(faker) => run(Some(faker)),
        None => py.detach(|| run(None)),
    }
    .map_err(pyo3::exceptions::PyValueError::new_err)?;

    let signals = PyDict::new(py);
    signals.set_item("keep_downgraded", result.keep_downgraded)?;
    signals.set_item("mask_collisions", result.mask_collisions)?;

    Ok((result.redacted, result.key, result.aliases, signals.unbind()))
}

/// Parse the Python `config` dict (`{type: {strategy, prefix, ...}}`) into the
/// core [`CoreConfig`]. Only the per-type entries that are dicts are read (a
/// non-dict value — e.g. the legacy `_unified_prefix` sentinel the Python
/// wrapper rejects up front — is skipped). `prefix.is_some()` carries the Python
/// `"prefix" in ec` check that drives `prefix_overridden`.
fn parse_config(config: Option<&Bound<'_, PyDict>>) -> PyResult<Option<CoreConfig>> {
    let Some(d) = config else { return Ok(None) };
    let mut out: CoreConfig = CoreConfig::with_capacity(d.len());
    for (k, v) in d.iter() {
        let type_name: String = match k.extract() {
            Ok(s) => s,
            Err(_) => continue,
        };
        let Ok(ec) = v.cast::<PyDict>() else { continue };
        // visible_prefix/suffix: reproduce Python `int(ec.get(key, 0) or 0)`
        // followed by the downstream non-positive → per-type-default behavior.
        //
        // Config from json.loads / yaml.safe_load carries numeric STRINGS ('5')
        // and FLOATS (2.7) that the validator doesn't coerce, plus int and the
        // wasm path's JS f64. Pre-port Python truncated floats (int(2.7)=2),
        // parsed numeric strings (int('5')=5), and let any non-positive result
        // fall through to the per-type mask default (a negative failed the old
        // `extract::<usize>()`; 0 is the explicit default sentinel). So:
        //   - usize > 0                 → Some(n)
        //   - Python float, floor >= 1  → Some(floor)
        //   - numeric string, int >= 1  → Some(parsed)
        //   - negative / 0 / None / NaN / non-numeric → None (per-type default)
        let get_usize = |key: &str| -> Option<usize> {
            let x = ec.get_item(key).ok().flatten()?;
            if x.is_none() {
                return None;
            }
            // Direct usize (plain int, JS integers): the common path.
            if let Ok(n) = x.extract::<usize>() {
                return (n > 0).then_some(n);
            }
            // Python float / JS number arriving as f64: truncate toward zero
            // (Python `int(2.7) == 2`); drop NaN / non-finite / non-positive.
            if let Ok(f) = x.extract::<f64>() {
                if f.is_finite() && f >= 1.0 {
                    return Some(f.trunc() as usize);
                }
                return None;
            }
            // Numeric string ('5', '2.7'): parse as int first, then as float so
            // '2.7' truncates the same way Python `int(float('2.7'))` would.
            if let Ok(s) = x.extract::<String>() {
                let s = s.trim();
                if let Ok(n) = s.parse::<i64>() {
                    return (n >= 1).then_some(n as usize);
                }
                if let Ok(f) = s.parse::<f64>() {
                    if f.is_finite() && f >= 1.0 {
                        return Some(f.trunc() as usize);
                    }
                }
            }
            None
        };
        out.insert(
            type_name,
            EntityConfig {
                strategy: opt_str(ec, "strategy"),
                // `prefix` present (even if None) sets prefix_overridden in
                // Python (`"prefix" in ec`). Match that: Some iff the key exists.
                prefix: if ec.contains("prefix").unwrap_or(false) {
                    Some(opt_str(ec, "prefix").unwrap_or_default())
                } else {
                    None
                },
                replacement: opt_str(ec, "replacement"),
                label: opt_str(ec, "label"),
                visible_prefix: get_usize("visible_prefix"),
                visible_suffix: get_usize("visible_suffix"),
            },
        );
    }
    Ok(Some(out))
}

/// Parse the optional Python `registry_defaults` dict
/// (`{type: {strategy, prefix, category_label}}`) into the core
/// [`CoreRegistryDefaults`]. The Python shim resolves the live-registry default
/// strategy + `DEFAULT_PREFIXES` / `DEFAULT_CATEGORY_LABEL` per detected type and
/// hands them in so runtime adapter types — invisible to the core's built-in
/// tables — get their declared defaults. `None` (the wasm path) → the core's
/// built-in fallback tables drive every type. A per-type field absent / None
/// falls back to the built-in table for that field.
fn parse_registry_defaults(
    registry_defaults: Option<&Bound<'_, PyDict>>,
) -> PyResult<Option<CoreRegistryDefaults>> {
    let Some(d) = registry_defaults else {
        return Ok(None);
    };
    let mut out: CoreRegistryDefaults = CoreRegistryDefaults::with_capacity(d.len());
    for (k, v) in d.iter() {
        let type_name: String = match k.extract() {
            Ok(s) => s,
            Err(_) => continue,
        };
        let Ok(rd) = v.cast::<PyDict>() else { continue };
        out.insert(
            type_name,
            RegistryDefault {
                strategy: opt_str(rd, "strategy"),
                prefix: opt_str(rd, "prefix"),
                category_label: opt_str(rd, "category_label"),
            },
        );
    }
    Ok(Some(out))
}

/// Build the per-type replacement info dict in the shape the Python
/// `_build_type_info` produces (the `info` return value, before the custom-faker
/// overlay). SSOT: the core [`core_build_type_info`] — the PyO3 binding and a
/// future wasm crate share this assembly. The Python wrapper layers its custom
/// adapter `faker_reserved` callables on top of this result.
///
/// `registry_defaults` carries the live-registry per-type default strategy /
/// prefix / category-label (resolved Python-side, the SSOT that includes runtime
/// adapter types) so a custom type honors its declared defaults; absent it the
/// core falls back to its built-in tables (the wasm path).
///
/// Returns `{type_name: {strategy, default_strategy, prefix, prefix_overridden,
/// faker_name, custom_faker, replacement, label, default_category_label,
/// visible_prefix, visible_suffix}}` — the dict `build_info_map` consumes, so the
/// Python dict shape is unchanged. The core never emits a `Custom` faker (only
/// `Builtin`/`None`); the custom-faker flag is therefore always `false` here and
/// the Python overlay flips it for registered adapter types.
#[pyfunction]
#[pyo3(signature = (entities, config=None, langs=None, registry_defaults=None))]
pub fn build_type_info<'py>(
    py: Python<'py>,
    entities: Vec<PyPatternMatch>,
    config: Option<&Bound<'_, PyDict>>,
    langs: Option<Vec<String>>,
    registry_defaults: Option<&Bound<'_, PyDict>>,
) -> PyResult<Bound<'py, PyDict>> {
    let core_entities: Vec<CorePM> = entities.iter().map(CorePM::from).collect();
    let core_config = parse_config(config)?;
    let core_registry_defaults = parse_registry_defaults(registry_defaults)?;
    let langs = langs.unwrap_or_default();

    let pairs = core_build_type_info(
        &core_entities,
        core_config.as_ref(),
        &langs,
        core_registry_defaults.as_ref(),
    );

    let out = PyDict::new(py);
    for (type_name, ti) in pairs {
        let d = PyDict::new(py);
        d.set_item("strategy", &ti.strategy)?;
        d.set_item("default_strategy", &ti.default_strategy)?;
        d.set_item("prefix", &ti.prefix)?;
        d.set_item("prefix_overridden", ti.prefix_overridden)?;
        // Fold FakerResolution back into the (faker_name, custom_faker) dict
        // fields the Python shape expects. The core never returns Custom.
        let (faker_name, custom_faker): (Option<&str>, bool) = match &ti.faker_resolution {
            FakerResolution::Builtin(n) => (Some(n.as_str()), false),
            FakerResolution::Custom => (None, true),
            FakerResolution::None => (None, false),
        };
        d.set_item("faker_name", faker_name)?;
        d.set_item("custom_faker", custom_faker)?;
        d.set_item("replacement", ti.replacement.as_deref())?;
        d.set_item("label", ti.label.as_deref())?;
        d.set_item("default_category_label", &ti.default_category_label)?;
        d.set_item("visible_prefix", ti.visible_prefix)?;
        d.set_item("visible_suffix", ti.visible_suffix)?;
        out.set_item(type_name, d)?;
    }
    Ok(out)
}

/// Stateful structured-redaction session.
///
/// Owns the accumulation key + reverse index + pseudonym generators in Rust
/// across cells, so redacting an N-cell CSV / JSON is O(N) total instead of
/// O(N²): the stateless per-cell [`replace`] re-clones and re-preloads the whole
/// growing key on every cell (marshalled in AND out across the boundary), which
/// is O(|key|) per cell. This session marshals only the per-cell entities +
/// type_info in and the redacted text out; the key lives in Rust and is read
/// once at the end via [`into_key`](Self::into_key).
///
/// Byte-identical to the per-cell path: it drives the SAME core
/// [`ReplaceSession`] the one-shot [`replace`] uses, so no replace logic is
/// duplicated. `structured.py` builds one of these, calls
/// [`redact_cell`](Self::redact_cell) per cell/leaf, then reads
/// [`into_key`](Self::into_key).
#[pyclass]
pub struct StructuredRedactor {
    session: ReplaceSession<'static, PyPseudoFactory>,
    /// Keep-strategy whitelist, constant for the session (single SSOT from
    /// Python, same value the stateless `replace` receives per call).
    keep_whitelist: HashSet<String>,
}

#[pymethods]
impl StructuredRedactor {
    /// Build a session. `salt` / prefixes / `keep_whitelist` are constant for the
    /// whole structured document (they come from the one redact() call's params);
    /// `key` seeds an optional existing mapping.
    #[new]
    #[pyo3(signature = (
        *, salt=None, key=None, person_prefix="P", org_prefix="O",
        unified_prefix=None, keep_whitelist
    ))]
    fn new(
        salt: Option<&Bound<'_, PyAny>>,
        key: Option<HashMap<String, String>>,
        person_prefix: &str,
        org_prefix: &str,
        unified_prefix: Option<&str>,
        keep_whitelist: HashSet<String>,
    ) -> PyResult<Self> {
        let salt = parse_salt(salt)?;
        let session = ReplaceSession::new(
            &PY_FACTORY,
            salt.as_ref(),
            person_prefix,
            org_prefix,
            unified_prefix,
            key.as_ref(),
        );
        Ok(Self {
            session,
            keep_whitelist,
        })
    }

    /// Redact one cell / leaf against the persistent session state, returning its
    /// redacted text. The key, reverse index, reserved set, and `keep_downgraded`
    /// flag accumulate in the session across calls. `entities` + `type_info` are
    /// the SAME per-cell shapes `_core.replace` takes.
    #[pyo3(signature = (text, entities, type_info, custom_fakers=None))]
    fn redact_cell(
        &mut self,
        text: &str,
        entities: Vec<PyPatternMatch>,
        type_info: &Bound<'_, PyDict>,
        custom_fakers: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<String> {
        let core_entities: Vec<CorePM> = entities.iter().map(CorePM::from).collect();
        let info_map = build_info_map(type_info)?;
        let py_faker_factory = build_faker_factory(custom_fakers)?;
        let faker_arg = py_faker_factory.as_arg();
        self.session
            .process(
                text,
                &core_entities,
                &info_map,
                &self.keep_whitelist,
                faker_arg,
            )
            .map_err(pyo3::exceptions::PyValueError::new_err)
    }

    /// The accumulated replacement → original key (a snapshot copy). Read once at
    /// the end of the document — the only key marshal across the boundary.
    fn into_key(&self) -> HashMap<String, String> {
        self.session.key().clone()
    }

    /// Whether any `keep`-strategy entity was downgraded so far this session (the
    /// Python wrapper turns this into the structured `keep_downgraded` event).
    #[getter]
    fn keep_downgraded(&self) -> bool {
        self.session.keep_downgraded()
    }

    /// Entity types for mask-family collisions disambiguated so far this session
    /// (mirrors `keep_downgraded` — the Python wrapper can turn a non-empty list
    /// into the structured `mask_collision` event / `SecurityWarning`).
    #[getter]
    fn mask_collisions(&self) -> Vec<String> {
        self.session.mask_collisions().to_vec()
    }

    /// The accumulated `{fake: aliases}` map for realistic fakers that emitted
    /// alternate transliterations so far this session (a snapshot copy). Mirrors
    /// the one-shot [`replace`] path's fourth return element, so a structured
    /// (CSV / JSON) redaction can thread the SAME aliases into
    /// `make_structured_restorer` that the batch and streaming faces already do
    /// — without it an LLM that rewrote a realistic fake into one of its aliases
    /// would silently stay unrestored on the structured face.
    #[getter]
    fn aliases(&self) -> HashMap<String, Vec<String>> {
        self.session.aliases().clone()
    }
}
