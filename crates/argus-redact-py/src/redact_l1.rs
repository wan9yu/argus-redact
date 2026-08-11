//! PyO3 bindings for the Rust L1 engine — `_core.detect_l1`, `_core.redact_l1`,
//! and the three hint helpers (`produce_hints_l1`, `get_person_threshold`,
//! `filter_self_reference`).
//!
//! ## Hint interop with `argus_redact._types.Hint`
//!
//! The T9 differential asserts `_core.produce_hints_l1(...)` is `==` to the
//! L1 slice of Python `produce_hints(...)`. For that equality to hold the binding
//! returns ACTUAL `argus_redact._types.Hint` dataclass instances (frozen
//! dataclass `__eq__` compares all fields). Each Rust [`HintKind`] is mapped to
//! `Hint(type=..., data={...}, region=(0,0), source_layer=1)`:
//!
//! - [`HintKind::TextIntent`] → `type="text_intent"`, `data={"intent": <str>}`.
//! - [`HintKind::SelfReferenceTier`] → `type="self_reference_tier"`,
//!   `data={"tier": <int>, "has_kinship": <bool>}`.
//!
//! `tier` is an `int`, `has_kinship` a `bool`, `intent` a `str` — matching the
//! exact Python value types so the `data` dict compares equal.
//!
//! Consumers (`get_person_threshold` / `filter_self_reference`) accept Python
//! objects and read `.type` / `.data` DUCK-TYPED — they receive `_types.Hint`
//! instances (from `produce_hints_l1` here or Python `produce_hints`).

use std::collections::{HashMap, HashSet};

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyTuple};

use argus_redact_core::cancel::{CancelFlag, DetectError};
use argus_redact_core::coverage::{
    restore_lost_coverage as core_restore_lost_coverage, FilterScope,
};
use argus_redact_core::hints::{
    filter_self_reference as core_filter_self_reference,
    get_person_threshold as core_get_person_threshold, produce_hints_l1 as core_produce_hints_l1,
    Hint, HintKind,
};
use argus_redact_core::redact_l1::{
    detect_l1_cancellable as core_detect_l1_cancellable, redact_l1 as core_redact_l1,
};
use argus_redact_core::redact_l1::RedactL1Args;
use argus_redact_core::FakerFactory;
use argus_redact_core::PatternMatch as CorePM;

use crate::replace::{build_faker_factory, build_info_map, parse_salt, PyPseudoFactory};
use crate::types::PyPatternMatch;

// ── Hint ↔ _types.Hint conversion ─────────────────────────────────────────────

/// Construct a Python `argus_redact._types.Hint` from one Rust [`Hint`].
///
/// Imports the `Hint` class fresh per call (cheap — Python caches the module);
/// builds the `data` dict with the exact value types Python uses so the frozen
/// dataclass compares `==` to Python `produce_hints` output.
fn hint_to_py<'py>(py: Python<'py>, hint: &Hint) -> PyResult<Bound<'py, PyAny>> {
    let hint_cls = py
        .import("argus_redact._types")?
        .getattr("Hint")?;
    let data = PyDict::new(py);
    let mut region: (i64, i64) = (0, 0);
    let type_name: &str = match &hint.kind {
        HintKind::PiiDensity { level, count } => {
            data.set_item("level", level)?;
            data.set_item("count", *count)?;
            "pii_density"
        }
        HintKind::NearMissFormat { original_type, text, start, end } => {
            data.set_item("original_type", original_type)?;
            data.set_item("text", text)?;
            region = (*start as i64, *end as i64);
            "near_miss_format"
        }
        HintKind::TextIntent { intent } => {
            data.set_item("intent", intent)?;
            "text_intent"
        }
        HintKind::SelfReferenceTier { tier, has_kinship } => {
            data.set_item("tier", *tier)?;
            data.set_item("has_kinship", *has_kinship)?;
            "self_reference_tier"
        }
    };
    let kwargs = PyDict::new(py);
    kwargs.set_item("type", type_name)?;
    kwargs.set_item("data", &data)?;
    kwargs.set_item("region", PyTuple::new(py, [region.0, region.1])?)?;
    kwargs.set_item("source_layer", 1i64)?;
    hint_cls.call((), Some(&kwargs))
}

/// Map a list of Rust hints to a Python list of `_types.Hint` instances.
fn hints_to_py<'py>(py: Python<'py>, hints: &[Hint]) -> PyResult<Vec<Bound<'py, PyAny>>> {
    hints.iter().map(|h| hint_to_py(py, h)).collect()
}

/// Read one Python hint object (duck-typed `.type` / `.data`) into a Rust [`Hint`].
///
/// Only the two L1 hint kinds are recognized; any other `.type` (e.g. the full
/// Python `pii_density` / `near_miss_format`) is dropped — `get_person_threshold`
/// and `filter_self_reference` only ever look at the two L1 kinds, so a hint of an
/// unknown type carries no signal for them and skipping it is faithful to the
/// Python consumers (which simply never match those `h.type` branches).
fn hint_from_py(obj: &Bound<'_, PyAny>) -> PyResult<Option<Hint>> {
    let type_name: String = obj.getattr("type")?.extract()?;
    let data = obj.getattr("data")?;
    match type_name.as_str() {
        "text_intent" => {
            let intent: String = data.get_item("intent")?.extract()?;
            Ok(Some(Hint {
                kind: HintKind::TextIntent { intent },
            }))
        }
        "self_reference_tier" => {
            let tier: u8 = data.get_item("tier")?.extract()?;
            let has_kinship: bool = data.get_item("has_kinship")?.extract()?;
            Ok(Some(Hint {
                kind: HintKind::SelfReferenceTier { tier, has_kinship },
            }))
        }
        _ => Ok(None),
    }
}

/// Read a Python hint list into Rust [`Hint`]s, dropping non-L1 kinds.
fn hints_from_py(hints: &Bound<'_, PyAny>) -> PyResult<Vec<Hint>> {
    let mut out: Vec<Hint> = Vec::new();
    for item in hints.try_iter()? {
        let item = item?;
        if let Some(h) = hint_from_py(&item)? {
            out.push(h);
        }
    }
    Ok(out)
}

// ── cooperative cancellation (CancelToken + ScanAborted) ───────────────────────

// The cooperative-cancellation abort raised when a scan observes a tripped
// `CancelToken`. It MUST derive `Exception` (via `PyException`), NEVER
// `BaseException`: the HTTP server offloads each scan into a detached worker whose
// `except Exception` forwards the error to the awaiting request. A
// `BaseException`-derived abort would slip past that guard, propagate into the
// app-lifetime task group, and tear the whole server down at every cancellation.
// The message is a fixed, PII-free string (`DetectError::Aborted`'s `Display`,
// "detection cancelled") — it never echoes scanned text.
pyo3::create_exception!(
    argus_redact._core,
    ScanAborted,
    pyo3::exceptions::PyException,
    "cooperative-cancellation abort of an L1 detection scan"
);

/// A cooperative-cancellation handle for a single detection scan.
///
/// Wraps the core [`CancelFlag`] (an `Arc<AtomicBool>`). A fresh token is
/// un-cancelled; [`cancel`](CancelToken::cancel) trips it from another thread and
/// the detached scan returns [`ScanAborted`] at its next poll boundary. Both
/// `cancel()` and the scan-side read take `&self` (a SHARED borrow), so tripping
/// the token from one thread never conflicts with the in-flight scan's borrow.
///
/// One token PER scan — it is never shared across scans (a shared token would
/// abort unrelated in-flight scans); the server constructs a fresh one per
/// `_run_scan`.
#[pyclass]
pub struct CancelToken {
    flag: CancelFlag,
}

#[pymethods]
impl CancelToken {
    #[new]
    fn new() -> Self {
        CancelToken {
            flag: CancelFlag::new(),
        }
    }

    /// Trip the token. Idempotent; the next scan poll returns `ScanAborted`.
    fn cancel(&self) {
        self.flag.cancel();
    }

    /// `True` once `cancel()` has been called on this token (or a clone of its
    /// underlying flag). Exposed for cooperative pollers and test observability.
    fn is_cancelled(&self) -> bool {
        self.flag.is_cancelled()
    }
}

impl CancelToken {
    /// Clone the underlying [`CancelFlag`] (shares the same atomic). The `Arc`
    /// crosses `py.detach`; the `Bound<CancelToken>` cannot.
    fn flag(&self) -> CancelFlag {
        self.flag.clone()
    }
}

/// Map a core [`DetectError`] onto the Python exception ladder: an abort becomes
/// [`ScanAborted`] (mapped to 504 at the server), and any other pattern/input
/// error stays a `ValueError` (mapped to 400 at the server) — byte-identical to the
/// pre-cancellation `.map_err(|e| PyValueError::new_err(e.to_string()))`, since a
/// no-cancel scan can only ever produce `DetectError::Pattern` and its `Display`
/// delegates to the inner `PatternError`.
fn map_detect_error(e: DetectError) -> PyErr {
    let msg = e.to_string();
    match e {
        DetectError::Aborted => ScanAborted::new_err(msg),
        DetectError::Pattern(_) => pyo3::exceptions::PyValueError::new_err(msg),
    }
}

// ── detect_l1 ─────────────────────────────────────────────────────────────────

/// `(redacted, key, aliases, keep_downgraded, mask_collisions)` — the
/// [`redact_l1`] return shape (identical to `_core.replace`'s).
type RedactL1Out = (
    String,
    HashMap<String, String>,
    HashMap<String, Vec<String>>,
    bool,
    Vec<String>,
);

/// `(layer1, person, regions, job_titles, framework, hints, near_misses)` — the
/// [`detect_l1`] return shape.
type DetectL1Out<'py> = (
    Vec<PyPatternMatch>,
    Vec<PyPatternMatch>,
    Vec<PyPatternMatch>,
    Vec<PyPatternMatch>,
    Vec<PyPatternMatch>,
    Vec<Bound<'py, PyAny>>,
    Vec<PyPatternMatch>,
);

/// Run the fast-mode L1 detection sequence, returning the RAW (unmerged) result
/// as seven distinct components so both fast mode
/// (`layer1 ++ person ++ regions ++ job_titles ++ framework`) and full mode
/// (`layer1` separately + `near_misses`) can consume it.
///
/// Mirrors `argus_redact_core::redact_l1::detect_l1`. `known_names=None` behaves
/// like the Python detector's empty-names default.
///
/// The keyword-only `cancel_token` opts into cooperative cancellation: a
/// [`CancelToken`] tripped from another thread makes the scan return
/// [`ScanAborted`] at its next poll boundary. `cancel_token=None` (the default) is
/// byte-identical to the pre-cancellation path — every poll is a no-op.
#[pyfunction]
#[pyo3(signature = (text, lang, known_names=None, *, cancel_token=None))]
pub fn detect_l1<'py>(
    py: Python<'py>,
    text: &str,
    lang: Vec<String>,
    known_names: Option<Vec<String>>,
    cancel_token: Option<&CancelToken>,
) -> PyResult<DetectL1Out<'py>> {
    let names = known_names.unwrap_or_default();
    // The `Bound<CancelToken>` cannot cross `py.detach`, but the `Arc<AtomicBool>`
    // inside it can — clone the flag out here and hand `Some(&flag)` to the core.
    // With no token the flag is `None`: every poll is a no-op and only
    // `DetectError::Pattern` can arise, so this is byte-identical to the old path.
    let flag = cancel_token.map(CancelToken::flag);
    // Detection is pure Rust (normalize + regex + person scoring) with no
    // Python callback anywhere in it, so the lock is released for the whole
    // scan — this is the expensive half of a redact.
    let result = py
        .detach(|| core_detect_l1_cancellable(text, &lang, &names, flag.as_ref()))
        .map_err(map_detect_error)?;
    let layer1: Vec<PyPatternMatch> =
        result.layer1.into_iter().map(PyPatternMatch::from).collect();
    let person: Vec<PyPatternMatch> =
        result.person.into_iter().map(PyPatternMatch::from).collect();
    let regions: Vec<PyPatternMatch> =
        result.regions.into_iter().map(PyPatternMatch::from).collect();
    let job_titles: Vec<PyPatternMatch> =
        result.job_titles.into_iter().map(PyPatternMatch::from).collect();
    let framework: Vec<PyPatternMatch> =
        result.framework.into_iter().map(PyPatternMatch::from).collect();
    let hints = hints_to_py(py, &result.hints)?;
    let near_misses: Vec<PyPatternMatch> = result
        .near_misses
        .into_iter()
        .map(PyPatternMatch::from)
        .collect();
    Ok((layer1, person, regions, job_titles, framework, hints, near_misses))
}

// ── redact_l1 ─────────────────────────────────────────────────────────────────

/// Fast-mode end-to-end redaction over L1 (regex + person) only.
///
/// Reuses the EXACT `type_info` / faker adaptation of `_core.replace`
/// (`build_info_map` / `build_faker_factory` / `parse_salt` / `PyPseudoFactory`),
/// then forwards detect_l1's `lang` / `known_names` and the type allow/deny
/// filter. Returns `(redacted, key, aliases, keep_downgraded, mask_collisions)`
/// — identical to `_core.replace`. Mirrors `_core.replace`'s signature for the
/// shared params, adding `known_names=None`, `types=None`, `types_exclude=None`.
#[pyfunction]
#[pyo3(signature = (
    text, lang, known_names=None, *, type_info,
    salt=None, key=None,
    person_prefix="P", org_prefix="O", unified_prefix=None, keep_whitelist,
    types=None, types_exclude=None, custom_fakers=None
))]
#[allow(clippy::too_many_arguments)]
pub fn redact_l1(
    text: &str,
    lang: Vec<String>,
    known_names: Option<Vec<String>>,
    type_info: &Bound<'_, PyDict>,
    salt: Option<&Bound<'_, PyAny>>,
    key: Option<HashMap<String, String>>,
    person_prefix: &str,
    org_prefix: &str,
    unified_prefix: Option<&str>,
    keep_whitelist: HashSet<String>,
    types: Option<HashSet<String>>,
    types_exclude: Option<HashSet<String>>,
    custom_fakers: Option<&Bound<'_, PyDict>>,
) -> PyResult<RedactL1Out> {
    let salt = parse_salt(salt)?;
    let names = known_names.unwrap_or_default();

    // SAME type_info / faker adaptation as `_core.replace` (shared helpers).
    let info_map = build_info_map(type_info)?;
    let py_faker_factory = build_faker_factory(custom_fakers)?;
    let faker_arg: Option<&dyn FakerFactory> = if py_faker_factory.fakers.is_empty() {
        None
    } else {
        Some(&py_faker_factory)
    };

    let factory = PyPseudoFactory;
    let result = core_redact_l1(
        RedactL1Args {
            text,
            lang: &lang,
            names: &names,
            type_info: &info_map,
            salt: salt.as_ref(),
            key: key.as_ref(),
            person_prefix,
            org_prefix,
            unified_prefix,
            keep_whitelist: &keep_whitelist,
            types: types.as_ref(),
            types_exclude: types_exclude.as_ref(),
        },
        &factory,
        faker_arg,
    )
    .map_err(pyo3::exceptions::PyValueError::new_err)?;

    Ok((
        result.redacted,
        result.key,
        result.aliases,
        result.keep_downgraded,
        result.mask_collisions,
    ))
}

// ── hint helpers ──────────────────────────────────────────────────────────────

/// Produce the full L1 hint set (`pii_density`, `near_miss_format`, `text_intent`,
/// `self_reference_tier`) as `_types.Hint`s.
///
/// COMPARABLE to the L1 slice of Python `produce_hints` (the binding returns real
/// `_types.Hint` instances). `near_misses` defaults to empty.
#[pyfunction]
#[pyo3(signature = (entities, text, near_misses=None))]
pub fn produce_hints_l1<'py>(
    py: Python<'py>,
    entities: Vec<PyPatternMatch>,
    text: &str,
    near_misses: Option<Vec<PyPatternMatch>>,
) -> PyResult<Vec<Bound<'py, PyAny>>> {
    let ents: Vec<CorePM> = entities.iter().map(CorePM::from).collect();
    let nms: Vec<CorePM> = near_misses
        .unwrap_or_default()
        .iter()
        .map(CorePM::from)
        .collect();
    let hints = core_produce_hints_l1(&ents, text, &nms);
    hints.iter().map(|h| hint_to_py(py, h)).collect()
}

/// Person-name threshold from the hints (1.2 instruction / 0.8 otherwise).
///
/// Accepts Python `_types.Hint` objects, read duck-typed (`.type` / `.data`).
#[pyfunction]
pub fn get_person_threshold(hints: &Bound<'_, PyAny>) -> PyResult<f64> {
    let core_hints = hints_from_py(hints)?;
    Ok(core_get_person_threshold(&core_hints))
}

/// Filter `self_reference` entities by the tier hint (tier 1 keeps all; else drops).
///
/// Accepts Python `_types.Hint` objects, read duck-typed (`.type` / `.data`).
#[pyfunction]
pub fn filter_self_reference(
    entities: Vec<PyPatternMatch>,
    hints: &Bound<'_, PyAny>,
) -> PyResult<Vec<PyPatternMatch>> {
    let core_entities: Vec<CorePM> = entities.iter().map(CorePM::from).collect();
    let core_hints = hints_from_py(hints)?;
    let out = core_filter_self_reference(core_entities, &core_hints);
    Ok(out.into_iter().map(PyPatternMatch::from).collect())
}

/// Re-admit entities whose coverage a post-merge filter destroyed.
///
/// `merged_spans` is the `(start, end)` snapshot of the post-merge, pre-filter
/// entity set — a span list rather than the entities themselves because the
/// callers take it before the filters consume the merged vector.
///
/// Returns `(entities, restored_types)`; `restored_types` is sorted, deduplicated
/// and PII-free (type names only).
#[pyfunction]
#[pyo3(signature = (pre_merge, merged_spans, filtered, types, types_exclude, drop_self_reference, text))]
pub fn restore_lost_coverage(
    pre_merge: Vec<PyPatternMatch>,
    merged_spans: Vec<(usize, usize)>,
    filtered: Vec<PyPatternMatch>,
    types: Option<Vec<String>>,
    types_exclude: Option<Vec<String>>,
    drop_self_reference: bool,
    text: &str,
) -> PyResult<(Vec<PyPatternMatch>, Vec<String>)> {
    let core_pre: Vec<CorePM> = pre_merge.iter().map(CorePM::from).collect();
    let core_filtered: Vec<CorePM> = filtered.iter().map(CorePM::from).collect();
    let keep: Option<HashSet<String>> = types.map(|v| v.into_iter().collect());
    let drop: Option<HashSet<String>> = types_exclude.map(|v| v.into_iter().collect());
    // `FilterScope` is `#[non_exhaustive]`: build it via the constructor
    // rather than a struct literal, which a crate outside `argus-redact-core`
    // (this one) can no longer write.
    let scope = FilterScope::new(keep.as_ref(), drop.as_ref(), drop_self_reference);
    let (out, restored) =
        core_restore_lost_coverage(&core_pre, &merged_spans, core_filtered, &scope, text);
    Ok((out.into_iter().map(PyPatternMatch::from).collect(), restored))
}
