use std::collections::HashMap;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDict;

use argus_redact_core::check_restore_safety as core_check_safety;
use argus_redact_core::restore_full as core_restore_full;
use argus_redact_core::restore_full_guarded as core_restore_full_guarded;
use argus_redact_core::{Anchor, GuardEventKind, RestoreOutcome, RestoreSession};

/// Restore redacted text by replacing pseudonyms with originals (simple 2-arg form).
/// Kept for back-compat; new callers should prefer `restore` with keyword args.
///
/// Returns `(restored_text, signals)` where `signals =
/// {"alias_collisions": list[str]}` — `alias_collisions` has one entry per
/// alias string that two distinct fakes both claimed (mapping to two
/// different originals); empty when no `aliases` were passed or none collided.
/// The Python wrapper (`pure/restore._do_restore`) turns a non-empty list into
/// a `SecurityWarning` — mirrors how `replace`'s `mask_collisions` is threaded.
///
/// This calls the STABLE `restore_full` compat wrapper (not
/// `restore_full_guarded` directly) so this binding's shape stays decoupled
/// from any guard-parameter evolution on the guarded entry point.
#[pyfunction]
#[pyo3(signature = (text, key, aliases=None, display_marker=None))]
pub fn restore<'py>(
    py: Python<'py>,
    text: &str,
    key: HashMap<String, String>,
    aliases: Option<HashMap<String, Vec<String>>>,
    display_marker: Option<String>,
) -> PyResult<(String, Py<PyDict>)> {
    // Route through restore_full when extras are provided (or always, for consistency).
    let (restored, alias_collisions) = core_restore_full(
        text,
        &key,
        aliases.as_ref(),
        display_marker.as_deref(),
    )
    .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

    let signals = PyDict::new(py);
    signals.set_item("alias_collisions", alias_collisions)?;

    Ok((restored, signals.unbind()))
}

/// Map a [`GuardEventKind`] to its stable snake_case name. `#[non_exhaustive]`
/// on the core enum means a future variant compiles here as "unknown" rather
/// than breaking the build — the Python layer (a later addition) is expected
/// to grow its own mapping in lockstep, this is just the fallback until it does.
fn guard_event_kind_str(kind: &GuardEventKind) -> &'static str {
    match kind {
        GuardEventKind::GuardNoAnchor => "guard_no_anchor",
        GuardEventKind::ProvenanceFailed => "provenance_failed",
        GuardEventKind::EmptyKeyWithScope => "empty_key_with_scope",
        GuardEventKind::OutOfScopePseudonym => "out_of_scope_pseudonym",
        GuardEventKind::AliasCollision => "alias_collision",
        _ => "unknown",
    }
}

/// Map a [`RestoreOutcome`] to its stable snake_case name. Same
/// `#[non_exhaustive]` fallback reasoning as [`guard_event_kind_str`].
fn restore_outcome_str(outcome: &RestoreOutcome) -> &'static str {
    match outcome {
        RestoreOutcome::Blocked => "blocked",
        RestoreOutcome::Partial => "partial",
        RestoreOutcome::Complete => "complete",
        _ => "unknown",
    }
}

/// Guarded restore: the (P)rovenance + (S)cope checks live in
/// `restore_full_guarded`; this binding only shapes its `RestoreResult` for
/// Python and never re-derives any of the guard logic.
///
/// `nonce=None` skips building an `Anchor` at all, so `restore_full_guarded`
/// takes its unguarded branch — same as calling `restore()` with no anchor,
/// always `outcome="complete"`. Passing a real `nonce` that the text never
/// echoes is a different case: an `Anchor` IS built, and the provenance check
/// inside `restore_full_guarded` is the thing that fails closed
/// (`outcome="blocked"`). Deciding when a bare `guard=True` call (no anchor at
/// all) should count as the latter is a policy call for the Python `restore()`
/// shim to make, not this binding.
///
/// Returns `(restored, alias_collisions, events, outcome)` where each event is
/// `{"kind": str, "count": int, "tokens": list[str] | None}` — `tokens` is the
/// core `GuardEvent.detail` carrier verbatim, no reason-code prose. Python
/// owns rendering any human-readable message from these.
#[pyfunction]
#[pyo3(signature = (text, key, aliases=None, display_marker=None, nonce=None, scope=None))]
#[allow(clippy::too_many_arguments)]
pub fn restore_guarded<'py>(
    py: Python<'py>,
    text: &str,
    key: HashMap<String, String>,
    aliases: Option<HashMap<String, Vec<String>>>,
    display_marker: Option<String>,
    nonce: Option<String>,
    scope: Option<Vec<String>>,
) -> PyResult<(String, Vec<String>, Vec<Py<PyDict>>, &'static str)> {
    let anchor = nonce.map(|nonce| Anchor::new(nonce, scope.unwrap_or_default().into_iter().collect()));

    let result = core_restore_full_guarded(
        text,
        &key,
        aliases.as_ref(),
        display_marker.as_deref(),
        anchor.as_ref(),
    )
    .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

    let events: Vec<Py<PyDict>> = result
        .events
        .iter()
        .map(|event| {
            let d = PyDict::new(py);
            d.set_item("kind", guard_event_kind_str(&event.kind))?;
            d.set_item("count", event.count)?;
            d.set_item("tokens", event.detail.clone())?;
            Ok(d.unbind())
        })
        .collect::<PyResult<Vec<_>>>()?;

    let outcome = restore_outcome_str(&result.outcome);

    Ok((result.restored, result.alias_collisions, events, outcome))
}

/// Check whether LLM output has suspicious pseudonym usage (possible injection).
///
/// Returns a list of warning strings. Empty list = safe.
/// Mirrors `pure/restore.check_restore_safety`.
#[pyfunction]
#[pyo3(signature = (redacted, llm_output, key))]
pub fn check_restore_safety(
    redacted: &str,
    llm_output: &str,
    key: HashMap<String, String>,
) -> Vec<String> {
    core_check_safety(redacted, llm_output, &key)
}

/// Stateful, unguarded restore session.
///
/// Owns a [`RestoreSession`]: the key/alias merge and the compiled
/// longest-first alternation regex are built once at construction, then
/// reused across every `restore_cell` call — mirrors `StructuredRedactor`
/// (`replace.rs`) on the redact side, but the session here is just owned
/// data plus a compiled `Regex`, so it needs neither a factory nor a
/// `'static` lifetime bound. Bulk callers (structured CSV/JSON, streaming)
/// route through this instead of the stateless [`restore`] to avoid
/// re-merging and re-compiling the same key on every cell.
#[pyclass]
pub struct StructuredRestorer {
    session: RestoreSession,
}

#[pymethods]
impl StructuredRestorer {
    #[new]
    #[pyo3(signature = (key, aliases=None))]
    fn new(
        key: HashMap<String, String>,
        aliases: Option<HashMap<String, Vec<String>>>,
    ) -> PyResult<Self> {
        RestoreSession::new(&key, aliases.as_ref())
            .map(|session| Self { session })
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Restore one cell of text against the session's precomputed key.
    fn restore_cell(&self, text: &str) -> PyResult<String> {
        self.session
            .restore_cell(text)
            .map(|r| r.restored)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Drop all cached key/alias/regex state. After this, `restore_cell`
    /// returns its input unchanged.
    fn wipe(&mut self) {
        self.session.wipe();
    }

    /// Same effect as [`wipe`](Self::wipe), for callers that model the
    /// session as a resource to explicitly close.
    fn close(&mut self) {
        self.session.close();
    }
}
