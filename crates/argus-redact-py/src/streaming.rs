//! PyO3 bindings for the streaming carry-window state machine — `_core.*`
//! mirrors of `glue/_detect_partial.py`'s helpers, plus the `StreamingRestorer`
//! boundary split.
//!
//! The carry-window ENGINE (boundary scan, the bounded-drain decision tree) lives
//! in `argus_redact_core::streaming` (the SSOT). Two pieces stay in Python and are
//! threaded back in as callables:
//!
//! - The entity-aware SNAP (`_carry_cut_index`): it detects on the full combined
//!   buffer with the caller's exact `lang`/`mode`/`names`/`types`/`types_exclude`
//!   params (the full L1+NER+semantic orchestration). The Python streaming tests
//!   ALSO monkeypatch `_carry_cut_index` directly, so the cut MUST remain a Python
//!   callable. [`consume_to_boundary`] therefore takes a `carry_cut` callable
//!   (`(combined, target) -> cut`) invoked exactly where the Python
//!   `_consume_to_boundary` called `_carry_cut_index`.
//!
//! This keeps the thin-shim contract: the Python `_consume_to_boundary` /
//! `_last_boundary_index` / `_bounded_carry` and the `StreamingRestorer` boundary
//! logic all delegate here; only the detection SSOT (and the redaction pipeline,
//! threaded through `redact_pseudonym_llm`) stay in Python.

use pyo3::prelude::*;

use argus_redact_core::streaming::{
    bounded_carry as core_bounded_carry, consume_to_boundary as core_consume_to_boundary,
    last_boundary_index as core_last_boundary_index, restorer_split as core_restorer_split,
    snap_cut as core_snap_cut, unclosed_pem_opener_start as core_unclosed_pem_opener_start,
};

/// Index *after* the rightmost REAL sentence-boundary char (`-1` if none).
///
/// Mirrors `glue/_detect_partial._last_boundary_index`: `\n` + CJK `。！？；` always
/// count; ASCII `.!?;` count only when followed by whitespace and never at the
/// buffer end. CHAR-index (Python `str`-index) semantics.
#[pyfunction]
pub fn streaming_last_boundary_index(text: &str) -> isize {
    core_last_boundary_index(text)
}

/// `(emit, residual)` for the `cut <= 0` bounded-drain guard.
///
/// Mirrors `glue/_detect_partial._bounded_carry`: at/above `max_buffer` (CHARS),
/// drain the prefix down to the trailing carry window; below it, carry everything.
#[pyfunction]
pub fn streaming_bounded_carry(combined: &str, max_buffer: usize) -> (String, String) {
    core_bounded_carry(combined, max_buffer)
}

/// Split `prev_buffer + chunk` at the last SAFE cut → `(emit_text, residual)`.
///
/// Mirrors `glue/_detect_partial._consume_to_boundary`. `carry_cut` is a Python
/// callable `(combined, target) -> cut` (CHAR indices) invoked at the boundary /
/// force-flush snap — the Python shim passes the module-level `_carry_cut_index`
/// (which detects on the full combined buffer with the caller's exact detection
/// params and snaps the cut back off any straddling entity / evidence-gated
/// candidate). `carry_cut_drain` is its CLOSED-ONLY twin, invoked ONLY for the
/// `cut == 0` bounded drain so a forced drain never SPLITS an entity even when
/// `carry_cut`'s widening chained the carry back to 0. Threading the cuts as
/// callables both preserves the carry decision (the A2 invariant) AND keeps the
/// Python `_carry_cut_index` monkeypatchable (the boundary-path-drain test).
#[pyfunction]
#[pyo3(signature = (prev_buffer, chunk, carry_cut, carry_cut_drain, *, max_buffer, force_flush=false))]
pub fn streaming_consume_to_boundary(
    py: Python<'_>,
    prev_buffer: &str,
    chunk: &str,
    carry_cut: Py<PyAny>,
    carry_cut_drain: Py<PyAny>,
    max_buffer: usize,
    force_flush: bool,
) -> PyResult<(String, String)> {
    // The carry_cut callbacks may raise; capture the first error and surface it
    // after the engine returns (the engine itself is infallible). A RefCell holds
    // the error so the closures stay `Fn` (the core API takes `&C`).
    let err: std::cell::RefCell<Option<PyErr>> = std::cell::RefCell::new(None);

    let call = |cb: &Py<PyAny>, combined: &str, target: usize| -> usize {
        if err.borrow().is_some() {
            return target;
        }
        match cb.bind(py).call1((combined, target)) {
            Ok(obj) => match obj.extract::<usize>() {
                Ok(cut) => cut,
                Err(e) => {
                    *err.borrow_mut() = Some(e);
                    target
                }
            },
            Err(e) => {
                *err.borrow_mut() = Some(e);
                target
            }
        }
    };

    let cut_fn = |combined: &str, target: usize| call(&carry_cut, combined, target);
    let drain_fn = |combined: &str, target: usize| call(&carry_cut_drain, combined, target);

    let (emit, residual) =
        core_consume_to_boundary(prev_buffer, chunk, max_buffer, force_flush, &cut_fn, &drain_fn);

    if let Some(e) = err.into_inner() {
        return Err(e);
    }
    Ok((emit, residual))
}

/// Snap an emit `target` back to a SAFE cut over the detected entity spans.
///
/// `spans` is the post-merge `(start, end, type_)` entity set Python's `_detect`
/// produced over the full combined buffer (CHAR offsets); the snap pulls the cut
/// back off any entity straddling it AND (when `widen`) off any evidence-gated
/// candidate (region/occupation/condition/hobby) whose corroborating cue /
/// proximate PII would land on the far side of the cut. `widen = False` is the
/// closed-only drain fallback (split-avoidance without the ±margin orphan
/// guard). Mirrors `glue/_detect_partial._carry_cut_index`'s loop — keeping the
/// snap RULE single-sourced in the core so the Python wheel and the wasm path
/// pick identical cuts (no silent leak from a drifted duplicate). Returns the
/// CHAR cut index (`0` = carry everything).
#[pyfunction]
pub fn streaming_snap_cut(spans: Vec<(usize, usize, String)>, target: usize, widen: bool) -> usize {
    core_snap_cut(&spans, target, widen)
}

/// CHAR offset of the start of the last UNCLOSED PEM private-key opener in
/// `combined` (`-----BEGIN … PRIVATE KEY-----` with no matching `-----END …`
/// after it), else `None`. The Python snap (`_carry_cut_index`) appends a
/// `(begin, len, "ssh_private_key")` pending span when this returns a start, so a
/// multi-line key in flight is carried whole (never emitted line-by-line in
/// plaintext) until END arrives. Single-sourced with the core engine's own
/// force-flush-ceiling check, so wheel + wasm agree.
#[pyfunction]
pub fn streaming_unclosed_pem_opener_start(combined: &str) -> Option<usize> {
    core_unclosed_pem_opener_start(combined)
}

/// Split a restorer buffer at its last REAL sentence boundary → `(complete, residual)`.
///
/// Mirrors the boundary logic in `streaming.StreamingRestorer.feed`, which now
/// shares the redactor's `last_boundary_index` rule: `\n` + CJK `。！？；` always
/// count; ASCII `.!?;` count ONLY before whitespace and NEVER at the buffer end (a
/// realistic fake's internal dot — email/IPv4 — can be the rightmost char). Flushing
/// on such an ambiguous dot would emit a half-token and leave the pseudonym
/// unrestored. Returns `("", buffer)` when no real boundary is present (buffer
/// everything). The Python shim then restores `complete` via the unified key.
#[pyfunction]
pub fn streaming_restorer_split(buffer: &str) -> (String, String) {
    core_restorer_split(buffer)
}
