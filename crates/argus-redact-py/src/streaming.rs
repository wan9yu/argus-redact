//! PyO3 bindings for the streaming detection-context-window state machine —
//! `_core.streaming_*` mirrors of the helpers `glue/_detect_partial.py` and
//! `streaming.StreamingRestorer` call, all delegating to the
//! `argus_redact_core::streaming` SSOT.
//!
//! The cut ENGINE (boundary scan, forward hold-back, left-context overlap, the
//! straddle snap, and the bounded-drain decision tree) lives entirely in core. The
//! bindings are plain value calls — NO Python callables are threaded back in and
//! NOTHING here is monkeypatched:
//!
//! - [`streaming_context_cut`] — the per-round emit cut. Python detects ONCE over
//!   the full buffer in `_context_cut`, passes the resulting spans (plus any
//!   in-flight PEM opener pending span) as a value, and gets back `(cut, redetect)`.
//!   `redetect` flags the forced bounded-drain split that needs the emit slice
//!   re-detected (see `argus_redact_core::streaming::ContextCut`).
//! - [`streaming_last_boundary_index`] — the sentence-boundary scan.
//! - [`streaming_unclosed_pem_opener_start`] — start of an in-flight PEM key (the
//!   open-ended pending span the snap holds the cut before).
//! - [`streaming_unclosed_jwt_opener_start`] — start of an unclosed end-of-buffer
//!   JWT run. The wheel appends `(begin, len+1, "jwt")` from this offset and
//!   does not re-scan.
//! - [`streaming_effective_max_buffer`] — the one ceiling both cut inputs see
//!   (PEM extra and JWT extra added to the caller base).
//! - [`streaming_restorer_split`] — the `StreamingRestorer` boundary split.
//!
//! The detection orchestration (`_detect`) and the redaction pipeline
//! (`redact_pseudonym_llm`) stay in Python; everything cut-shaped is core.

use pyo3::prelude::*;

use argus_redact_core::streaming::{
    context_cut as core_context_cut, effective_max_buffer as core_effective_max_buffer,
    emit_possible as core_emit_possible, last_boundary_index as core_last_boundary_index,
    restorer_split as core_restorer_split,
    unclosed_jwt_opener_start as core_unclosed_jwt_opener_start,
    unclosed_pem_opener_start as core_unclosed_pem_opener_start,
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


/// Pick the streaming emit cut for a buffer whose char content is `text`. Returns
/// `(cut, redetect)`.
///
/// Converts `text` to a char slice (Python-str-equivalent char count), then delegates
/// to `core::context_cut(spans, chars, ctx_len, max_buffer, w, force_flush)`. `cut` is
/// the CHAR index up to which the buffer is safe to emit (`cut == ctx_len` = hold);
/// `redetect` is `true` only on the forced bounded-drain split, where the caller must
/// RE-DETECT the emit slice `[ctx_len, cut)` rather than range-shift the full-buffer
/// detection (the full-buffer straddler would be dropped and its head leaked raw).
///
/// `spans` are the straddle-snap spans over the WHOLE buffer (normalized entities plus
/// the in-flight PEM opener pending span if any). `ctx_len` is the size of the retained
/// already-emitted left-context prefix. `w` is `EVIDENCE_CONTEXT_WINDOW` (128).
/// Mirrors `glue/_detect_partial._context_cut`.
#[pyfunction]
pub fn streaming_context_cut(
    text: &str,
    spans: Vec<(usize, usize, String)>,
    ctx_len: usize,
    max_buffer: usize,
    w: usize,
    force_flush: bool,
) -> (usize, bool) {
    let chars: Vec<char> = text.chars().collect();
    let cc = core_context_cut(&spans, &chars, ctx_len, max_buffer, w, force_flush);
    (cc.cut, cc.redetect)
}

/// `true` when the streaming buffer MIGHT emit on the next cut — a
/// spans-INDEPENDENT conservative upper bound. Converts `text` to `Vec<char>` and
/// delegates to `argus_redact_core::streaming::emit_possible`. Returns `false` only
/// when `context_cut` is GUARANTEED to hold regardless of spans (no sentence boundary
/// in the safe window, buffer below `max_buffer`, and `force_flush` is `false`).
/// Mirrors the gate added to `core::StreamingRedactor::feed` so the Python
/// `_context_cut` can skip the expensive `_detect` on a provably-holding feed.
#[pyfunction]
pub fn streaming_emit_possible(
    text: &str,
    ctx_len: usize,
    max_buffer: usize,
    w: usize,
    force_flush: bool,
) -> bool {
    let chars: Vec<char> = text.chars().collect();
    core_emit_possible(&chars, ctx_len, max_buffer, w, force_flush)
}

/// Force-flush ceiling for `combined` given the caller `base`.
///
/// Adds the PEM extra while a private-key BEGIN is present and the JWT extra
/// while an unclosed-at-EOS opener exists or a closed validated JWT is longer
/// than the carry window. A short completed JWT does not raise. The wheel
/// passes this one value to both `streaming_emit_possible` and
/// `streaming_context_cut`. SSOT: `core::effective_max_buffer`.
#[pyfunction]
pub fn streaming_effective_max_buffer(combined: &str, base: usize) -> usize {
    core_effective_max_buffer(combined, base)
}

/// CHAR offset of the start of the last UNCLOSED PEM private-key opener in
/// `combined` (`-----BEGIN … PRIVATE KEY-----` with no matching `-----END …`
/// after it), else `None`. `glue/_detect_partial._context_cut` appends a
/// `(begin, len+1, "ssh_private_key")` pending span when this returns a start, so a
/// multi-line key in flight is carried whole (never emitted line-by-line in
/// plaintext) until END arrives. Single-sourced with the core engine's own
/// force-flush-ceiling check, so wheel + wasm agree.
#[pyfunction]
pub fn streaming_unclosed_pem_opener_start(combined: &str) -> Option<usize> {
    core_unclosed_pem_opener_start(combined)
}

/// CHAR offset of the rightmost UNCLOSED JWT opener in `combined`, else `None`.
///
/// `glue/_detect_partial._context_cut` appends `(begin, len+1, "jwt")` when this
/// returns a start. A complete token returns `None`, so `begin` is never placed
/// inside one. The wheel must not re-scan. SSOT: `core::unclosed_jwt_opener_start`.
#[pyfunction]
pub fn streaming_unclosed_jwt_opener_start(combined: &str) -> Option<usize> {
    core_unclosed_jwt_opener_start(combined)
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
