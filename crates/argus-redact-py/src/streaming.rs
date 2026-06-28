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
//! - [`streaming_pem_begin_present`] — the force-flush ceiling gate (literal AND
//!   the private-key regex), so the wheel and wasm raise the ceiling on exactly the
//!   same PEM blocks.
//! - [`streaming_restorer_split`] — the `StreamingRestorer` boundary split.
//!
//! The detection orchestration (`_detect`) and the redaction pipeline
//! (`redact_pseudonym_llm`) stay in Python; everything cut-shaped is core.

use pyo3::prelude::*;

use argus_redact_core::streaming::{
    context_cut as core_context_cut, last_boundary_index as core_last_boundary_index,
    pem_begin_present as core_pem_begin_present, restorer_split as core_restorer_split,
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

/// `true` if `combined` holds a PEM private-key BEGIN marker (the literal
/// `-----BEGIN ` AND the full private-key regex) — complete OR in-flight. Drives the
/// force-flush ceiling raise in `glue/_detect_partial._context_cut` so the wheel and
/// the wasm path (core `feed` → `pem_max_buffer`) raise the ceiling on EXACTLY the
/// same blocks: a `-----BEGIN CERTIFICATE-----` / public-key / CSR block (literal but
/// not a private key) does NOT raise it. SSOT: `core::pem_begin_present`.
#[pyfunction]
pub fn streaming_pem_begin_present(combined: &str) -> bool {
    core_pem_begin_present(combined)
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
