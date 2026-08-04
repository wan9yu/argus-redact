//! Streaming carry-window state machine — the SSOT for incremental redaction.
//!
//! This is the Rust port of the carry-window engine that lived in
//! `glue/_detect_partial.py` + `streaming.py` (the carry-window engine hardened in
//! v0.7.10, which fixed two boundary-split PII leaks). The state machine buffers
//! chunks until a SAFE cut
//! point, emits the committed prefix for redaction, and carries the unconsumed
//! tail into the next round so an entity straddling the cut is never split (which
//! would leak its head unredacted — neither half matches its pattern alone).
//!
//! ## The carry-window functions
//!
//! - [`last_boundary_index`] — index *after* the rightmost REAL sentence boundary.
//!   `\n` + the CJK full-width `。！？；` ALWAYS count (they never appear inside an
//!   ASCII entity and CJK sentences carry no trailing space). The ASCII boundaries
//!   `.!?;` count ONLY when the NEXT char is whitespace; at the buffer END (no next
//!   char) an ASCII boundary is ambiguous (`. ` sentence-end vs `.com` intra-entity)
//!   and does NOT count — wait for the next chunk.
//! - [`snap_cut`] — snap a proposed cut back to a SAFE position that never splits a
//!   detected entity (straddle-only). [`StreamingRedactor`] detects once over a
//!   buffer carrying ±W of context and redacts the emit range with THAT detection —
//!   so the cut location can no longer strip a candidate of its evidence.
//! - [`context_cut`] — the [`StreamingRedactor`] cut rule: the last sentence
//!   boundary that still leaves ≥ `W` (= [`EVIDENCE_CONTEXT_WINDOW`]) chars of
//!   forward context buffered, snapped off any straddled entity. The buffer also
//!   retains the last `W` already-emitted chars as left-context (detection only).
//!
//! ## Generic over detection + redaction (no PyO3, no registry — like `redact_l1`)
//!
//! The state machine's entity-aware snap step ([`snap_cut`] / [`context_cut`]) needs
//! entity spans over the combined buffer. To keep this core module free of PyO3 /
//! Python glue, the spans come from a caller-supplied detect closure (`Fn(&str) ->
//! DetectSpans`). [`StreamingRedactor`] is likewise generic over a
//! redact-with-entities closure (`Fn(&str, &DetectSpans) -> Result<RedactSegment,
//! String>`) that redacts the emit text using the GIVEN pre-detected, range-shifted
//! spans — no internal re-detect. The Python shim threads `redact_pseudonym_llm`
//! (with pre-detected entities) through it; wasm threads `replace` + grammar tail
//! over the pre-detected entities.
//! The accumulated key + carry-window buffer (the actual streaming STATE) live
//! here, in the SSOT.
//!
//! ## Cross-sentence evidence: the detection-context window
//!
//! The evidence-gated L1 detectors (region/occupation/condition/hobby) fire only
//! on a nearby cue or proximate PII. [`StreamingRedactor`] keeps the emitted text
//! classified with the SAME ±W context batch would give it: it never emits within
//! `W` of the buffer end (forward hold-back, so a candidate's forward window
//! always exists before it commits) and retains the last `W` emitted chars as
//! left-context (so a prior-sentence cue is back in scope when its candidate
//! arrives). One detect-on-full per round drives both the cut and the redaction,
//! so the cut location never strips a candidate of its evidence.
//!
//! **Guarantee:** `stream(chunks) ≡ batch(concat(chunks))` for every input whose
//! corroborating evidence lies within `±W` (`W` = [`EVIDENCE_CONTEXT_WINDOW`]).
//! The single residual edge is a candidate whose *sole* evidence is a corroborator
//! LONGER than `W` straddling the lookahead: a bounded buffer cannot wait for an
//! arbitrarily long entity to finish before committing the candidate. PEM/SSH keys
//! are held whole by the opener mechanism below, but other long corroborators are
//! not — notably a `url_token` whose `?token=` sits `>W` chars into the URL, which
//! can leave a proximate region/hobby uncorroborated in the stream while batch,
//! seeing the whole URL, redacts it. The leaked term is then a low-sensitivity
//! quasi-identifier (the long corroborator itself is still redacted). Narrowing
//! this further — by dropping such technical, non-personal PII from the evidence
//! set — is a detector-precision question, separate from this bounded-streaming
//! limit. Documented, not a defect of the window.

use std::collections::HashMap;
use std::sync::LazyLock;

use fancy_regex::Regex;

use crate::coverage::{restore_lost_coverage, FilterScope};
use crate::hints::{filter_self_reference, Hint};
use crate::merger::merge_entities_with_text;
use crate::restore::{RestoreError, RestoreSession};
use crate::types::PatternMatch;

/// Sentence-boundary chars that ALWAYS terminate a unit: `\n` and the CJK
/// full-width punctuation. They never appear inside an ASCII entity (email/IPv4
/// use `.`), and CJK sentences have no trailing space, so a CJK boundary is
/// unambiguous even at the buffer end. Mirrors `_ALWAYS_BOUNDARIES`.
const ALWAYS_BOUNDARIES: [char; 5] = ['\n', '。', '！', '？', '；'];

/// The ASCII boundary chars. `.`/`!`/`?`/`;` double as intra-entity chars (an
/// email/IPv4 dot, `a;b` in some tokens), so they count as a sentence end ONLY
/// when the next buffer char is whitespace — and never at the buffer end, where
/// the next char is unknown. Mirrors `_ASCII_BOUNDARIES`.
const ASCII_BOUNDARIES: [char; 4] = ['.', '!', '?', ';'];

/// Whitespace chars that disambiguate a trailing ASCII boundary as a real
/// sentence end. Mirrors `_WHITESPACE`.
const WHITESPACE: [char; 3] = [' ', '\t', '\n'];

/// Maximum buffer size (in CHARS) before forcing a flush on boundary-less input.
/// Mirrors `DEFAULT_MAX_BUFFER`.
pub const DEFAULT_MAX_BUFFER: usize = 4096;

/// Trailing window (in CHARS) carried into the next chunk at a boundary-less
/// force-flush. Must be ≥ the longest BOUNDED entity span so a straddling entity
/// always fits inside the carried region. Mirrors `_CARRY_WINDOW`.
pub const CARRY_WINDOW: usize = 256;

/// The detection-context window `W` (in CHARS) the [`StreamingRedactor`] holds on
/// each side of every emit so streaming detection equals batch detection for the
/// evidence-gated L1 detectors (region/occupation/condition/hobby).
///
/// Derived, not a round number: an evidence-gated candidate fires on a cue within
/// `±40` (the detectors' `*_WINDOW`) OR a corroborating PII within proximity `50`
/// (`*_PROX_NEAR`) — and the PII must be FULLY present to be detected, so the
/// proximity reach is `50 + the corroborator's own length`. The realistic
/// structural corroborators (phone ~15, id 18, bank 19, email ~30-40) cap around
/// `50 + ~78 ≈ 128`, which also dominates the `40` cue window. A `>128`-char
/// corroborator is the documented residual edge (see the module-level guarantee).
///
/// Parity-by-convention across the snap copies, like [`CARRY_WINDOW`] /
/// [`DEFAULT_MAX_BUFFER`]. (Alternative considered: reuse `CARRY_WINDOW = 256` —
/// one fewer constant, more margin, ~one extra sentence of latency.)
pub const EVIDENCE_CONTEXT_WINDOW: usize = 128;

fn is_always_boundary(c: char) -> bool {
    ALWAYS_BOUNDARIES.contains(&c)
}

fn is_ascii_boundary(c: char) -> bool {
    ASCII_BOUNDARIES.contains(&c)
}

fn is_whitespace(c: char) -> bool {
    WHITESPACE.contains(&c)
}

/// Index *after* the rightmost REAL sentence-boundary char in `chars`. `-1` (here
/// returned as `None`) if none. Mirrors `_last_boundary_index`, operating on a
/// CHAR slice so multi-byte chars are counted as 1 (Python `str` semantics).
///
/// Returns `Some(char_index_after_boundary)` or `None`.
fn last_boundary_index_chars(chars: &[char]) -> Option<usize> {
    let n = chars.len();
    for pos in (0..n).rev() {
        let ch = chars[pos];
        if is_always_boundary(ch) {
            return Some(pos + 1);
        }
        if is_ascii_boundary(ch) {
            // Real sentence end only if followed by whitespace; at the buffer end
            // the next char is unknown → ambiguous, keep scanning leftward.
            if pos + 1 < n && is_whitespace(chars[pos + 1]) {
                return Some(pos + 1);
            }
        }
    }
    None
}

/// Index *after* the rightmost REAL sentence-boundary char in `text`. `-1` if none.
///
/// Public CHAR-space mirror of `_last_boundary_index` (the Python helper returns a
/// `str`-index; this returns the same CHAR index, or `-1` when absent). Used by
/// the PyO3 shim's `_last_boundary_index` parity binding.
pub fn last_boundary_index(text: &str) -> isize {
    let chars: Vec<char> = text.chars().collect();
    match last_boundary_index_chars(&chars) {
        Some(i) => i as isize,
        None => -1,
    }
}


/// Raw detection input for the [`StreamingRedactor`] detect closure: the
/// `layer1 ++ person` (+ evidence-gated) entities plus the L1 `hints`, exactly as
/// a fast-mode `detect_l1` produces them. [`StreamingRedactor::detect_final`]
/// normalizes them internally (`merge_entities_with_text` → `filter_self_reference`
/// → `restore_lost_coverage`) before the cut and redaction steps, so callers may
/// thread the RAW overlapping set unchanged.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DetectSpans {
    /// Raw `layer1 ++ person` entities over the combined buffer (CHAR-space spans).
    pub entities: Vec<PatternMatch>,
    /// L1 hints over the combined buffer (drive `filter_self_reference`).
    pub hints: Vec<Hint>,
}

/// Snap `target` back to a SAFE cut over the normalized entity spans (each
/// `(start, end, type_)`, CHAR-space `[start, end)`) of the combined buffer.
///
/// Straddle-only: a cut is unsafe only if it would SPLIT a closed entity span
/// (`start < cut < end`); it then snaps back to that entity's start so the entity
/// is carried whole (neither half matches its pattern alone, so a split = a
/// verbatim leak). The span type is ignored — with the detection-context window
/// ([`StreamingRedactor`] detects once over ±W of context and redacts the emit
/// range with that detection), the cut location can no longer orphan an
/// evidence-gated candidate from its evidence, so the old per-type widening is
/// gone. Iterates to a FIXED POINT because snapping one span's cut back can expose
/// a straddle of another (a neighbouring entity the new cut now lands inside). The
/// cut strictly decreases each round, bounded below by 0, so this terminates. `0`
/// means "carry everything" (the unbounded-token residual edge / an entity from
/// the buffer start past the cut).
///
/// SSOT for the snap rule: the wasm path and the Python wheel path both call it
/// (via [`StreamingRedactor`] / the PyO3 `context_cut` binding), so the cut is
/// byte-identical across runtimes.
pub fn snap_cut(spans: &[(usize, usize, String)], target: usize) -> usize {
    let mut cut = target;
    loop {
        let mut next = cut;
        for (start, end, _type_) in spans {
            if *start < cut && cut < *end && *start < next {
                next = *start;
            }
        }
        if next == cut {
            return cut;
        }
        cut = next;
    }
}

/// The cut [`StreamingRedactor`] picks on a buffer that always carries ±`w` of
/// detection context. Result of [`context_cut`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextCut {
    /// CHAR index in the buffer up to which to emit. `cut == ctx_len` means
    /// "nothing new is safe to emit yet" (the buffer is held).
    pub cut: usize,
    /// `true` only on the forced bounded-drain split (a boundary-less buffer that
    /// grew to `max_buffer` and whose sole entity spans from `ctx_len` past the
    /// drain point, so the cut MUST split it). The emit range `[ctx_len, cut)` then
    /// has to be RE-DETECTED in isolation and redacted with those slice-local
    /// spans — the full-buffer straddler [`shift_spans`] would otherwise DROP
    /// (`end > cut`) leaks its head raw. A boundary-less mega-buffer carries no
    /// cross-sentence evidence, so re-detecting the bare slice is correct here
    /// (it restores the pre-rework drain safety). `false` on every other path
    /// (boundary cut, clean-snap drain, hold, force-flush): the emit range uses
    /// the range-shifted full-buffer detection.
    pub redetect: bool,
}

/// Pick the [`StreamingRedactor`] emit cut over a buffer of `chars` that retains
/// the last `w` already-emitted chars (`ctx_len` of them, as left-context) and
/// holds back the last `w` chars (forward context). `spans` are the normalized
/// snap spans over the WHOLE buffer (merged + self-ref-filtered entities plus the
/// in-flight PEM opener pending span, if any — see [`StreamingRedactor::snap_spans`]).
///
/// The cut is the LAST real sentence boundary that (a) leaves ≥ `w` tail buffered
/// (`≤ len − w`) and (b) lies past the already-emitted left-context (`> ctx_len`),
/// then snapped back off any straddled entity via [`snap_cut`]. `force_flush`
/// drains everything past `ctx_len` (`cut = len`). When no such boundary exists —
/// none present, all within the hold-back window, or the snap chained back to/under
/// `ctx_len` — the buffer is HELD (`cut = ctx_len`), UNLESS it has grown to
/// `max_buffer`, in which case it is bounded-drained (`len − CARRY_WINDOW`, snapped
/// off a straddle) so it can never grow without bound.
///
/// [`ContextCut::redetect`] is set only when the bounded drain is FORCED to split a
/// span (so the emit slice must be re-detected, see [`bounded_drain_cut`]); every
/// boundary / clean-snap / hold / force-flush cut leaves it `false`.
pub fn context_cut(
    spans: &[(usize, usize, String)],
    chars: &[char],
    ctx_len: usize,
    max_buffer: usize,
    w: usize,
    force_flush: bool,
) -> ContextCut {
    let len = chars.len();
    if force_flush {
        return ContextCut { cut: len, redetect: false };
    }
    let safe_end = len.saturating_sub(w);
    if safe_end > ctx_len {
        if let Some(target) = last_boundary_index_chars(&chars[..safe_end]) {
            if target > ctx_len {
                let cut = snap_cut(spans, target);
                if cut > ctx_len {
                    return ContextCut { cut, redetect: false };
                }
                // else: the snap chained back to/under ctx_len (a span straddles
                // the whole emittable region) — fall through to the bounded drain.
            }
        }
    }
    // No usable boundary. Hold everything, unless the buffer would otherwise grow
    // without bound (≥ max_buffer): then force a bounded drain.
    if len >= max_buffer {
        let (cut, redetect) = bounded_drain_cut(spans, len, ctx_len);
        return ContextCut { cut, redetect };
    }
    ContextCut { cut: ctx_len, redetect: false }
}

/// True iff [`context_cut`] could possibly emit for this buffer — the
/// spans-INDEPENDENT triggers of [`context_cut`] (force-flush, a real sentence
/// boundary leaving ≥ `w` forward context, or the `>= max_buffer` drain).
/// Lets [`StreamingRedactor::feed`] skip the expensive detect + [`context_cut`] on
/// a feed that provably holds. CONSERVATIVE: it must be `true` whenever
/// [`context_cut`] would emit (it may be `true` and then [`context_cut`] still
/// holds when the snap pulls the boundary back — that just costs a wasted detect,
/// never a wrong skip).
///
/// Mirrors [`context_cut`]'s emit triggers EXACTLY: same `force_flush`, same
/// `len >= max_buffer` drain check, and the same `last_boundary_index_chars` scan
/// over `chars[..len - w]` requiring `target > ctx_len`. The ONLY part of
/// [`context_cut`] it omits is the spans-dependent [`snap_cut`] refinement, which
/// can only pull a cut BACK to `ctx_len` (hold) — never the other way — so the
/// omission keeps `emit_possible` a strict superset of the emit set. Callers MUST
/// pass the SAME `max_buffer` ([`StreamingRedactor::pem_max_buffer`]) and `w`
/// ([`EVIDENCE_CONTEXT_WINDOW`]) they pass to [`context_cut`].
pub fn emit_possible(
    chars: &[char],
    ctx_len: usize,
    max_buffer: usize,
    w: usize,
    force_flush: bool,
) -> bool {
    if force_flush {
        return true;
    }
    let len = chars.len();
    if len >= max_buffer {
        return true;
    }
    let safe_end = len.saturating_sub(w);
    safe_end > ctx_len
        && last_boundary_index_chars(&chars[..safe_end]).is_some_and(|t| t > ctx_len)
}

/// The [`context_cut`] bounded-drain cut: `(cut, redetect)`. Drains at
/// `len − CARRY_WINDOW`, snapped CLOSED off any straddled entity so the forced
/// drain never SPLITS a *closed* span that fits. Returns:
///
/// - `(ctx_len, false)` — cannot make forward progress (`len ≤ CARRY_WINDOW`, or
///   the drain target is at/under `ctx_len`): HOLD; it grows past the window and
///   drains next round. The caller still emits nothing.
/// - `(drain, false)` — the snap pulled the cut CLEANLY back to a span start above
///   `ctx_len`: no entity straddles `drain`, so the emit range uses the
///   range-shifted full-buffer detection like any boundary cut.
/// - `(target, true)` — the snap chained back to/under `ctx_len`, i.e. a single
///   entity spans from `ctx_len` (or the buffer start) past the drain point and a
///   split is unavoidable (the `>window` mega-entity edge: a ≥`max_buffer`
///   boundary-less JWT / api-key / url_token). We force the raw `len − CARRY_WINDOW`
///   cut — which is `> ctx_len`, GUARANTEEING forward progress so the buffer can
///   never grow unbounded — and set `redetect` so the caller RE-DETECTS the emit
///   slice (its head is a complete typed token that re-detection redacts, instead
///   of [`shift_spans`] dropping the full-buffer straddler and leaking it raw).
fn bounded_drain_cut(spans: &[(usize, usize, String)], len: usize, ctx_len: usize) -> (usize, bool) {
    if len <= CARRY_WINDOW {
        // Cannot drain below the carry window without underflow; hold (it will grow
        // past the window and drain next round).
        return (ctx_len, false);
    }
    let target = len - CARRY_WINDOW;
    if target <= ctx_len {
        // Draining would underflow into the retained left-context; hold.
        return (ctx_len, false);
    }
    let drain = snap_cut(spans, target);
    if drain > ctx_len {
        // Clean snap off a closed straddler (or no straddle): nothing straddles the
        // cut, so the range-shifted detection is safe — no re-detect needed.
        (drain, false)
    } else {
        // The snap chained to/under ctx_len: a single entity runs from ctx_len past
        // the drain point. Force the split at the raw target (forward progress) and
        // re-detect the emit slice so its head is redacted, not dropped.
        (target, true)
    }
}

/// PEM private-key BEGIN / END markers. These MIRROR the `ssh_private_key` pattern
/// in `data/shared.ron` (parity-by-convention — keep both in sync). A multi-line
/// PEM key is the one bounded entity whose interior contains `\n` ALWAYS_BOUNDARIES,
/// so the carry/snap must treat an in-flight (BEGIN-but-no-END) key specially or it
/// emits the head line-by-line in plaintext before the END marker ever arrives.
static PEM_BEGIN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-----BEGIN (?:RSA |OPENSSH |DSA |EC )?PRIVATE KEY-----")
        .unwrap_or_else(|e| panic!("streaming: PEM_BEGIN_RE compile failed: {e}"))
});
static PEM_END_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-----END (?:RSA |OPENSSH |DSA |EC )?PRIVATE KEY-----")
        .unwrap_or_else(|e| panic!("streaming: PEM_END_RE compile failed: {e}"))
});

/// The pending-span type label for an in-flight PEM opener. [`snap_cut`] is
/// type-agnostic and treats the `[begin, len)` span with the closed-entity straddle
/// rule (snap the cut back to `begin`), which is exactly what carrying an
/// unterminated key whole requires.
const PEM_OPENER_TYPE: &str = "ssh_private_key";

/// Extra CHARS of force-flush headroom granted while a PEM opener is in flight, on
/// top of `max_buffer`. Covers the `ssh_private_key` body bound (10000) + the
/// markers + slack, so a valid key accumulates WHOLE before `END` arrives instead
/// of being force-flush-split. Bounded (a CAP): past `max_buffer + this`, an
/// unterminated BEGIN is treated as malformed/adversarial and bounded-drained (the
/// documented head-leak edge) rather than growing the buffer without bound.
const PEM_OPENER_CEILING_EXTRA: usize = 11_000;

/// CHAR offset of the start of the last UNCLOSED PEM private-key opener in
/// `combined` (a `-----BEGIN … PRIVATE KEY-----` with no matching `-----END …`
/// after it), or `None`. Used to (a) hold the carry cut before an in-flight
/// multi-line key so it is never emitted line-by-line in plaintext, and (b) raise
/// the force-flush ceiling so a key up to the pattern's body bound accumulates
/// whole. A cheap literal `contains` short-circuits the common (no-key) case.
pub fn unclosed_pem_opener_start(combined: &str) -> Option<usize> {
    if !combined.contains("-----BEGIN ") {
        return None;
    }
    let mut last_begin: Option<(usize, usize)> = None;
    for m in PEM_BEGIN_RE.find_iter(combined).flatten() {
        last_begin = Some((m.start(), m.end()));
    }
    let (begin_byte_start, begin_byte_end) = last_begin?;
    // Closed iff an END marker appears anywhere at/after the last BEGIN's end.
    if PEM_END_RE.is_match(&combined[begin_byte_end..]).unwrap_or(false) {
        return None;
    }
    // Byte offset → CHAR offset (the snap works in char-space).
    Some(combined[..begin_byte_start].chars().count())
}

/// True if the buffer holds a PEM private-key BEGIN marker (complete OR in-flight).
/// Drives the force-flush ceiling raise. The open-ended carry span (for an UNCLOSED
/// opener) keeps the cut before BEGIN while the key streams in, but a COMPLETE key
/// larger than `max_buffer` is a detected entity that the bounded drain would still
/// SPLIT into a plaintext head once `END` arrives and the ceiling drops. Keeping the
/// ceiling raised while ANY BEGIN is present lets such a key be carried whole and
/// redacted as one unit (or, past the CAP, bounded-drained — the documented edge,
/// which a key within the 10000 body bound never reaches).
///
/// SSOT for the force-flush ceiling gate: the wheel calls it via the
/// `streaming_pem_begin_present` PyO3 binding so wheel + wasm pick the SAME cut on a
/// non-private-key PEM block (a bare `-----BEGIN ` literal is NOT enough — the full
/// private-key regex must match).
pub fn pem_begin_present(combined: &str) -> bool {
    combined.contains("-----BEGIN ") && PEM_BEGIN_RE.is_match(combined).unwrap_or(false)
}

/// One emitted/redacted segment: the realistic downstream text + the key
/// (`{fake: original}`) + the aliases (`{fake: [alias, ...]}`) for THAT segment.
/// Mirrors the fields of the Python `PseudonymLLMResult` that streaming surfaces
/// (`.downstream_text` / `.key` / `.aliases`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RedactSegment {
    pub downstream_text: String,
    pub key: HashMap<String, String>,
    pub aliases: HashMap<String, Vec<String>>,
}

/// The result of one `feed` / `flush`: the segment + the redactor's accumulated
/// key snapshot after merging this segment (so the caller can restore the full
/// stream with one key). An empty `downstream_text` (with the accumulated key
/// unchanged) means the buffer hasn't reached a safe cut yet.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EmitResult {
    pub segment: RedactSegment,
    pub accumulated_key: HashMap<String, String>,
}

/// Restrict the FINAL (merged + self-ref-filtered) entity set to the emit range
/// `[lo, hi)` (CHAR indices) and re-base it onto the emit substring: keep every
/// entity that ENDS within the range (`lo < end ≤ hi`) and subtract `lo` from its
/// offsets. [`context_cut`]'s straddle snap guarantees no entity has `end > hi`, so
/// the forward edge never splits one. An entity whose head reaches back into the
/// already-emitted left-context (`start < lo`) is CLAMPED to the range
/// (`start → lo`): its head is committed plaintext we cannot rewrite, but its
/// in-range tail is still redacted — this is the direct-PII pattern that only
/// completed once the retained left-context joined it (its head having been emitted
/// before it was part of any entity).
///
/// For a clamped straddler the entity `text` is also TRUNCATED to its in-range tail
/// (drop the `lo − start` head chars). The redact closure mints the fake from this
/// text and the key maps `fake → tail`, so restore expands the fake back to exactly
/// the chars the emit range covers — NOT the full original, which would duplicate
/// the already-emitted head on restore (a round-trip corruption). Entities are
/// non-overlapping (merged), so at most one straddles `lo` and the clamp can never
/// overlap a neighbour. The result carries no hints: the entities are final, and
/// the redact closure replaces them directly (no re-detect / re-merge / re-filter).
fn shift_spans(entities: &[PatternMatch], lo: usize, hi: usize) -> DetectSpans {
    let shifted = entities
        .iter()
        .filter(|e| e.end > lo && e.end <= hi)
        .map(|e| {
            // Chars of the entity head that fall in the already-emitted left-context
            // (`[start, lo)`); 0 when the entity starts at/after `lo`.
            let drop = lo.saturating_sub(e.start);
            let text = if drop > 0 {
                e.text.chars().skip(drop).collect::<String>()
            } else {
                e.text.clone()
            };
            PatternMatch {
                text,
                type_: e.type_.clone(),
                start: e.start.saturating_sub(lo),
                end: e.end - lo,
                confidence: e.confidence,
                layer: e.layer,
            }
        })
        .collect();
    DetectSpans {
        entities: shifted,
        hints: Vec::new(),
    }
}

/// Sentence-bounded incremental redaction with cross-chunk key continuity.
///
/// Detects ONCE per round over a buffer that always carries ±`W`
/// ([`EVIDENCE_CONTEXT_WINDOW`]) of context (left-context overlap + forward
/// hold-back, via [`context_cut`]), then redacts the emit range using THAT
/// detection (range-shifted pre-detected spans, [`shift_spans`]) — never a
/// re-detect of the bare slice — so streaming detection equals batch for the
/// evidence-gated detectors. Merges each segment's key into `accumulated_key`
/// (first-seen wins, mirroring the Python `setdefault`). Generic over:
///   - `D`: the detect closure (`Fn(&str) -> DetectSpans`) run once over the whole
///     buffer; its RAW spans are merged + self-ref-filtered here into the final set
///     that drives BOTH the cut and the redaction.
///   - `R`: the redact closure (`Fn(&str, &DetectSpans) -> Result<RedactSegment,
///     String>`) that redacts the emit text USING the given final, range-shifted
///     entities — no re-detect, no re-merge, no re-filter (just replace + any
///     post-step like grammar). The given `DetectSpans` carries no hints.
///
/// State: `buffer` is the ORIGINAL text (retained left-context ++ pending) and
/// `ctx_len` is the length of the already-emitted left-context prefix (`0`
/// initially; `min(prev_cut, W)` thereafter — that prefix is for detection only and
/// is never re-emitted).
pub struct StreamingRedactor<D, R>
where
    D: Fn(&str) -> DetectSpans,
    R: Fn(&str, &DetectSpans) -> Result<RedactSegment, String>,
{
    detect: D,
    redact: R,
    max_buffer: usize,
    buffer: String,
    ctx_len: usize,
    accumulated_key: HashMap<String, String>,
}

impl<D, R> StreamingRedactor<D, R>
where
    D: Fn(&str) -> DetectSpans,
    R: Fn(&str, &DetectSpans) -> Result<RedactSegment, String>,
{
    /// Build a redactor with the default max-buffer.
    pub fn new(detect: D, redact: R) -> Self {
        Self::with_max_buffer(detect, redact, DEFAULT_MAX_BUFFER)
    }

    /// Build a redactor with an explicit max-buffer (CHARS).
    pub fn with_max_buffer(detect: D, redact: R, max_buffer: usize) -> Self {
        Self {
            detect,
            redact,
            max_buffer,
            buffer: String::new(),
            ctx_len: 0,
            accumulated_key: HashMap::new(),
        }
    }

    /// Append `chunk`, detect once over the whole buffer, and emit the range up to
    /// the [`context_cut`] (redacted with the range-shifted detection). Returns an
    /// [`EmitResult`] with an empty `downstream_text` when nothing past the retained
    /// left-context is safe to emit yet. Mirrors `StreamingRedactor.feed`.
    pub fn feed(&mut self, chunk: &str) -> Result<EmitResult, String> {
        self.buffer.push_str(chunk);
        let chars: Vec<char> = self.buffer.chars().collect();
        // Cheap emit gate: if no spans-independent trigger of `context_cut` can fire
        // for this buffer, the cut provably holds (≤ ctx_len), so skip the expensive
        // full-buffer detect + cut. CONSERVATIVE — `emit_possible` is a strict
        // superset of `context_cut`'s emit set (same max_buffer + W), so a buffer
        // that would emit is never skipped.
        if !emit_possible(&chars, self.ctx_len, self.pem_max_buffer(), EVIDENCE_CONTEXT_WINDOW, false) {
            return Ok(self.empty_result());
        }
        let final_entities = self.detect_final(&self.buffer);
        let cc = context_cut(
            &self.snap_spans(&final_entities, chars.len()),
            &chars,
            self.ctx_len,
            self.pem_max_buffer(),
            EVIDENCE_CONTEXT_WINDOW,
            false,
        );
        let cut = cc.cut;
        if cut <= self.ctx_len {
            return Ok(self.empty_result());
        }
        let emit: String = chars[self.ctx_len..cut].iter().collect();
        let spans = if cc.redetect {
            // Forced bounded-drain split (a ≥max_buffer boundary-less mega-entity):
            // RE-DETECT the bare emit slice and redact with those slice-local spans
            // (pre-rework drain safety), so the entity head is redacted instead of
            // dropped+leaked by the range-shifted full-buffer straddler.
            DetectSpans {
                entities: self.detect_final(&emit),
                hints: Vec::new(),
            }
        } else {
            shift_spans(&final_entities, self.ctx_len, cut)
        };
        // Carry the last W chars (already emitted, as left-context) plus everything
        // not yet emitted; `ctx_len` marks the retained prefix.
        let lo = cut.saturating_sub(EVIDENCE_CONTEXT_WINDOW);
        self.buffer = chars[lo..].iter().collect();
        self.ctx_len = cut - lo;
        self.redact_and_merge(&emit, &spans)
    }

    /// End-of-stream flush — drain everything past the retained left-context with a
    /// fresh full-buffer detect and no hold-back (end-of-stream context ≡ batch's
    /// view of the tail), then reset. Returns an empty [`EmitResult`] when nothing
    /// is pending. Mirrors `StreamingRedactor.flush`.
    pub fn flush(&mut self) -> Result<EmitResult, String> {
        let chars: Vec<char> = self.buffer.chars().collect();
        if chars.len() <= self.ctx_len {
            self.buffer.clear();
            self.ctx_len = 0;
            return Ok(self.empty_result());
        }
        let final_entities = self.detect_final(&self.buffer);
        let emit: String = chars[self.ctx_len..].iter().collect();
        let shifted = shift_spans(&final_entities, self.ctx_len, chars.len());
        self.buffer.clear();
        self.ctx_len = 0;
        self.redact_and_merge(&emit, &shifted)
    }

    /// Detect once over `buffer` and reduce to the FINAL entity set (merge →
    /// self-ref filter → coverage restore), exactly as batch `_detect` does — the
    /// set that drives both the cut and the redaction.
    fn detect_final(&self, buffer: &str) -> Vec<PatternMatch> {
        let DetectSpans { entities, hints } = (self.detect)(buffer);
        // The streaming face applies no type filter — the caller-supplied
        // redact closure owns that — so the only dropping filter here is the
        // self-reference tier filter. The coverage invariant still applies:
        // a dropped self_reference span may have absorbed a real entity.
        let scope = FilterScope::from_hints(None, None, &hints);
        let pre_merge: Option<Vec<PatternMatch>> =
            if scope.admits_all(&entities) { None } else { Some(entities.clone()) };
        let merged = merge_entities_with_text(entities, buffer);
        // One Option carrying both halves — `merged` is moved into the filter
        // below, so its spans must be taken first, and the snapshot is only
        // ever useful paired with them. See the twin in `redact_l1`.
        let snapshot: Option<(Vec<PatternMatch>, Vec<(usize, usize)>)> =
            pre_merge.map(|pre| (pre, merged.iter().map(|e| (e.start, e.end)).collect()));
        let filtered = filter_self_reference(merged, &hints);
        match snapshot {
            Some((pre, spans)) => restore_lost_coverage(&pre, &spans, filtered, &scope, buffer).0,
            None => filtered,
        }
    }

    /// The snap input for [`context_cut`]: the final spans as `(start, end, type)`
    /// tuples PLUS the in-flight PEM opener pending span (so an unterminated key is
    /// carried whole). `len` is the buffer length in CHARS.
    fn snap_spans(&self, final_entities: &[PatternMatch], len: usize) -> Vec<(usize, usize, String)> {
        let mut spans: Vec<(usize, usize, String)> = final_entities
            .iter()
            .map(|e| (e.start, e.end, e.type_.clone()))
            .collect();
        if let Some(begin) = unclosed_pem_opener_start(&self.buffer) {
            // Open-ended (end one past the buffer) so a cut at the buffer end still
            // counts as a straddle and snaps back to BEGIN.
            spans.push((begin, len + 1, PEM_OPENER_TYPE.to_string()));
        }
        spans
    }

    /// Raise the force-flush ceiling while a multi-line PEM private key is present,
    /// so the whole key (body bound 10000) accumulates and redacts as one unit
    /// instead of being bounded-drain-split into a plaintext head leak. Gates on
    /// [`pem_begin_present`] (the same predicate the wheel calls via
    /// `streaming_pem_begin_present`); bounded by the CAP, past which an
    /// unterminated/oversized opener is bounded-drained.
    fn pem_max_buffer(&self) -> usize {
        if pem_begin_present(&self.buffer) {
            self.max_buffer.saturating_add(PEM_OPENER_CEILING_EXTRA)
        } else {
            self.max_buffer
        }
    }

    /// A copy of the unified key across all fed chunks. Mirrors `aggregate_key`.
    pub fn aggregate_key(&self) -> HashMap<String, String> {
        self.accumulated_key.clone()
    }

    /// The current residual buffer — left-context ++ pending (test/inspection aid;
    /// mirrors `_inc_buffer`).
    pub fn buffer(&self) -> &str {
        &self.buffer
    }

    fn empty_result(&self) -> EmitResult {
        EmitResult {
            segment: RedactSegment::default(),
            accumulated_key: self.accumulated_key.clone(),
        }
    }

    fn redact_and_merge(
        &mut self,
        text: &str,
        spans: &DetectSpans,
    ) -> Result<EmitResult, String> {
        let segment = (self.redact)(text, spans)?;
        // setdefault: first-seen mapping wins; realistic and audit spaces are
        // disjoint by construction, so collisions are impossible (mirrors the
        // Python `setdefault` merge).
        for (fake, original) in &segment.key {
            self.accumulated_key
                .entry(fake.clone())
                .or_insert_with(|| original.clone());
        }
        Ok(EmitResult {
            segment,
            accumulated_key: self.accumulated_key.clone(),
        })
    }
}

/// Buffer streaming LLM output and restore PII at sentence boundaries.
///
/// Has its OWN boundary logic (distinct from the redactor's carry-window): it
/// flushes at the LAST occurrence of any boundary char (whole-code matching across
/// chunk boundaries needs only a complete sentence, not the entity-aware snap),
/// then restores the complete part via a [`RestoreSession`] built once (in `new`)
/// over the fixed key and replayed across every call, rather than recompiling the
/// key/alias merge + regex per call. Mirrors `StreamingRestorer`. `Sentence`
/// buffers at boundaries; `None` restores every chunk immediately.
pub struct StreamingRestorer {
    session: Result<RestoreSession, RestoreError>,
    buffer: String,
    strategy: RestoreStrategy,
}

/// The restorer's buffering strategy. Mirrors the Python `"sentence"` / `"none"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreStrategy {
    /// Flush at sentence boundaries (`。.！!？?；;\n`).
    Sentence,
    /// Restore every chunk immediately (no buffering).
    None,
}

/// Split a restorer buffer at its LAST REAL sentence boundary → `(complete,
/// residual)`.
///
/// Mirrors the redactor's [`last_boundary_index`] rule (one SSOT for "what is a
/// sentence end"): `\n` and the CJK full-width `。！？；` ALWAYS count (they never
/// appear inside a restore code / realistic fake, and CJK sentences carry no
/// trailing space); the ASCII boundaries `.!?;` count ONLY when the NEXT buffer
/// char is whitespace, and NEVER at the buffer end (ambiguous: a realistic fake's
/// internal dot — `user16068@example.net`, an IPv4 octet — can be the rightmost
/// char at a `feed`). Flushing on such an ambiguous dot would emit a half-token
/// (`…@example.`) and restore the fragment, leaving the pseudonym unrestored.
/// Returns the prefix up to and including the rightmost REAL boundary as
/// `complete`, the rest as `residual`; `("", buffer)` when none is present (buffer
/// everything). CHAR-space (Python `str`) semantics. SSOT for the Python
/// `StreamingRestorer.feed` boundary split.
pub fn restorer_split(buffer: &str) -> (String, String) {
    let chars: Vec<char> = buffer.chars().collect();
    match last_boundary_index_chars(&chars) {
        None => ("".to_string(), buffer.to_string()),
        Some(split) => {
            let complete: String = chars[..split].iter().collect();
            let residual: String = chars[split..].iter().collect();
            (complete, residual)
        }
    }
}

impl StreamingRestorer {
    /// Build a restorer over `key` with the given strategy.
    ///
    /// Precompiles the key/alias merge + regex ONCE, up front, into a cached
    /// [`RestoreSession`] rather than recompiling on every `feed`/`flush` call
    /// (`restore_full` would re-derive that state from scratch each time).
    /// `new` stays INFALLIBLE (crates.io stability: it returns `Self`, not a
    /// `Result`) even though `RestoreSession::new` can fail closed on a
    /// corrupted empty-string key entry — that failure is captured in the
    /// stored `Result` and surfaces the first time `feed`/`flush` actually
    /// needs the session, never as a panic here.
    pub fn new(key: HashMap<String, String>, strategy: RestoreStrategy) -> Self {
        Self {
            session: RestoreSession::new(&key, None),
            buffer: String::new(),
            strategy,
        }
    }

    /// The cached session, or the construction-time error re-wrapped (`RestoreError`
    /// has no `Clone`, so only its message is cloned) for callers that need an owned
    /// `Result` at the `?`-propagation site.
    fn session(&self) -> Result<&RestoreSession, RestoreError> {
        self.session.as_ref().map_err(|e| RestoreError(e.0.clone()))
    }

    /// Feed a chunk. Returns restored text based on the strategy. Mirrors
    /// `StreamingRestorer.feed`.
    pub fn feed(&mut self, chunk: &str) -> Result<String, RestoreError> {
        if self.strategy == RestoreStrategy::None {
            // No `aliases` are threaded through this streaming path, so
            // `alias_collisions` is always empty — discard it.
            return self.session()?.restore_cell(chunk).map(|r| r.restored);
        }

        self.buffer.push_str(chunk);

        // Find the last sentence boundary + split, via the SSOT helper.
        let (complete, residual) = restorer_split(&self.buffer);
        if complete.is_empty() {
            return Ok("".to_string());
        }
        self.buffer = residual;
        self.session()?.restore_cell(&complete).map(|r| r.restored)
    }

    /// Flush the remaining buffer. Mirrors `StreamingRestorer.flush`.
    pub fn flush(&mut self) -> Result<String, RestoreError> {
        if self.buffer.is_empty() {
            return Ok("".to_string());
        }
        // Computed (not `?`-propagated) so the buffer is cleared below
        // regardless of whether the session errors — matching the prior
        // `restore_full` call's behavior, which always cleared on this path.
        let result = self.session().and_then(|s| s.restore_cell(&self.buffer)).map(|r| r.restored);
        self.buffer.clear();
        result
    }
}

#[cfg(test)]
mod tests;
