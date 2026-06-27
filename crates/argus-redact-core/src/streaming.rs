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
//! ## The four carry-window functions (exact Python parity)
//!
//! - [`last_boundary_index`] — index *after* the rightmost REAL sentence boundary.
//!   `\n` + the CJK full-width `。！？；` ALWAYS count (they never appear inside an
//!   ASCII entity and CJK sentences carry no trailing space). The ASCII boundaries
//!   `.!?;` count ONLY when the NEXT char is whitespace; at the buffer END (no next
//!   char) an ASCII boundary is ambiguous (`. ` sentence-end vs `.com` intra-entity)
//!   and does NOT count — wait for the next chunk.
//! - [`bounded_carry`] — at `cut <= 0` (a span longer than the window blocks a safe
//!   cut), once the buffer ≥ `max_buffer` drain to `len - CARRY_WINDOW` so the
//!   buffer can never grow unbounded; below `max_buffer`, carry everything.
//! - [`carry_cut_index`] / [`snap_cut`] — at a boundary / force-flush cut, DETECT
//!   on the FULL combined buffer and snap the cut back so it neither splits an
//!   entity NOR orphans an evidence-gated candidate (region/occupation/condition/
//!   hobby) from the cue or proximate PII that fired it (detect-on-full).
//! - [`consume_to_boundary`] — the orchestrator: `(emit_text, residual)`.
//!
//! ## Generic over detection + redaction (no PyO3, no registry — like `redact_l1`)
//!
//! The state machine's only entity-aware step ([`carry_cut_index`]) needs entity
//! spans over the combined buffer. To keep this core module free of PyO3 / Python
//! glue, the spans come from a caller-supplied detect closure (`Fn(&str) ->
//! Vec<(usize, usize)>`, CHAR-space `[start, end)`). [`StreamingRedactor`] is
//! likewise generic over a redact closure that turns one emit segment into
//! `(downstream_text, key, aliases)` — so the Python shim threads the full
//! `redact_pseudonym_llm` pipeline through it, and wasm can thread `redact_l1`.
//! The accumulated key + carry-window buffer (the actual streaming STATE) live
//! here, in the SSOT.
//!
//! ## Known limitation: cross-sentence evidence for context-gated detectors
//!
//! The evidence-gated L1 detectors (region/occupation/condition/hobby) fire only
//! on a nearby cue or proximate PII. The snap carries a candidate together with
//! evidence present in the COMBINED buffer at cut time. It cannot carry evidence
//! that lives in a *separately committed* sentence: if a chunk boundary forces a
//! flush at a `。`/`.` between a bare candidate and its only cue (e.g.
//! `"我对花生。" | "过敏很严重。"` — allergen, then its `过敏` cue in the next
//! chunk), the candidate is emitted before the cue ever shares its buffer, so it
//! never fires and the bare term passes through. Batch redaction sees the whole
//! text and catches it; online streaming cannot without speculative cross-sentence
//! look-ahead (a separate design). This is inherent to single-pass streaming, not
//! a snap defect.

use std::collections::HashMap;
use std::sync::LazyLock;

use fancy_regex::Regex;

use crate::hints::{filter_self_reference, Hint};
use crate::merger::merge_entities_with_text;
use crate::restore::{restore_full, RestoreError};
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

/// `bounded_carry` over a CHAR slice: at `cut <= 0`, once the buffer reaches
/// `max_buffer` (CHARS) force-emit the prefix down to the trailing carry window so
/// the buffer is guaranteed to drain (no unbounded growth); below `max_buffer`,
/// carry everything. Returns `(emit, residual)` as owned strings. Mirrors
/// `_bounded_carry`.
fn bounded_carry_chars_mb(combined: &[char], max_buffer: usize) -> (String, String) {
    // A buffer no longer than the carry window can never drain to `len -
    // CARRY_WINDOW` (the subtraction would underflow → out-of-range slice panic /
    // wasm abort). Such a buffer is always safe to carry whole — it will grow past
    // the window and drain here next round. Mirrors Python's negative-index
    // `('', combined)` semantics for `len <= CARRY_WINDOW`.
    if combined.len() <= CARRY_WINDOW {
        return ("".to_string(), combined.iter().collect());
    }
    if combined.len() >= max_buffer {
        let target = combined.len() - CARRY_WINDOW;
        let emit: String = combined[..target].iter().collect();
        let residual: String = combined[target..].iter().collect();
        (emit, residual)
    } else {
        ("".to_string(), combined.iter().collect())
    }
}

/// Public string-level `bounded_carry` mirror (for the PyO3 parity binding).
pub fn bounded_carry(combined: &str, max_buffer: usize) -> (String, String) {
    let chars: Vec<char> = combined.chars().collect();
    bounded_carry_chars_mb(&chars, max_buffer)
}

/// Entity-aware bounded drain: like [`bounded_carry_chars_mb`], but the force-emit
/// cut at `len - CARRY_WINDOW` is first snapped back off any entity it would SPLIT
/// (`drain_fn` is the CLOSED-ONLY snap). This is the `cut == 0` fallback: the
/// widened snap chained the carry all the way to the buffer start, so we cannot
/// honor it without unbounded growth, but draining at the raw `len - CARRY_WINDOW`
/// could split an entity straddling exactly that point (head emitted + tail carried
/// = the two halves recombine downstream = a verbatim leak). Snapping the drain off
/// that straddle keeps the entity whole. `drain_fn` returning `0` means a single
/// entity spans from the buffer start past the window (the genuine >window
/// unbounded-token edge) — splitting is then unavoidable, so fall back to the raw
/// `len - CARRY_WINDOW` drain (its head is emitted; documented edge).
fn bounded_drain<C>(chars: &[char], max_buffer: usize, drain_fn: &C) -> (String, String)
where
    C: Fn(&str, usize) -> usize,
{
    if chars.len() <= CARRY_WINDOW {
        return ("".to_string(), chars.iter().collect());
    }
    if chars.len() >= max_buffer {
        let target = chars.len() - CARRY_WINDOW;
        let combined: String = chars.iter().collect();
        let drain = drain_fn(&combined, target);
        let cut = if drain == 0 { target } else { drain };
        let emit: String = chars[..cut].iter().collect();
        let residual: String = chars[cut..].iter().collect();
        (emit, residual)
    } else {
        ("".to_string(), chars.iter().collect())
    }
}

/// The RAW detection input the carry-window snap normalizes before snapping: the
/// `layer1 ++ person` entities plus the L1 `hints`, exactly as a fast-mode
/// `detect_l1` produces them. The snap applies the same `merge_entities_with_text`
/// then `filter_self_reference` that the Python `_detect` (fast) pipeline applies,
/// so a caller may thread the RAW overlapping set and still get the merged-cut
/// behavior: the snap is order- and overlap-invariant, which keeps the cut identical
/// to the Python path (the SSOT requirement for wasm streaming).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DetectSpans {
    /// Raw `layer1 ++ person` entities over the combined buffer (CHAR-space spans).
    pub entities: Vec<PatternMatch>,
    /// L1 hints over the combined buffer (drive `filter_self_reference`).
    pub hints: Vec<Hint>,
}

/// Normalize a RAW detect set to the SAME non-overlapping, de-self-referenced span
/// set Python's `_detect` (fast mode) produces — `merge_entities_with_text` →
/// `filter_self_reference` (`boost_cross_layer` is a no-op in single-layer fast
/// mode). Returns CHAR-space `(start, end, type_)` spans (the type drives the
/// evidence-gated widening in [`snap_cut`]). This is what makes the snap
/// caller-agnostic: raw-vs-merged input collapses to the same span set here.
fn normalize_snap_spans(input: DetectSpans, combined: &str) -> Vec<(usize, usize, String)> {
    let merged = merge_entities_with_text(input.entities, combined);
    let filtered = filter_self_reference(merged, &input.hints);
    filtered.into_iter().map(|e| (e.start, e.end, e.type_)).collect()
}

/// L1 detector output types that fire on CONTEXT rather than a self-contained
/// pattern: a region / occupation / condition / hobby candidate is emitted only
/// when a cue (within the detector's `±WINDOW`) or proximate PII corroborates it.
/// Such a candidate can sit ENTIRELY on one side of a cut while the evidence that
/// fired it sits on the other — so re-detecting the emitted prefix ALONE drops it
/// below threshold and emits the bare term in plaintext. The snap widens their
/// danger zone so candidate + evidence are always carried (and re-scored) as a
/// unit. Keep in sync with the emitted `type_`s of `regions.rs` (`location`),
/// `occupation.rs` (`job_title`), and the `evidence_detector` instances
/// (`conditions.rs` → `medical`, `hobbies.rs` → `hobby`).
const EVIDENCE_GATED_TYPES: [&str; 4] = ["location", "job_title", "medical", "hobby"];

/// Char margin added on EACH side of an evidence-gated candidate when deciding
/// whether a cut would orphan it from its evidence. The widest sole-sufficient
/// evidence window across the L1 evidence detectors is PII proximity NEAR = 50
/// (regions: weight 0.5 alone clears the 0.5 gate; conditions/hobbies: 0.3,
/// load-bearing in combination with the lexicon weight), dominating the cue
/// window 40. We add **+1**: the detectors count proximity INCLUSIVELY
/// (`distance <= NEAR`, regions.rs / evidence_detector.rs), so a corroborating
/// closed PII can sit at EXACTLY distance 50. The margin must exceed that by one
/// char so the snap's left edge (`start - margin`) lands strictly INSIDE the PII
/// (not on its end), letting the strict closed-entity straddle pull the whole PII
/// back with the candidate. At margin == 50 a PII at exactly distance 50 was
/// orphaned (left edge == PII end, not a strict straddle). See `REGION_PROX_NEAR`
/// / `DEFAULT_PROX_NEAR` (= 50).
const EVIDENCE_CARRY_MARGIN: usize = 51;

fn is_evidence_gated(type_: &str) -> bool {
    EVIDENCE_GATED_TYPES.contains(&type_)
}

/// Snap `target` back to a SAFE cut over the normalized entity spans (each
/// `(start, end, type_)`, CHAR-space `[start, end)`) of the combined buffer.
///
/// A cut is unsafe if it would (a) split a closed entity span, or (b) — when
/// `widen` is set — orphan an evidence-gated candidate from the cue / proximate
/// PII that fired it (anything within [`EVIDENCE_CARRY_MARGIN`] chars on either
/// side). For (a) the cut snaps back to the entity start (carry it whole); for (b)
/// it snaps back PAST the candidate's left margin so the candidate AND its
/// evidence are carried together and re-scored next round — a cue is not itself a
/// detected entity, so only carrying the whole margin keeps it. Iterates to a
/// FIXED POINT because snapping one span's cut back can expose a straddle of
/// another span (e.g. a widened candidate's new cut landing inside a neighbouring
/// closed entity). The cut strictly decreases each round, bounded below by 0, so
/// this terminates. `0` means "carry everything" (the unbounded-token residual
/// edge).
///
/// `widen = false` is the CLOSED-ONLY mode: every span (including evidence-gated
/// ones) is treated as a plain entity that may not be SPLIT, but the ±margin
/// orphan-avoidance is dropped. The boundary-less force-flush drain uses it: when
/// the widened snap can only return 0 (dense evidence chains the carry all the way
/// to the buffer start) we must still drain to bound the buffer, and closed-only
/// gives a drain point that never splits an entity — restoring the pre-widening
/// drain safety while accepting an orphan (unavoidable below `max_buffer`).
///
/// This is the SSOT for the snap rule: the wasm path ([`carry_cut_index`]) and
/// the Python wheel path (`_carry_cut_index`, via the PyO3 `streaming_snap_cut`
/// binding) both call it, so the cut is byte-identical across runtimes.
pub fn snap_cut(spans: &[(usize, usize, String)], target: usize, widen: bool) -> usize {
    let mut cut = target;
    loop {
        let mut next = cut;
        for (start, end, type_) in spans {
            if widen && is_evidence_gated(type_) {
                let lo = start.saturating_sub(EVIDENCE_CARRY_MARGIN);
                let hi = end + EVIDENCE_CARRY_MARGIN;
                if lo <= cut && cut <= hi && lo < next {
                    next = lo;
                }
            } else if *start < cut && cut < *end && *start < next {
                next = *start;
            }
        }
        if next == cut {
            return cut;
        }
        cut = next;
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

/// The pending-span type label for an in-flight PEM opener. Any NON-evidence-gated
/// type works — [`snap_cut`] then treats the `[begin, len)` span with the strict
/// closed-entity rule (snap the cut back to `begin`), which is exactly what carrying
/// an unterminated key whole requires.
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
fn pem_begin_present(combined: &str) -> bool {
    combined.contains("-----BEGIN ") && PEM_BEGIN_RE.is_match(combined).unwrap_or(false)
}

/// Build the snap-input spans: the normalized detect set PLUS, when the buffer
/// holds an in-flight (unclosed) PEM private-key opener, an open-ended pending span
/// `[begin_start, len)` (typed as a closed entity) so [`snap_cut`] pulls the cut
/// back before BEGIN and the whole multi-line key is carried until END arrives.
fn snap_input_spans<D>(combined: &str, detect: &D) -> Vec<(usize, usize, String)>
where
    D: Fn(&str) -> DetectSpans,
{
    let mut spans = normalize_snap_spans(detect(combined), combined);
    if let Some(begin) = unclosed_pem_opener_start(combined) {
        // Open-ended: end is one PAST the buffer so a cut AT the buffer end (the
        // trailing `\n` boundary of an in-flight key line) still counts as a
        // straddle and snaps back to BEGIN. The key continues into future chunks.
        let open_end = combined.chars().count() + 1;
        spans.push((begin, open_end, PEM_OPENER_TYPE.to_string()));
    }
    spans
}

/// Pick a force-flush / boundary emit cut at or before `target` (a CHAR index)
/// that neither splits a detected entity NOR orphans an evidence-gated candidate
/// from its evidence, by detecting on the FULL combined text and snapping the cut
/// back via [`snap_cut`].
///
/// `detect` returns the RAW [`DetectSpans`] (`layer1 ++ person ++ regions ++
/// job_titles ++ framework` + hints) over `combined`; the snap NORMALIZES them
/// (merge + self-reference filter) to the exact set Python's `_detect` (fast)
/// produces BEFORE the cascading snap, so the cut is order/overlap-invariant
/// regardless of whether the caller threaded raw or merged spans. An in-flight PEM
/// opener is added as an open-ended pending span (see [`snap_input_spans`]). Mirrors
/// `_carry_cut_index`. Returns the CHAR cut index (`0` means carry everything).
pub fn carry_cut_index<D>(combined: &str, target: usize, detect: &D) -> usize
where
    D: Fn(&str) -> DetectSpans,
{
    snap_cut(&snap_input_spans(combined, detect), target, true)
}

/// Closed-only counterpart of [`carry_cut_index`]: the same detect + normalize (+
/// PEM opener span), but [`snap_cut`] runs without the evidence-gated widening
/// (`widen = false`). Used ONLY as the force-flush drain fallback — see
/// [`bounded_drain`].
fn carry_cut_index_closed<D>(combined: &str, target: usize, detect: &D) -> usize
where
    D: Fn(&str) -> DetectSpans,
{
    snap_cut(&snap_input_spans(combined, detect), target, false)
}

/// Split `prev_buffer + chunk` at the last SAFE cut. Returns `(emit_text,
/// residual)` — `emit_text` is the committed prefix (or `""` if nothing is ready
/// to emit yet); `residual` is the tail to carry into the next call.
///
/// `cut_fn` computes the entity-aware emit cut at or before a CHAR `target` index
/// over the combined text (`Fn(&str, usize) -> cut`). This is the snap step —
/// EXACTLY the `_carry_cut_index(combined, target, ...)` call site in the Python
/// `_consume_to_boundary`. Keeping the cut as a closure (not baking detection in)
/// preserves the Python structure: the PyO3 shim threads the real (monkeypatchable)
/// Python `_carry_cut_index` here, and pure-Rust callers build one from a detect
/// closure via [`consume_to_boundary_detect`]. Mirrors `_consume_to_boundary`.
///
/// `drain_fn` is the CLOSED-ONLY snap (no evidence widening), used ONLY for the
/// `cut == 0` bounded drain via [`bounded_drain`] so the forced drain never SPLITS
/// an entity even when `cut_fn`'s widening chained the carry back to 0.
pub fn consume_to_boundary<C, C2>(
    prev_buffer: &str,
    chunk: &str,
    max_buffer: usize,
    force_flush: bool,
    cut_fn: &C,
    drain_fn: &C2,
) -> (String, String)
where
    C: Fn(&str, usize) -> usize,
    C2: Fn(&str, usize) -> usize,
{
    let combined: String = {
        let mut s = String::with_capacity(prev_buffer.len() + chunk.len());
        s.push_str(prev_buffer);
        s.push_str(chunk);
        s
    };
    if combined.is_empty() {
        return ("".to_string(), "".to_string());
    }
    if force_flush {
        return (combined, "".to_string());
    }

    // While a multi-line PEM private key is present (in-flight OR a complete key
    // larger than max_buffer), raise the force-flush ceiling so the whole key (body
    // bound 10000) is carried and redacted as one unit instead of being
    // force-flush-split into a plaintext head leak. An in-flight key is held before
    // BEGIN by the opener pending span; a complete >max_buffer key is a detected
    // entity but the bounded drain would still split it once END closes the opener
    // (dropping the ceiling) — so the raise is gated on ANY BEGIN, not just unclosed.
    // Bounded by the CAP — past it an unterminated/oversized key is bounded-drained.
    let max_buffer = if pem_begin_present(&combined) {
        max_buffer.saturating_add(PEM_OPENER_CEILING_EXTRA)
    } else {
        max_buffer
    };

    let chars: Vec<char> = combined.chars().collect();
    let boundary = last_boundary_index_chars(&chars);

    match boundary {
        None => {
            if chars.len() >= max_buffer {
                // Boundary-less force-flush. Carry a trailing window so a
                // straddling entity is whole next round. Tiny buffers (≤ window)
                // carry all rather than slicing a negative index.
                if chars.len() <= CARRY_WINDOW {
                    return ("".to_string(), combined);
                }
                let target = chars.len() - CARRY_WINDOW;
                let cut = cut_fn(&combined, target);
                if cut == 0 {
                    // The (widened) snap chained the carry all the way to the buffer
                    // start — either a single entity spans from 0 past the window, or
                    // dense evidence-gated candidates chained their ±margin zones back
                    // to 0. We are already at len >= max_buffer, so force a bounded
                    // drain rather than carrying all (carrying all would let the span
                    // grow the buffer without bound → O(n^2) re-detect → MAX_INPUT_SIZE
                    // crash). The drain is snapped CLOSED-ONLY so it never SPLITS an
                    // entity straddling the drain point (a split would recombine
                    // downstream into a verbatim leak); only a genuine >window token
                    // (drain_fn → 0) falls back to the raw window drain.
                    return bounded_drain(&chars, max_buffer, drain_fn);
                }
                let emit: String = chars[..cut].iter().collect();
                let residual: String = chars[cut..].iter().collect();
                (emit, residual)
            } else {
                ("".to_string(), combined)
            }
        }
        Some(boundary) => {
            // A real sentence end. Even so it can sit inside a detected entity
            // (e.g. "123 Main St. Apt 4" where "St. " is a real boundary). Apply
            // the same entity-aware snap: if an entity straddles the boundary, snap
            // the cut back to its start and carry it whole. cut <= 0 → carry all
            // (gated on max_buffer via bounded_carry); it resolves at a later
            // boundary or the end-of-stream flush.
            let cut = cut_fn(&combined, boundary);
            if cut == 0 {
                return bounded_drain(&chars, max_buffer, drain_fn);
            }
            let emit: String = chars[..cut].iter().collect();
            let residual: String = chars[cut..].iter().collect();
            (emit, residual)
        }
    }
}

/// [`consume_to_boundary`] with the cut computed from a `detect` closure via
/// [`carry_cut_index`] — the pure-Rust convenience for callers (wasm,
/// [`StreamingRedactor`]) that detect directly rather than threading a Python
/// `_carry_cut_index`. `detect` returns the RAW [`DetectSpans`] over the combined
/// text (the snap normalizes them) and MUST use the SAME detection params the
/// caller's redaction uses.
pub fn consume_to_boundary_detect<D>(
    prev_buffer: &str,
    chunk: &str,
    max_buffer: usize,
    force_flush: bool,
    detect: &D,
) -> (String, String)
where
    D: Fn(&str) -> DetectSpans,
{
    let cut_fn = |combined: &str, target: usize| carry_cut_index(combined, target, detect);
    let drain_fn = |combined: &str, target: usize| carry_cut_index_closed(combined, target, detect);
    consume_to_boundary(prev_buffer, chunk, max_buffer, force_flush, &cut_fn, &drain_fn)
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

/// Sentence-bounded incremental redaction with cross-chunk key continuity.
///
/// Buffers input until a SAFE cut (via the carry-window state machine), then
/// redacts the committed prefix through the caller-supplied redact closure and
/// merges the segment's key into `accumulated_key` (first-seen wins, mirroring the
/// Python `setdefault`). Generic over:
///   - `D`: the detect closure (`Fn(&str) -> DetectSpans`) used for the
///     carry-window entity-snap — MUST match the redact closure's detection params.
///   - `R`: the redact closure (`Fn(&str) -> Result<RedactSegment, String>`) that
///     turns one emit segment into its `(downstream_text, key, aliases)`.
pub struct StreamingRedactor<D, R>
where
    D: Fn(&str) -> DetectSpans,
    R: Fn(&str) -> Result<RedactSegment, String>,
{
    detect: D,
    redact: R,
    max_buffer: usize,
    buffer: String,
    accumulated_key: HashMap<String, String>,
}

impl<D, R> StreamingRedactor<D, R>
where
    D: Fn(&str) -> DetectSpans,
    R: Fn(&str) -> Result<RedactSegment, String>,
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
            accumulated_key: HashMap::new(),
        }
    }

    /// Buffer until a safe cut, then redact the committed prefix. Returns an
    /// [`EmitResult`] with an empty `downstream_text` when the buffer hasn't
    /// reached a cut yet. Mirrors `StreamingRedactor.feed`.
    pub fn feed(&mut self, chunk: &str) -> Result<EmitResult, String> {
        let (emit_text, residual) = consume_to_boundary_detect(
            &self.buffer,
            chunk,
            self.max_buffer,
            false,
            &self.detect,
        );
        self.buffer = residual;
        if emit_text.is_empty() {
            return Ok(self.empty_result());
        }
        self.redact_and_merge(&emit_text)
    }

    /// End-of-stream flush — drain the pending buffer through the redact closure.
    /// Returns an empty [`EmitResult`] if the buffer is empty. Mirrors
    /// `StreamingRedactor.flush`.
    pub fn flush(&mut self) -> Result<EmitResult, String> {
        if self.buffer.is_empty() {
            return Ok(self.empty_result());
        }
        let emit = std::mem::take(&mut self.buffer);
        self.redact_and_merge(&emit)
    }

    /// A copy of the unified key across all fed chunks. Mirrors `aggregate_key`.
    pub fn aggregate_key(&self) -> HashMap<String, String> {
        self.accumulated_key.clone()
    }

    /// The current residual buffer (test/inspection aid; mirrors `_inc_buffer`).
    pub fn buffer(&self) -> &str {
        &self.buffer
    }

    fn empty_result(&self) -> EmitResult {
        EmitResult {
            segment: RedactSegment::default(),
            accumulated_key: self.accumulated_key.clone(),
        }
    }

    fn redact_and_merge(&mut self, text: &str) -> Result<EmitResult, String> {
        let segment = (self.redact)(text)?;
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
/// then restores the complete part via `restore_full`. Mirrors
/// `StreamingRestorer`. `Sentence` buffers at boundaries; `None` restores every
/// chunk immediately.
pub struct StreamingRestorer {
    key: HashMap<String, String>,
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
    pub fn new(key: HashMap<String, String>, strategy: RestoreStrategy) -> Self {
        Self {
            key,
            buffer: String::new(),
            strategy,
        }
    }

    /// Feed a chunk. Returns restored text based on the strategy. Mirrors
    /// `StreamingRestorer.feed`.
    pub fn feed(&mut self, chunk: &str) -> Result<String, RestoreError> {
        if self.strategy == RestoreStrategy::None {
            return restore_full(chunk, &self.key, None, None);
        }

        self.buffer.push_str(chunk);

        // Find the last sentence boundary + split, via the SSOT helper.
        let (complete, residual) = restorer_split(&self.buffer);
        if complete.is_empty() {
            return Ok("".to_string());
        }
        self.buffer = residual;
        restore_full(&complete, &self.key, None, None)
    }

    /// Flush the remaining buffer. Mirrors `StreamingRestorer.flush`.
    pub fn flush(&mut self) -> Result<String, RestoreError> {
        if self.buffer.is_empty() {
            return Ok("".to_string());
        }
        let result = restore_full(&self.buffer, &self.key, None, None);
        self.buffer.clear();
        result
    }
}

#[cfg(test)]
mod tests;
