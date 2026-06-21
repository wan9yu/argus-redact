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
//! - [`carry_cut_index`] — at a boundary / force-flush cut, DETECT on the FULL
//!   combined buffer and snap the cut back to the start of any entity straddling
//!   the target so the whole entity is carried together (detect-on-full).
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

use std::collections::HashMap;

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
/// mode). Returns CHAR-space `[start, end)` spans. This is what makes the snap
/// caller-agnostic: raw-vs-merged input collapses to the same span set here.
fn normalize_snap_spans(input: DetectSpans, combined: &str) -> Vec<(usize, usize)> {
    let merged = merge_entities_with_text(input.entities, combined);
    let filtered = filter_self_reference(merged, &input.hints);
    filtered.into_iter().map(|e| (e.start, e.end)).collect()
}

/// Pick a force-flush / boundary emit cut at or before `target` (a CHAR index)
/// that splits no detected entity, by detecting on the FULL combined text and
/// snapping the cut back to the start of any entity straddling `target`.
///
/// `detect` returns the RAW [`DetectSpans`] (`layer1 ++ person` + hints) over
/// `combined`; the snap NORMALIZES them (merge + self-reference filter) to the
/// exact set Python's `_detect` (fast) produces BEFORE the cascading snap, so the
/// cut is order/overlap-invariant regardless of whether the caller threaded raw or
/// merged spans. Mirrors `_carry_cut_index`. Returns the CHAR cut index
/// (`0` means carry everything).
pub fn carry_cut_index<D>(combined: &str, target: usize, detect: &D) -> usize
where
    D: Fn(&str) -> DetectSpans,
{
    let spans = normalize_snap_spans(detect(combined), combined);
    let mut cut = target;
    for (start, end) in spans {
        // An entity straddles the cut iff it starts strictly before it and ends
        // strictly after it. Snap the cut back to its start so head+tail are
        // carried together and re-detected next round.
        if start < cut && cut < end {
            cut = start;
        }
    }
    cut
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
pub fn consume_to_boundary<C>(
    prev_buffer: &str,
    chunk: &str,
    max_buffer: usize,
    force_flush: bool,
    cut_fn: &C,
) -> (String, String)
where
    C: Fn(&str, usize) -> usize,
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
                    // An entity spans from the buffer start past the window. We are
                    // already at len >= max_buffer, so force a bounded drain (down
                    // to the trailing window) rather than carrying all — carrying
                    // all here would let an open-ended span grow the buffer without
                    // bound (O(n^2) re-detect, then a MAX_INPUT_SIZE crash). The
                    // documented >window unbounded-token edge; its head is emitted.
                    return bounded_carry_chars_mb(&chars, max_buffer);
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
                return bounded_carry_chars_mb(&chars, max_buffer);
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
    consume_to_boundary(prev_buffer, chunk, max_buffer, force_flush, &cut_fn)
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
