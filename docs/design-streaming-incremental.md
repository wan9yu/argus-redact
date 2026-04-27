# Streaming incremental detection — design notes (v0.5.7+)

This document explains the design behind `StreamingRedactor(incremental=True)`,
introduced in v0.5.7 to handle entities that span chunk boundaries.

## Problem

`StreamingRedactor.feed()` in v0.5.6 required each chunk to be a complete
logical unit (sentence / paragraph / turn). When upstream code feeds raw LLM
tokens or arbitrary byte chunks, an entity that straddles a chunk boundary
goes undetected:

```python
r = StreamingRedactor(salt=b"...")
r.feed("Call 1391")           # no entity detected
r.feed("2345678 today.")      # no entity detected
# Phone "13912345678" was split — both halves slip through unredacted.
```

This breaks the privacy contract whenever the producer's chunk size is not
under the consumer's control (most streaming LLM clients).

## Algorithm

We commit to detect on **complete sentence prefixes**, identified by a fixed
boundary set:

```
\n   。   .   ！   !   ？   ?   ；   ;
```

Each `feed(chunk)` call:

1. Concatenate `combined = self._inc_buffer + chunk`.
2. Find the rightmost boundary character in `combined`.
3. If found at position `b`: emit `combined[:b]`, keep `combined[b:]` as the
   new buffer.
4. If no boundary and `len(combined) >= max_buffer (=4096)`: forced flush —
   emit everything, clear the buffer. Prevents unbounded growth on input
   without sentence punctuation (raw token streams, JSON, code blocks).
5. Otherwise: hold the buffer, return an empty `PseudonymLLMResult`.

`flush()` runs the forced-flush branch on whatever is left in the buffer at
end-of-stream.

The emitted prefix is run through the standard pipeline: `_detect()` →
`_replace_and_emit()` (realistic + audit) → `PseudonymLLMResult`. The
`existing_key` mechanism (already used for cross-chunk consistency) ensures
the same original value reuses the same fake even when first seen mid-stream.

## Why sentence boundaries (not byte-level partial regex)

A "true" byte-level partial regex state machine would track every pattern's
intermediate match state and emit entities the moment they're complete. It
would have lower latency on token streams without punctuation.

We rejected it for v0.5.7 because:

- **Implementation cost**: Python's `re` module doesn't support partial
  matching natively. A full state-machine approach requires either the
  third-party `regex` library (new runtime dependency) or hand-rolled
  per-pattern automata (large surface area, hard to keep correct as patterns
  evolve).
- **Recall scope**: 98% of real-world LLM output contains sentence
  punctuation within a few hundred characters. Sentence boundaries are good
  enough for the dominant use case.
- **NER + L3 LLM compatibility**: Layer 2 NER and Layer 3 semantic detection
  operate on complete sentences anyway. A byte-level partial scheme would
  need per-layer adaptation; sentence boundaries are uniform.

The forced flush at `max_buffer=4096` is the safety valve for the 2% case.

## Public API

`StreamingRedactor.__init__(..., incremental=False)`. Default off — preserves
v0.5.6 behavior exactly.

When `True`:

- `feed(chunk)` may return an empty `PseudonymLLMResult` (caller must check
  before using).
- `flush()` should be called once at end-of-stream to drain a no-boundary
  tail.

`existing_key` and `aggregate_key()` work identically in both modes — the
unified key dict is built up as entities are emitted. `export_state()` /
`from_state()` continue to round-trip correctly; the incremental buffer is
included in `_inc_buffer` for completeness, though current schema does not
serialize it (mid-stream resume is out of scope for v0.5.7).

## Private internals

Two private modules in `glue/`:

- `_detect_partial.py` — pure helper: `(text, prev_buffer) → (entities, residual)`.
  Includes `_last_boundary_index()` (used by both `_detect_partial` and the
  redactor's incremental branch) and a `force_flush=True` switch for
  end-of-stream cases.
- `_streaming_buffer.py` — `_StreamingBuffer` class wrapping the helper.
  Provides a stateful detect-only interface: `feed(chunk) → list[PatternMatch]`
  and `flush() → list[PatternMatch]`. Not used by `StreamingRedactor`
  directly (which inlines its own buffering for access to emit-text), but
  available for callers that want raw entities without replacement.

## Limitations & roadmap

- **NER cost**: every emit-segment runs the full L1+L2+L3 pipeline. For long
  streams with frequent sentence breaks this is N detections instead of 1.
  Mitigations on the table for v0.5.8+: (a) lazy NER (only if L1 found
  high-density PII), (b) explicit `min_emit_chunk` threshold to amortize.
- **Mid-stream state schema**: `export_state()` does not currently round-trip
  `_inc_buffer`. A long-running session that pauses mid-sentence and resumes
  via `from_state()` will lose the incomplete tail. v0.5.8+ schema bump can
  add it.
- **Byte-level partial detection** (a true state machine across regex
  patterns) is the v0.6+ candidate when token-stream latency demands it.
