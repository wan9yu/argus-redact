# Known Issues

> v0.5.8 closed every Unresolved entry open at the time. Defects found since are
> listed under **Unresolved** below. Everything under **Design Constraints** is an
> explicit permanent trade-off, documented for transparency — not a backlog.

## Unresolved

### Overlapping spans are resolved by length, not by detection layer

- **What**: `merge_entities` / `pick_winner`
  (`crates/argus-redact-core/src/merger.rs`) resolve an overlap between two detected
  spans by **span length** — the longer span wins, with confidence only as a
  same-length tiebreak. The detection layer is never consulted. An over-greedy
  Layer-1 regex span that is one character longer than a Layer-2 NER span therefore
  discards it, and when the L1 span is the *wrong* one, the PII the NER spans covered
  is left in the clear.
- **Reproduction** (`mode="ner"`, zh): on `客户李明明王小丽联系电话13800138000` the L1
  person candidate generator emits `李明明王` (4 chars, wrong) while the NER model emits
  `李明明` and `王小丽` (both correct). The 4-char L1 span wins both overlaps, both NER
  spans are discarded, and the output is `客户P-NNNNN小丽联系电话138****8000` — the name
  `小丽` in plaintext.
- **Who is affected**: the defect needs an L1↔L2 overlap, so it needs a NER model —
  `mode="ner"` or `mode="auto"`. `mode="fast"` is Layer-1 only and has no cross-layer
  overlap to mis-resolve. Observed in Chinese, where adjacent person names can be fused
  into a single L1 candidate; the merge rule itself is language-neutral.
- **Status — open.** The obvious fix (on an overlap, prefer the higher detection layer,
  L3 > L2 > L1) was implemented, benchmarked and **rejected** in v0.7.20. On
  `pii_bench_zh` — our own benchmark;
  `python -m tests.benchmark pii_bench_zh --mode ner --limit 300` — it fixed exactly what
  it targeted (`person`: +18 true positives, false positives 18 → 0) but cost 6.9pp of
  overall recall (.9057 → .8365, −66 true positives). `address` fell from 64 true
  positives to **0**: the NER model emits one coarse `location` span over each L1
  `address` span, so "higher layer wins" flips the entity type and every address then
  fails the value match. `license_plate` fell from 23 to 3. Neither type carries a
  checksum validator, so a "validated beats unvalidated" precedence could not rescue
  them. "Trust the higher layer" is true for names and false in general — for
  structured-but-unvalidated types, the L1 regex is the detector that knows the correct
  span. Scoping the rule to `person` only is the surviving hypothesis; it is not
  implemented.
- **What you should do**: if your text can contain person names running together with no
  delimiter, do not rely on NER to correct a Layer-1 person span — inserting a separator
  (`、`, comma, space) between adjacent names prevents the fused candidate, and both
  names are then redacted. In audit paths, inspect the spans from
  `redact(..., detailed=True)`: an unusually long `person` span (more than 3 characters
  for Chinese) is the signature of this defect. No configuration changes the merge rule
  today.

### `restore()` can substitute a pseudonym key inside a longer adjacent token

- **What**: `restore()` matches a pseudonym as a plain substring scan, not on a token
  boundary. If a pseudonym is immediately followed (or preceded) by other non-delimiter
  characters that happen to form a longer run — e.g. an LLM or downstream system appends
  a suffix directly onto the code — the key still matches and substitutes inside that
  longer token: `restore("P-12345_final", {"P-12345": "Michael Zhang"}, guard=False)` →
  `"Michael Zhang_final"`, not `"P-12345_final"` left alone.
- **Who is affected**: this is **in-scope only** — the value substituted is always the
  caller's own key's original for a pseudonym the caller minted, never a cross-scope or
  cross-session leak. It surfaces whenever a pseudonym abuts other content with no
  delimiter between them.
- **Why we won't fix**: a token-boundary check was implemented and **rejected**. Chinese
  masked output is often delimiter-free by construction (`P-61961138****8000有事找他` —
  a pseudonym directly followed by CJK text with no separator), so a boundary check would
  make that a *non-match* and leave the pseudonym unrestored. Even a maximal-munch
  boundary heuristic broke a real fixture where a pseudonym abuts literal digits from
  unrelated structured text (e.g. an address's unit number immediately after a
  pseudonym). The failure mode of "under-restores real content" is worse than the failure
  mode of "restores into an adjacent token" for the primary (Chinese, delimiter-sparse)
  use case.
- **What you should do**: if your pipeline concatenates a pseudonym directly against
  other machine-generated content (filenames, IDs, suffixes) with no separator, insert a
  delimiter before doing so. In audit paths, inspect long spans via
  `redact(..., detailed=True)` / `restore(..., detailed=True)`: a restored value that is
  longer than any known original is the signature of this defect.

## Deprecation Notices

### bare `restore()` without `guard=` — flip shipped in v0.8.0

- **What**: Calling `restore(text, key)` without passing `guard=` emitted a
  `DeprecationWarning` from v0.7.18 ("bare restore without guard= is deprecated; will
  default to guard=True in v0.8.0"). **As of v0.8.0, the flip has shipped**: `guard=True`
  is now the default, so a bare `restore(text, key)` with no `anchor` **fails closed** —
  it returns the text un-restored — instead of substituting.
- **Action required**: If your code relied on the old silent-substitution default, pass
  `guard=False` explicitly to keep it. For text that came back from an LLM, migrate to
  `restore(text, key, guard=True, anchor=anchor)` or `guarded_restore()` — see
  `docs/security-model.md` § Guarded restore.
- **Status**: Shipped in v0.8.0. `guard=None` is still accepted (runs the legacy path,
  emits `DeprecationWarning`, and — new in v0.8.0 — also emits a `SecurityWarning` if it
  actually substituted a pseudonym).

## Design Constraints

Each entry follows three lines:

- **What** — one-sentence description of the constraint.
- **Why we won't fix** — the design / external trade-off it reflects.
- **What you should do** — caller-side mitigation.

### `AuditLedger` is caller-persisted and keyless by default

- **What**: `AuditLedger` carries no built-in I/O (like the redaction key — no
  global state, no file is written automatically). Persistence is the caller's
  responsibility: call `to_dict()` and write the result to durable storage;
  reload with `AuditLedger.from_dict(d)`. The default constructor uses plain
  SHA-256 for chaining, which provides append-only integrity (detects interior
  modification, reorder, deletion) but **not** forge-resistance: an adversary who
  controls the ledger store can recompute the entire chain from scratch.
- **Why we won't fix**: Mandatory I/O would impose a storage dependency on every
  caller, including those running argus in-process or in short-lived containers.
  The correct persistence and key-management strategy varies too widely across
  deployment contexts to embed in the library.
- **What you should do**: Pass `hmac_key=secrets.token_bytes(32)` when the threat
  model includes an adversary who controls the ledger store, and keep the HMAC key
  separate from the ledger. For tail-truncation detection, persist `led.head_digest`
  externally after each session (e.g., in a trusted log or signed receipt) and
  compare it against `led.head_digest` after reload. See
  [Compliance artifacts (v0.7.18)](security-model.md#compliance-artifacts-v0718)
  for the full integrity-boundary discussion.

### Out of scope — NLP coref, full-fidelity round-trip, multimodal, tool_use, token streaming

- **What**: argus-redact does **not** address these LLM-pipeline UX concerns:
  - NLP coreference resolution (titles like `张先生`, pronouns, partial references)
  - Full-fidelity semantic round-trip after LLM paraphrase / translation
  - Multimodal redaction (vision, audio, file uploads)
  - Tool-use / function-calling cross-turn state machines
  - Token-by-token streaming (sentence-buffered is the upper bound; see `docs/design-streaming-incremental.md`)
- **Why we won't fix**: each requires an NLP/LLM-mediated solution incompatible with the primitive's "small core, deterministic, audited, fast" SLA. Trying to own them would balloon the surface area beyond single-maintainer capacity. See [architecture-layers.md](architecture-layers.md) for the layered identity argus-redact has codified.
- **What you should do**: use the `pseudonym` strategy (`P-NNNNN`-style codes; LLMs treat them opaquely, fewer variants) for higher restore fidelity; use the `compose` layer's `prompt_anchor()` and `expand_aliases()` (namespace stubs since v0.6.7; helpers ship v0.6.9) for best-effort coverage of common variants; or run a downstream coref-aware gateway (e.g., Argus Gateway) for fuller semantic round-trip.

### Contextual-integrity judgment is out of scope — argus redacts mandatory/structural PII

- **What**: argus detects and redacts **mandatory / structural PII** — identifiers
  sensitive regardless of context (names, IDs, phones, emails, cards, addresses, …).
  It does **not** make **contextual-integrity** judgments: whether a given datum is a
  privacy violation depending on *who* holds it, *why*, and *in what context* (a phone
  number in a medical record vs a public directory).
- **Why we won't fix**: contextual judgment is inherently subjective and LLM-mediated —
  human annotators agree ~89% on mandatory redactions but only ~48% on contextual ones
  (RedactionBench, Brynjólfsson et al. 2026, arXiv:2606.18782, grounded in Nissenbaum's
  contextual-integrity theory). A deterministic, audited, fast primitive cannot and
  should not adjudicate that — it would trade a verifiable contract for an opaque model
  judgment.
- **What you should do**: use argus for the mandatory/structural layer (its strength) and
  route contextual-integrity decisions to a downstream LLM-aware gateway. argus is the
  deterministic floor, not the context adjudicator.

### Force-rebuild on major version pin bump

- **What**: Upgrading the argus-redact pin across a major version boundary (e.g., `0.5.x` → `0.6.0`) requires a clean rebuild of any caller cache that holds pseudonym mappings.
- **Why we won't fix**: cryptographic derivation chain changes (salt schema, KDF, pseudonym seeding) across major versions are by design — they fix security vulnerabilities or close known issues. Pseudonym tokens generated under one chain cannot be reproduced under another, so cached mapping tables become incoherent.
- **What you should do**: when bumping a major version, force a clean rebuild of any docker image / build cache / persisted key store. A downstream project hit a cache-induced false-green on a `0.5.x` → `0.6.0` bump: local dev held stale 0.5.x mappings while the fresh CI build saw real 0.6.0 behavior, and the mismatch surfaced only because CI didn't share the dev cache. Pin to `>=0.6.4` if you saw those symptoms.

### `199-99` mobile sub-segment requires annual review

- **What**: The realistic-mode `199-99-XXXXXX` mobile range relies on this
  sub-segment remaining unassigned by 工信部 (MIIT). Numbering plans are revised
  periodically.
- **Why we won't fix**: External regulatory authority controls this allocation.
  argus-redact cannot anticipate when (or whether) it will be assigned.
- **What you should do**: Re-verify against MIIT public allocations annually.
  If the sub-segment gets assigned, switch to a different unassigned sub-segment.
  The prefix is a literal in the Rust core, in two places that must stay in sync:
  `fake_phone_reserved` in `crates/argus-redact-core/src/fakers.rs` (emits `19999` +
  6 random digits) and the `phone_zh` pollution-scan pattern in
  `crates/argus-redact-core/src/reserved_range.rs`. It is not caller-configurable —
  changing it is a source change plus a rebuild.

### Realistic-mode output must not be re-redacted

- **What**: Re-redacting realistic output (`downstream_text` from
  `redact_pseudonym_llm`) would silently corrupt the key dict — the same fake
  value would map to two different originals.
- **Why we won't fix**: This is intrinsic to deterministic-fake redaction.
  Detecting "is this input already faked?" precisely would require a marker
  channel that defeats the purpose.
- **What you should do**: `redact_pseudonym_llm` raises `PseudonymPollutionError`
  by default. Call `restore()` first; then re-redact the original if needed.

### Realistic data must not be stored as business truth

- **What**: `downstream_text` looks like real PII (`19999...` mobile,
  `999-XX-XXXX` SSN) but is synthetic by design. Persisting it in
  customer / business records causes data pollution that's hard to detect
  post-hoc.
- **Why we won't fix**: This is an operational constraint, not a code
  property. The library cannot enforce how downstream systems persist its
  output.
- **What you should do**: Always pair `downstream_text` with the key dict.
  Never persist `downstream_text` in business databases. Use `audit_text`
  (placeholder labels) for compliance archives.

### HanLP model size (~500MB)

- **What**: The Chinese NER backend (HanLP) ships a ~500MB model file.
- **Why we won't fix**: Smaller character-level models tested produced
  unacceptable quality. The full model is the smallest with usable recall.
- **What you should do**: Use `mode="fast"` (regex + L1b person scoring) for
  production paths where model size matters; reserve `mode="ner"` for
  corpus-scale processing where the larger model amortizes over many calls.

### Ollama cold start (10-20s)

- **What**: First Layer-3 call after process start has a 10-20 second
  initialization cost as the local LLM model loads into memory.
- **Why we won't fix**: Inherent to local-LLM model loading.
- **What you should do**: Warm up Layer 3 at process start by calling
  `redact()` with `mode="auto"` on a no-op input. Subsequent calls are cached.

### Docker full image size (~5GB)

- **What**: The full-stack Docker image (regex + NER + L3 + benchmark) is
  ~5GB.
- **Why we won't fix**: PyTorch + transformer model weights dominate the
  size; multi-stage build is already applied.
- **What you should do**: For deployments that don't need Layer 3, use the
  fast-mode subset image (no PyTorch — typically <1GB).

### Perf-budget baseline is platform-specific and drifts

- **What**: The performance gate (`.github/workflows/perf.yml`) compares each
  PR's measured timings against the committed `tests/benchmark/baseline.json`
  with a fixed ±10% threshold. Those numbers are specific to the CI runner
  (`ubuntu-latest`) and its image, so the baseline legitimately **drifts**: it
  shifts when the runner image's speed changes, and a deliberate design change
  can move a single metric (e.g. the v0.7.x streaming "detect-once on a ±W
  context window" raised the single-large-feed `streaming_feed_per_chunk` cost —
  the inherent price of cross-sentence-correct streaming). Until the baseline is
  refreshed after such a shift, the gate reads red on otherwise-unrelated PRs.
- **Why we won't fix**: a fixed absolute threshold is the simplest reliable
  regression signal; an auto-/relative baseline would mask the regressions the
  gate exists to catch. The gate runs on PRs only (a cheap signal on change),
  and editing `baseline.json` in a PR deliberately **exempts** the gate — the
  caller-owned escape hatch for an intentional refresh or an accepted-cost
  change.
- **What you should do**: refresh the baseline from a **CI (Linux) measurement**,
  never a local dev machine — the comparison is platform-blind ±10%, so a
  macOS/laptop baseline will spuriously trip on the Linux runner. A PR that
  touches `baseline.json` is auto-exempted; the perf job's `Measure` step prints
  the current Linux `current.json` to copy in. Re-baseline (with a one-line note
  in the commit) whenever a deliberate design change shifts a metric — this is
  expected periodic maintenance, not a defect.

### English is best-effort — structured-PII strong, free-text weak, `ner` not recommended

- **What**: argus-redact is Chinese-first. English detection is strong on
  **structured identifiers** (email, phone, SSN, credit card, ID, passport,
  postcode, IP — email tests ~99% recall) but **best-effort on free-text
  entities** (person, location, address), which depend on noisy NER. In English,
  `mode="ner"` can *reduce* precision — spaCy `en_core_web_sm` over-tags `person`
  on prose — so `mode="fast"` is the recommended floor for English.
- **Why we won't fix**: high-precision free-text English entity detection needs a
  model-grade NER that the "small core, deterministic, audited, fast" SLA does not
  carry. The L2 person evidence gate (single-sourced with the L1 gate) filters the
  worst spaCy false positives, but L2 spans lack L1's surname-pool anchor, so a
  residual prose-FP rate remains; chasing it with stricter heuristics trades recall
  and balloons the English surface area beyond single-maintainer scope.
- **What you should do**: use `mode="fast"` for English (structured-PII focused,
  high precision). Treat English free-text person / location / address as
  best-effort; for broad English entity coverage, pair argus with a downstream
  NER-aware gateway. Do not rely on argus for compliance-grade redaction of
  English *free-text* PII. (Chinese `mode="fast"` covers both structured and
  free-text at F1 ~93 — the asymmetry is the zh-first product reality.)

### Korean RRN has no check-digit validator by design

- **What**: `rrn` (Korean Resident Registration Number) is matched on format
  and date-plausibility (the digit pattern must decode to a real month/day)
  only — there is no mod-11 checksum gate on the trailing digits, unlike
  several other national-ID validators.
- **Why we won't fix**: post-2020 Korean RRNs randomize the trailing digits by
  policy, so a checksum computed against the pre-2020 scheme would reject a
  genuine current-issue RRN — a false *negative* that leaves real PII
  unredacted. Format plus date-plausibility is the recall-safe choice for a
  numbering scheme that no longer carries a stable public check digit.
- **What you should do**: treat `rrn` matches as format-validated, not
  checksum-validated. If your input is known pre-2020 and you need stricter
  precision, add a downstream checksum check on top of argus's match.

### Some national-ID validators are length/format-only, not checksum-validated

- **What**: A few validators (`aadhaar`, `de_tax_id`) check digit count and
  a couple of structural constraints (e.g., leading-digit rules) but do not
  implement the full public check-digit algorithm (Aadhaar's Verhoeff digit,
  the German Steuer-ID's pairwise-sum check).
- **Why we won't fix**: over-redaction is the fail-safe direction here — a
  malformed number of the right shape and length is still redacted rather
  than leaked. Implementing and maintaining the full checksum for every
  national scheme is a long tail; where the format-only validator already
  redacts every genuine ID (plus some non-IDs of the same shape), the
  precision cost is preferred over the risk of a checksum bug leaking a real
  ID that fails it.
- **What you should do**: if you need to distinguish a genuine ID from a
  same-shape non-ID number in this pair of types, validate the check digit
  yourself downstream; argus's match tells you "right shape," not
  "cryptographically confirmed valid."

### Chinese evidence-gated detectors suppress low-evidence bare candidates

- **What**: The Chinese bare-surname person heuristic (`person_zh.rs`) and the
  evidence-gated quasi-identifier detectors (bare-region, occupation,
  condition, hobby — `evidence_detector.rs`) require at least one corroborating
  signal (a cue word, an honorific, nearby person-identifying PII, …) before a
  candidate is redacted at Layer 1. A bare surname or region name with zero
  corroborating evidence is deliberately left unredacted at this layer.
- **Why we won't fix**: this is a precision/recall tradeoff, not an oversight.
  Bare surnames and region names appear constantly in ordinary prose that
  isn't about a specific person (`王先生做的很好` vs `我姓王`); redacting every
  occurrence would over-redact common prose. Candidates with no evidence are
  left to Layer 2 (NER), which has broader context to judge them.
- **What you should do**: for `mode="fast"`-only pipelines where recall on
  bare names/regions with no surrounding context matters more than prose
  precision, run `mode="ner"` or `mode="auto"` so Layer 2 gets a chance at the
  low-evidence candidates Layer 1 intentionally passes over.

## Recently Fixed

### v0.8.3 — Streaming checkpoint mid-PII-value resume verified

- **Checkpoint-mid-PII-value resume — closed.** `StreamingRedactor.export_state()`
  / `from_state()` persist `_inc_buffer` and `_ctx_len`, so checkpointing while a
  PII value straddles the in-flight buffer — its head fed, tail not yet arrived —
  and resuming on a NEW instance redacts the completed value exactly as an
  uninterrupted stream would, with no raw leak across the checkpoint seam.
  Verified by `tests/safety/test_streaming_straddle.py::TestCheckpointMidPII`
  (phone, email, and a ~150-char token straddling the force-flush cut).

### v0.7.0 (2026-06-15) — Core Split

- Rust core split into a Cargo workspace: pure-Rust `argus-redact-core` (now on
  crates.io) + `argus-redact-py` PyO3 binding (the wheel). Pseudonym RNG bridged
  via a `RandomSource` trait; output is bit-for-bit identical to v0.6.12 (locked
  by golden-vector + KDF replay tests). **No Python API change.**
- `docs/security.md` gained a "Cloud-LLM pipeline" threat-model section
  (adversarial-provider framing; pseudonymization ≠ anonymization wording).
- CI: sdist install gate + pure-Rust core tests + Cargo.lock shadow guard.

### v0.6.12 (2026-06-15) — zh L1 Coverage (HK/Macao permits + housing fund)

- **往来港澳通行证 (`eep`)** and **港澳居民来往内地通行证 / 回乡证 (`hrp`)**
  now have L1 fast-mode patterns. Both are context-anchored (no public
  checksum exists for either, so the keyword anchor controls false
  positives). The two are distinct direction-opposite documents (`C` vs
  `[HM]` prefix) and never cross-type.
- **公积金账号 (`housing_fund`)** has a context-anchored pattern
  (`公积金账号/账户` + digit run). Housing-fund account formats vary by
  city with no national standard, so coverage is anchor-gated; cities/formats
  not covered can be handled with downstream tenant custom patterns.
- These are L1-regex types; `mode="ner"` (HanLP MSRA = PER/LOC/ORG) does not
  add coverage for structured permit/account numbers.

### v0.6.11 (2026-06-04) — Adapter Surface

- **Layer 2 adapter authoring primitives** (`compose.register_pii_type` /
  `PIITypeDef` / `PatternMatch`) — three re-exports of stable internal APIs.
  Adapter authors can now build PresidioBridge-style integrations against
  a documented Layer 2 contract.
- **Layer 2 signature snapshot** (`tests/architecture/test_compose_signatures.py`) —
  best-effort drift guard. Layer 2 SLA: evolution allowed with CHANGELOG note.
- **Full-FF salt OverflowError fixed** — `b"\xff" * 32` salt no longer crashes
  on `PseudonymGenerator` seed conversion. Modular arithmetic keeps the sum
  in u64.
- **`redact()` return-shape precedence locked** — `report > detailed >
  with_types > default`. Multi-flag combinations now have defined shapes
  and a clean dispatch.
- **Hypothesis flake resolved** — `test_state_round_trip_preserves_aggregate_key`
  strategy now filters polluted inputs via `scan_for_pollution()`, matching
  the production contract.
- **Adapter authoring recipe** (`docs/recipes/writing-an-adapter.md`) —
  with the `_pre_detected=` stability promise spelled out.

### v0.6.10 (2026-06-04) — Pre-1.0 Subtract + Hardening

- **Layer 1 signature lock** (`tests/architecture/test_frozen_api.py`) — 7
  public functions + 3 exception-class parent chains pinned for v1.0 freeze.
  Any future drift requires a major version bump.
- **KDF replay vectors** (`tests/security/test_pseudonym_chain_replay.py`) —
  12 vectors lock the SHAKE-256 / HMAC pseudonym derivation chain. Rust and
  Python-fallback paths verified bit-identical.
- **Top-level `StreamingRedactor` DeprecationWarning** — soft migration to
  the canonical `argus_redact.compose.StreamingRedactor` import path. Full
  removal in v1.0.
- **Defense-in-depth**: server bearer comparison now constant-time
  (`secrets.compare_digest`); new symmetric `safe_read_text` with POSIX
  `O_NOFOLLOW` on key-file + config-file reads; `DEMO_SALT` warning comment
  pointing at `secrets.token_bytes(32)`.
- **CI hardening**: manylinux + musllinux x86_64 release containers pinned
  to digests (no more `:latest` resolution on quay.io). aarch64 rows
  unchanged (already GHCR cross-images).
- **Dead code subtracted**: `RedactMiddleware` (no-op stub),
  `_StreamingBuffer` (replaced in v0.5.x), `generate_pseudonym()` standalone
  function (duplicated class API). Private symbols, zero blast radius.
- **Internal cleanup**: `_core_loader.py` consolidates 4 duplicated Rust
  extension try-imports; `replacer.py` magic numbers extracted to module
  constants; `layer_1b_person_en_ms` telemetry merged into
  `layer_1b_person_ms`.

### v0.6.9 (2026-06-01) — Compose Helpers Ship for Real

- **`compose.prompt_anchor(key, lang) -> str` real implementation** — replaces v0.6.7 NotImplementedError stub. Returns multi-line detailed-3-rule system-prompt addendum (zh + en). Snapshot-tested.
- **`compose.expand_aliases(key, lang) -> dict` real implementation** — replaces v0.6.7 stub. Generates surname+title composite aliases for Person entries; 5 zh titles + 5 en titles; alias → original directionality; handles compound zh surnames + multi-token en names. Round-trip tested.
- **`docs/recipes/compose-{prompt-anchor,expand-aliases}.md`** — two new usage recipes covering when-to-use, combining the two helpers, limitations.
- **Perf baseline refreshed** for ubuntu-latest runner image 20260525.161.1 drift. Same pattern as v0.6.6 PR #15 refresh.
- **Dependabot PR #16 merged**: `docker/setup-qemu-action` bumped from 4.0.0 to 4.1.0 SHA pin in `.github/workflows/release.yml`.

### v0.6.8 (2026-06-01) — API Surface SSOT

- **`seed=` keyword removed from 9 public entry points** — use `salt=` (accepts `int | bytes | None`). Hard break, no DeprecationWarning alias. CLI `--seed N` flag unchanged at the argparse level.
- **`PIITypeDef.strategy` is now runtime SSOT** — `DEFAULT_STRATEGIES` dict deleted; `replace()` reads `lookup(type)[0].strategy`. Per-language test (zh+en+shared) replaces zh-only drift guard.
- **Presidio bridge routes through public `redact()`** via new `_pre_detected=` private kwarg, inheriting MAX_INPUT_SIZE / profile / telemetry / normalization.
- **3 new PII types registered**: `phone_landline` (mask, prefix `LL`), `date` (remove, prefix `DATE`), `url` (remove, prefix `URL`).
- **README.zh.md sync to en parity** — added 5+ missing sections (North Star, Detection accuracy, Risk Assessment CLI, Security, Contributors). Pinned code blocks enforced in CI.
- **README "All 52 types" → "All PII types"**; "PIPL ~85%" → "Meets PIPL Art.28 sensitive PII categories".

### v0.6.7 (2026-06-01) — Layer Codification

- **`argus_redact.compose` namespace shipped** — `StreamingRedactor` / `StreamingRestorer` / `redact_pseudonym_llm` re-exported; `prompt_anchor` / `expand_aliases` stubs raising NotImplementedError with v0.6.9 roadmap hint. Top-level aliases preserved (no DeprecationWarning).
- **`pure/` purity guard** — new `tests/architecture/test_layer_purity.py` AST-walks the primitive subtree and forbids imports of `argus_redact.glue` / `argus_redact.impure` / network / subprocess / LLM-client modules.
- **`__init__.py` `__all__` annotated** with Layer 1 / Layer 2 / Compliance metadata / Type aliases / SSOT / Version section dividers.
- **`glue/redact.py` consumes `layers.py` SSOT** — `LAYER_REGEX` / `LAYER_NER` / `LAYER_SEMANTIC` constants replace 6 integer literals; new test asserts no regression.
- **Architecture doc cross-references** — `architecture.md` and `architecture-layers.md` now carry top blockquotes disambiguating Primitive/Compose/Downstream vs. Pure/Impure/Glue vs. detection L1/L1b/L2/L3.
- **`scripts/sync_docs_version.py` py3.10 compat** — replaced `tomllib` (3.11+) with regex on pyproject.toml. (v0.6.6 CI failure on Python 3.10.)

### v0.6.6 (2026-05-31) — Reader Contract

- **Integration session-isolation** — `RestoreRunnable` / `RestoreTransform` raise `SessionStateError` when paired Redact helper has no key. Previously returned text unchanged, masking a multi-tenant cross-session leak vector.
- **Dead ContextVar stripped from langchain integration** — class docstring no longer claims thread-safe-via-contextvars.
- **README hero example pinned to doctest** — every `<!-- pin -->` ```python``` block in README.md / README.zh.md exec'd in CI.
- **`0% PII leak` headline rewritten** — lists actual PRvL LLMs (GPT-5 / Claude-Opus-4.5 / Gemini-2.5-Pro / GLM-4.5); discloses 96%/Bronze cell on `pseudonym-llm` + Opus-4.5.
- **ai4privacy numbers regenerated on 0.6.6 baseline** — committed JSON under `tests/benchmark/results/`; `docs/benchmark-report.md` is the single source of truth, README carries compact table + link.
- **Single-source version sync** — `scripts/sync_docs_version.py` + `make sync-docs-version[-check]`; CI guards against drift on every PR.

| Issue | Version | Fix |
|-------|---------|-----|
| Compliance metadata SSOT not exposed for downstream | v0.6.5 | New top-level exports `PIPL_REFERENCES`, `GDPR_SPECIAL_CATEGORIES`, `HIPAA_PHI_CATEGORIES` projected from the PII type registry. Drift-guard test (`tests/architecture/test_compliance_metadata_export.py`) ensures every type cites ≥1 PIPL article. See [API reference → Compliance metadata exports](api-reference.md#compliance-metadata-exports-v065) for shapes and usage. |
| Performance regressions could land silently | v0.6.4 | New `.github/workflows/perf.yml` runs 5-run median over 6 workloads on every PR; compares against committed `tests/benchmark/baseline.json` with 10% threshold. Touching the baseline file in a PR exempts the gate (caller-owned). |
| Hypothesis property tests for security invariants | v0.6.3 | New `tests/security/property/`: 6 properties (round-trip, faker-in-reserved-range derived from registry, determinism, keep-whitelist, state round-trip, pseudonym format). Findings landed as fixes in same release. |
| Mutation testing pass on `pure/{replacer,restore,pseudonym}.py` | v0.6.3 | One-shot mutmut run against the then-pure-Python implementations of those three modules (502 mutants killed / 296 survived / 0 real bugs found); 27 targeted unit tests added to kill survivors. Those numbers are a v0.6.3 snapshot and are not reproducible from the current tree — the logic has since moved to the Rust core, where mutation testing runs over the security-critical and Layer-1 modules via `make mutants-core` (cargo-mutants). |
| `SECURITY.md` + GitHub private vulnerability reporting | v0.6.3 | Canonical disclosure channel; supported-versions table; threat-model link to `docs/security.md`; SLA tiers. |
| Codecov soft gate on PRs | v0.6.3 | `.codecov.yml`: 90% patch target, 1% project threshold; comment-only, no merge block. |
| `StreamingRedactor.export_state()` embedded the salt in the serialized dict | v0.6.2 | Default omits salt; pass `include_salt=True` (deprecated) for back-compat. `from_state(state, *, salt=...)` now requires explicit salt kwarg; legacy embedded-salt dumps still load with `DeprecationWarning`. Caller-supplied salt always wins when both are present. |
| HTTP server `/redact` and `/restore` open by default when `ARGUS_API_KEY` unset | v0.6.2 | `create_app(allow_no_auth=False)` raises `RuntimeError` when env var missing. CLI gains `argus-redact serve --insecure` flag for local dev opt-out (emits `SecurityWarning`). |
| CLI write paths followed symlinks; key files mode 0644 | v0.6.2 | New `_safe_io` module: `safe_write_text` / `safe_write_key` / `safe_atomic_write_text` use `O_NOFOLLOW` on POSIX (Windows: `is_symlink` pre-check). Key files written mode 0600. `glue/redact.py:_replace_and_emit` (default redact path's key persistence) also routed through the safe path. |
| MCP `_TOKEN_STORE` was an unbounded module-level dict with no eviction | v0.6.2 | Switched to `OrderedDict` with 5-min idle TTL + 100-entry LRU cap. Token access bumps timestamp (sliding window). Per-session binding deferred to v0.7 (FastMCP API survey). |
| Salt entropy collapsed from caller's full bytes to 8 bytes / 63 bits | v0.6.1 | `_seed_from_salt` no longer truncates: full salt bytes flow through HMAC-SHA256 keying. Caller's 32-byte salt now provides 32 bytes of entropy (was: first 8 bytes). |
| `random.Random` (Mersenne Twister) drove realistic-faker derivation | v0.6.1 | Replaced with `_ShakeRng`, a SHAKE-256-keyed PRNG with rejection-sampled `randint`/`choice`. MT-19937 is reconstructible from output and broke realistic-strategy privacy under chosen-plaintext analysis. |
| `hash(entity_type) % 10000` was process-randomized via PYTHONHASHSEED | v0.6.1 | Replaced with `_type_seed_offset` deriving from SHA-256. "Same salt → same fake" now holds across multi-worker deployments and `from_state` cross-process resume. |
| Empty-salt path silently returned `b""` | v0.6.1 | `_resolve_salt` raises `ValueError` when caller provides no seed/salt and `ARGUS_REDACT_PSEUDONYM_SALT` env var is unset. Pre-fix, the realistic faker derivation collapsed to a deterministic public hash recoverable from one observed (fake, original) pair. |
| Faker could return the input value as the fake (identity-pass leak) | v0.6.1 | `_generate_unique_fake` adds `value` to `used` before rolling. `RESERVED_PERSON_NAMES_EN` no longer contains real common names (`James Smith` / `Bob Loblaw` removed). |
| `strategy="keep"` on non-self-reference type silently passed PII through | v0.6.1 | `keep` now restricted to entities of `type == "self_reference"` whose text is in a whitelist of pronouns + kinship phrases. Other uses downgrade to the type's default with a `SecurityWarning`. Guards against Layer-3 misclassifying sensitive PII as `self_reference`. |
| GitHub Actions used floating tags (incl. PyPI publish step) | v0.6.1 | Every `uses:` in `.github/workflows/*.yml` pinned to a 40-char commit SHA. `id-token: write` scoped to the publish job only. New `.github/dependabot.yml` for weekly grouped SHA bumps. |
| `StreamingRedactor(incremental=False)` legacy opt-out | v0.6.0 | Removed. Sentence-bounded buffering is now the only streaming mode. Passing the kwarg raises `TypeError`. |
| Faker `bare-string` return fallback | v0.6.0 | Removed. `faker_reserved` callables MUST return `tuple[str, list[str]]`. Bare-string returns raise on tuple unpack. |
| Dual `result.key` / `result.key_entries` views | v0.6.0 | Unified to single `result.key: dict[str, str]` + sibling `result.aliases: dict[str, tuple[str, ...]]`. `KeyEntry` dataclass removed. `restore(text, key, aliases=...)` accepts the new kwarg for cross-language recovery. |
| `_unified_prefix` config-dict sentinel | v0.6.0 | Promoted to top-level kwarg `redact(text, unified_prefix="R")` / `redact_pseudonym_llm(..., unified_prefix=...)` / CLI `--unified-prefix`. Passing it as a config key now raises `ValueError`. |
| `replace()` `aliases_out` mutable out-parameter | v0.6.0 | `replace()` returns 3-tuple `(text, key, aliases)` — Pythonic multi-value return. The C-style fill-in-caller-dict pattern is gone. |
| `restore()` silent failure on display-marker text | v0.6.0 | Auto-detects known preset markers (`ⓕ`, `ˢ`, `*`, `(`, `假`, `)`) adjacent to keys and substitutes inline while preserving the marker. Custom markers still require explicit `display_marker=` kwarg. |
| HK / TW / Macau / Taiwan ARC ID types not covered | v0.5.10 | Four new PII types registered: `hk_id`, `tw_id`, `macau_id`, `taiwan_arc`. HKID + TWID have full check-digit validators; Macau and Taiwan ARC are format-only. The `Out of scope (v0.5.x)` section has been removed from this file and from the auto-generated `docs/pii-types.md` catalog. |
| Address transliteration aliases (zh ↔ en) | v0.5.10 | Closes the v0.5.8 `# deferred to v0.6+` TODO. `RESERVED_ADDRESSES_ZH_ALIASES` and `RESERVED_ADDRESSES_EN_ALIASES` populated; address fakers emit non-empty aliases; drift tests guard coverage. |
| `fakers_zh.py` ↔ `fakers_zh_reserved.py` naming asymmetry | v0.5.10 | Renamed `fakers_zh.py` → `fakers_zh_real.py` for symmetry with `fakers_zh_reserved.py`. Module is benchmark/test-data infrastructure only. In v0.7.4 it moved to `tests/benchmark/generators/` (not shipped) and the `faker` field on `PIITypeDef` that it fed was removed; the sole redact-path faker is `faker_reserved`. |
| `assess_risk` PIPL/GDPR/HIPAA inference hardcoded | v0.5.9 | Compliance metadata moved to `PIITypeDef.pipl_articles` / `gdpr_special_category` / `hipaa_phi_category` fields. Rules centralized in `specs/_compliance.py`; downstream DPIA generators read via `specs.get(lang, name)` without mirroring rules. |
| No public way to ask "is this strategy reversible?" | v0.5.9 | New `is_strategy_reversible(strategy)` public helper + `PIITypeDef.is_reversible` derived property. |
| L1/L1b/L2/L3 layer naming had no SSOT | v0.5.9 | New `argus_redact.layers` module exposes `LAYER_REGEX` / `LAYER_NER` / `LAYER_SEMANTIC` / `LAYER_NAMES`. Downstream docs import rather than coining their own. |
| No machine-readable PII type catalog | v0.5.9 | `docs/pii-types.md` auto-generated from registry via `make catalog`; CI drift check fails when out of sync. |
| L1b ±20 char window + 50/150 PII proximity tiers undocumented | v0.5.9 | `docs/architecture.md` documents both distance mechanisms; `tests/detection/lang/test_zh_person.py` adds 4 lockdown tests. |
| Default `remove` strategy output mistaken for `[label]` literal | v0.5.9 | README + configuration.md + getting-started.md show actual `ID-NNNNN` form prominently with explicit ⚠️ callouts. |
| Cross-language LLM rewrites not auto-restored | v0.5.8 → v0.6.0 | v0.5.8 introduced `KeyEntry` + `result.key_entries`. v0.6.0 simplified to flat `result.key: dict[str, str]` + sibling `result.aliases: dict[str, tuple[str, ...]]`. Pass `restore(text, key, aliases=result.aliases)` for cross-language recovery; `KeyEntry` and `result.key_entries` were removed. |
| `StreamingRedactor` default mode required complete logical-unit chunks | v0.5.8 | `incremental=True` is now the default — sentence-bounded buffering handles cross-chunk entities transparently. `incremental=False` opt-out emitted `DeprecationWarning` in v0.5.8 and was removed in v0.6.0. |
| Windows CI test fixture encoding | v0.5.8 hotfix | `tests/conftest.py:load_examples`, `tests/safety/test_*.py` JSON loaders, and CLI `read_text/write_text` test helpers all pin `encoding="utf-8"` for cross-platform compat. |
| zh fast-mode over-redacts pronouns / 3-char co-occurrences (issue #12) | v0.5.7 | (a) `self_reference` now defaults to new `keep` strategy — pronouns / kinship phrases preserved verbatim, never become `P-NNN`. (b) zh person candidate generator propagates negative-name-pool blocks to 3-char extensions, blocking false positives like `任何评`. |
| `StreamingRedactor` cross-chunk entity detection | v0.5.7 | Opt-in `incremental=True` accumulates chunks until a sentence boundary, then runs detection on the buffered prefix. `flush()` drains end-of-stream tail. |
| Windows untested | v0.5.7 | GitHub Actions Windows runner added (Python 3.12 smoke test). UTF-8 encoding pinned on all CLI / glue file I/O for cross-platform stability. |
| hints uk/in/br coverage | v0.5.7 | New `lang/{uk,in_,br}/hints.py` modules; aggregated by `pure/hints.py` registry. v0.5.6 covered zh/en/ja/ko/de; v0.5.7 closes the remaining three. |
| hints language coverage (zh/en only) | v0.5.6 | `self_reference` + command-mode detection now covers zh/en/ja/ko/de via per-lang `lang/<code>/hints.py` modules; aggregated by `pure/hints.py` |
| specs/en.py asymmetric vs specs/zh.py | v0.5.6 | en regex now lives in `specs/en.py:_patterns`; `lang/en/patterns.py` is a thin re-export. Validators (`_validate_ssn`, Luhn, `_MONTHS`) move to `specs/en.py` to break import cycle |
| MCP key exposure in tool response | v0.5.4 | `redact` tool now mints `key_token` (process-scoped UUID). Raw `key` was removed in v0.5.5; restore tool accepts `key_token` only. |
| restore() rebuilt alternation regex per call | v0.5.4 | `lru_cache(maxsize=128)` on `frozenset(key.keys())` — streaming hot path no longer pays compile cost |
| en/person realistic required NER | v0.5.3 | `lang/en/person.py` adds Census surname + SSA given-name list for fast-mode detection |
| Pollution scanner false-positive on canonical names | v0.5.3 | `reserved_names` parameter on `redact_pseudonym_llm` / `StreamingRedactor` lets caller override canonical fake-name tables |
| SSN validation incomplete (666/900-999) | v0.4.10 | Reject invalid area codes per SSA rules |
| Email allows consecutive dots | v0.4.10 | Validate function rejects `..` and leading/trailing dots |
| Age matches 999 | v0.4.10 | Validate function limits to 0-149 |
| 15-digit old ID not detected | v0.4.10 | Separate pattern for pre-1999 format (6+6+3 digits) |
| Unicode email not detected | v0.4.10 | CJK-only local-part pattern (RFC 6531) |
| ID number false positive on 18-digit orders | v0.4.8 | Restore MOD 11-2 checksum validation |
| Near-miss info lost | v0.4.8 | match_patterns returns (entities, near_misses) tuple |
| Report generation removed | v0.4.9 | Use redact(report=True) for raw data, downstream generates reports |
| Unicode bypass (fullwidth, ZWSP, ZWJ, RTL) | v0.4.4 | NFKC normalization + invisible char stripping before regex |
| Input >1MB DoS | v0.4.4 | Input size limit (1MB), rejects with clear error |
| ID number false negative on typos | v0.4.4 | Relaxed checksum: format-valid IDs accepted even with wrong check digit |
| HTTP config path injection | v0.4.4 | Reject config as file path string via HTTP (dict only) |
| NFKC offset mapping bug | v0.4.4 | Per-char normalize instead of broken heuristic |
| HTTP server default 0.0.0.0 | v0.4.3 | Changed to 127.0.0.1 |
| mask strategy leaks partial PII | v0.4.3 | Compliance profiles (pipl/gdpr/hipaa) force remove strategy |
| restore() injection risk | v0.4.3 | `check_restore_safety()` detects pseudonym amplification |
| In-memory key residue | v0.4.3 | `wipe_key()` + limitation documented in security-model.md |
| L3 silent failure | v0.4.3 | layer_3_status in stats (ok/skipped/error) |
| NER silent failure | v0.4.3 | mode="ner" warns when no models available; layer_2_status in stats |
| Passport false positive (version numbers) | v0.4.3 | Keyword-triggered pattern (requires "护照" prefix) |
| Person name false positive ("段代码") | v0.4.3 | Evidence-gating: requires structural signal |
| German phone too loose | v0.4.3 | Structured format + digit count validation |
| `import secrets` displaced | v0.4.2 | Moved back to module level |
