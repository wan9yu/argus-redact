# Changelog

All notable changes to argus-redact. Maintained from v0.6.6 forward. Prior releases documented in git history and `docs/known-issues.md` "Recently Fixed".

## v0.7.13 — Faker fail-closed + crate-publish recovery

A bug-fix release. The `date_of_birth` realistic faker could crash redaction on
date forms it cannot synthesize; it now fails closed. Also restores the
crates.io publish that the v0.7.12 pipeline missed. **No detection-output
change.**

### Fixed
- **`date_of_birth` realistic faker no longer crashes on dates it can't fake.**
  The detector matches year-month (`生日2000年1月`), 2-digit years, and
  Chinese-numeral months (`生日三月`, `出生于十一月十五日`), but the date-noise
  faker only shifts a full Y-M-D date. Previously an unfakeable match exhausted
  the re-roll loop and raised `ValueError` in realistic / `redact_pseudonym_llm`
  modes. Now any realistic faker that cannot produce a unique non-identity fake
  **fails closed to a pseudonym** — the entity stays redacted, the original is
  never echoed, and redaction never raises. Genuine faker errors (a custom
  callable that raises, an unknown built-in) still surface. Fast mode (default
  `remove`) was never affected.

### Internal
- **The Cargo workspace version is now synced from `pyproject.toml`.** `make
  sync-docs-version` (and its CI `--check`) now rewrites `[workspace.package]
  version`, closing the gap that left v0.7.12 on crates.io at 0.7.11 while PyPI
  shipped 0.7.12. crates.io skips the failed 0.7.12 and resumes at 0.7.13.

## v0.7.12 — zh quasi-identifier detection breadth + re-identification eval

Broadens Chinese quasi-identifier detection and adds a re-identification
evaluation axis. **New detection output** (region / occupation / condition /
hobby) feeds the default `remove` path; realistic-fake and pseudonym output for
existing types is unchanged. One new type (`hobby`), bringing the catalog to 63.

### Added — detection breadth (evidence-gated, Chinese)
- **Shared evidence-gated detector framework** (`evidence_detector`): cue regex +
  curated-lexicon confidence + PII-proximity, with a precision threshold and a
  first-character prefilter. New detectors instantiate it; the existing
  person/region/occupation detectors are unchanged.
- **Region detector** — bare administrative regions (not only structured
  addresses) are caught at L1, and a district match absorbs its leading
  parent-city prefix (`上海浦东新区` → one span, no bare `上海` left over).
- **Occupation detector** — bare job titles caught at L1 (honorific-guarded).
- **Condition / allergy coverage** (`medical`) — free-text conditions and
  allergies (`对X过敏`, `患有…`) beyond the structured medication pattern, which
  was also split to gate `吃了/吃的` on a drug suffix and to catch common
  suffix-less drug names (closing a `吃了<drug>` leak).
- **`hobby` type** — a re-identification quasi-identifier, default `remove`.
  Honestly *not* a GDPR special / PIPL sensitive category; included for re-id
  reduction, not compliance.

### Added — evaluation
- **Re-identification eval** (`tests/benchmark/reid_eval.py`, off by default,
  `ARGUS_REID_EVAL=1`) — a closed-world synthetic 24-persona fixture measuring
  how often an LLM re-identifies a redacted profile, plus an ablation harness to
  rank which surviving signal carries re-id leverage.

### Notes
- A `generalize` strategy and Chinese admin-region coarsening were explored,
  measured against the re-id eval, and **removed before release** — coarsening a
  quasi-identifier (district → city) did not beat full removal (tie-to-noise).
  See `docs/design-quasi-identifier-generalization.md`. The region/occupation
  detectors built alongside it were kept.
- `DetectL1Result::entities()` renamed to `layer1_and_person()` (honest helper
  name); detector lexicon loading deduped via `DetectorConfig::from_ron`.

## v0.7.11 — In-browser WASM build

Adds a WebAssembly build for fully in-browser PII redaction, plus maintenance.
**No change to Python/crates behavior** — the supporting core refactors are
parity-preserving (golden vectors byte-identical to v0.7.10); zero migration.

### Added
- **`argus-redact-wasm`** — a WebAssembly build (wasm-bindgen) exposing fast-mode
  `redact()` / `restore()` and a streaming `StreamingRedactor` (`feed`/`flush`),
  for browser + Node, all 8 languages, all built-in types + strategies. Shipped
  as the `pkg/` artifact on the GitHub release (not published to npm). Output is
  byte-identical to the native fast-mode engine (same detection, realistic fakes,
  and pseudonym codes). ~823 KB gzipped.

### Internal (parity-preserving, no output change)
- The last replace-path logic moved into the Rust core so the PyO3 binding and
  the WASM build share one implementation (SSOT): built-in `TypeInfo` assembly,
  the pseudonym RNG (a CPython-exact MT19937 port that removes the CPython
  `random` dependency), and the streaming carry-window state machine (the Python
  `StreamingRedactor`/`StreamingRestorer` are now thin shims). Golden vectors
  unchanged.

### Chore
- Bump `actions/checkout` to v7.0.0 and `taiki-e/install-action` to v2.82.2.

## v0.7.10 — Detection-correctness closeout

A focused follow-up to v0.7.9 that closes three detection-correctness gaps from
the v0.7.9 audit and folds in maintenance quick-wins. **Detection output changes
for English person names by design** (the golden vectors were regenerated); all
other detection output is unchanged from v0.7.9.

### Detection correctness (output intentionally changes)

- **No leading-slice leak when an entity contains a self-reference.** A
  non-priority entity (organization, address) that wholly contains an interior
  self_reference is now redacted whole; previously the container's leading slice
  could leak (e.g. zh `自我管理咨询有限公司` → `自我[ORG]`). The contained
  self_reference yields to its container.
- **Streaming no longer splits an entity at a chunk boundary.** `StreamingRedactor`
  carries a trailing window across the buffer force-flush, and no longer treats a
  `.` inside an email/host (or a trailing ambiguous `.`) as a flush point — so an
  entity straddling a chunk boundary is caught whole next round instead of leaking
  a raw fragment. CJK boundaries and `\n` are unchanged.
- **English person detection is evidence-gated.** A bare `Capitalized Surname`
  pair is no longer auto-redacted; it must be corroborated — a known given name,
  a title (Mr/Dr/…), proximity to other PII, or a pool-independent "name-like"
  leading token (alphabetic, not a common English word). This recovers precision
  on noisy prose (drops `Central Park`-style false positives) while keeping the
  recall trade origin-neutral: the name-like signal recovers non-Anglo full names
  (Marco Rossi, Wei Chen, D'Andre…) the US given-name pool misses, rather than an
  Anglo-biased gate. zh person detection already used this evidence model.

### Maintenance

- **Quick-wins:** corrected the api-reference note on fast-mode person detection;
  moved key-file loading out of the pure layer into glue (pure `restore` is now
  I/O-free); scrubbed the Layer-3 failure log to the exception type only (no
  traceback / input fragment); broke the registry↔replacer import cycle via a
  leaf module.
- **Mutation testing extended to the detection core.** `make mutants-core` now
  covers normalize / redact_l1 / person_en / person_zh / patterns; genuine
  surviving mutants were killed with Rust unit tests.

### Honest note

The English evidence-gate recovers person precision on the Kaggle PIILO
real-essay set (`fast`-mode 67.2% → 71.6%) for a small recall trade
(31.7% → 29.8%). The
benchmark precision understates the gate: a large share of the remaining "false
positives" are real names the value-exact benchmark counts as errors
(whitespace/zero-width mismatches, or non-PII famous-name citations the gold
does not label). The dominant recall ceiling is surname-pool coverage (non-Anglo
surnames not yet pooled), not the gate. ai4privacy (no person type) and the
Chinese suite are unchanged; English benchmarks were re-run — see
[docs/benchmark-report.md](docs/benchmark-report.md).

## v0.7.9 — Hardening

A security and detection-correctness hardening release. **This is an
intentional bit-identity departure from v0.7.8**: v0.7.9 changes detection
output by design (new card families, Unicode normalization, recall work), and
the golden vectors were regenerated to match. Pin v0.7.8 if you depend on
byte-for-byte v0.7.8 output; otherwise upgrade for the broader coverage and the
fail-closed defaults below. This realignment is per the design spec.

### Security / fail-closed

- **Fail-closed detection layers.** A requested layer that is unavailable no
  longer silently degrades:
  - `mode="ner"` raises `LayerUnavailableError` when no NER model is installed
    (previously fell back to L1 silently).
  - `mode="auto"` emits a warning and reflects the missing layer in status when
    L2/L3 are unavailable, and continues with the layers it has.
  - New `strict=` parameter on `redact()` (default `False`): `strict=True`
    turns the `auto`-mode degradation warnings into raised errors, for callers
    that must not ship partial coverage.
- **Unknown `lang` raises** `ValueError` instead of silently treating a typo'd
  language code as "no language" (fail-closed input validation).
- **Missing `_core` extension raises** at `redact()` time rather than producing
  unredacted output — a missing/broken native extension can no longer
  fail open.
- **HIPAA profile redacts ≥ default.** Dropped the prior under-redacting
  whitelist; the `hipaa` profile now redacts at least as much as `default`.
- **Ollama egress guard.** A non-loopback `OLLAMA_HOST` ships raw,
  pre-redaction text off the box; it is now default-denied and requires an
  explicit `ARGUS_ALLOW_REMOTE_OLLAMA=1` opt-in (which also warns, naming the
  remote host).
- **CLI key-file hardening.** Input reads use `O_NOFOLLOW` (refuse symlinks),
  and key-bearing output files are written with mode `0o600`.
- **Rust `MAX_INPUT_SIZE` cap.** The core enforces an input-size ceiling and
  fails closed on the pattern scan rather than attempting unbounded work.
- **Low-entropy salt warning.** A salt with insufficient entropy now warns
  (a salt-keyed KDF strengthening is deferred — see Known limitations).

### Detection correctness (output intentionally changes)

- **American Express / Diners Club cards** are now detected (Luhn floor lowered
  to 13 digits, broadened card regex).
- **Combining-mark normalization.** `normalize_text` folds combining marks
  (offset-mapped so spans map back to the original text), and person detection
  now runs on the normalized text with spans mapped back — closing a class of
  diacritic-based evasions.
- **Full Unicode confusables.** A generated confusables table
  (Latin / Cyrillic / Greek / Coptic, parity-gated) replaces the prior partial
  homograph defense.
- **Context-heuristic gate fix.** Checksum-validated matches (e.g. Luhn,
  MOD11-2) are no longer suppressed by adjacent context heuristics.
- **Recall improvements.** Unicode-aware English tokenizer; grown en/zh surname
  pools for non-Anglo names (parity-gated); a zh "surname + 3 characters" cap.
- **zh org/school regex linearization.** Atomic suffix groups plus a lowered
  backtrack limit for the Chinese organization/school patterns (ReDoS
  hardening).
- **CJK-digit homograph fix.** A lone CJK-digit homograph is no longer folded
  into an adjacent ASCII PII run, closing an adjacency leak.

### Honest note

Recall improved broadly, with a precision tradeoff on noisy English prose. On
the Kaggle PIILO real-essay set, `fast`-mode person-name recall rose
(2.9% → 29.8%) while precision dropped (90% → 69%) as the broader detection
adds false positives on free-form text. Benchmarks were re-run on v0.7.9; see
[docs/benchmark-report.md](docs/benchmark-report.md) for the full matrix and
reproduction commands.

### Known limitations

- **Cross-salt isolation** holds for **pseudonymized** values but **not for
  masked** values: masked outputs are deterministic codes, so the same masked
  input yields the same masked output across salts. An LLM-roundtrip-safe,
  salt-keyed masking scheme is deferred.

## v0.7.1 – v0.7.8 — Rust core migration

The v0.7.x line moved the detection/redaction hot path from Python into the
`argus-redact-core` Rust crate, in steps. Each release was locked to
**bit-for-bit identical output** by golden-vector + KDF-replay parity tests —
the Python API was unchanged throughout, and Python users needed no migration
(`pip install -U`).

- **v0.7.8 — Tier-1 close-out (100% Rust):** the L1 hot path is fully in Rust;
  the Python entity merger fork was closed via
  `_core.merge_entities_with_text`.
- **v0.7.7 — Rust L1 redact/restore engine:** the redact/restore engine moved
  to Rust.
- **v0.7.6 — zh + en person scoring → Rust.**
- **v0.7.5 — Faker-registry / crypto SSOT collapse:** closed the cleanup arc.
- **v0.7.4 — Zero-debt cleanup:** the Python redact path became a thin shell
  over the core.
- **v0.7.3 — Replace / Restore / Fakers engine → Rust.**
- **v0.7.2 — Detection normalization → Rust.**
- **v0.7.1 — Patterns + Validators → Rust SSOT.**

## v0.7.0 — 2026-06-15 — Core Split

### Changed

- The Rust core is now a **Cargo workspace** with two crates:
  - `argus-redact-core` — pure-Rust algorithms (regex matching, entity merging,
    restore, pseudonym derivation), no PyO3. **Published to crates.io.**
  - `argus-redact-py` — the PyO3 binding (`_core` extension module), the wheel
    artifact (`publish = false`).
  The pseudonym RNG is bridged via a `RandomSource` trait so the core stays
  PyO3-free; the binding implements it over Python's `random.Random` / `secrets`.
  Output is **bit-for-bit identical** to v0.6.12 (locked by golden-vector + KDF
  replay tests).

### Added

- `argus-redact-core` on crates.io — the detection/redaction primitives are now
  consumable from any Rust project (and the foundation for future iOS / Android /
  WASM builds). Lockstep-versioned with the Python package.
- `docs/security.md` — new "Cloud-LLM pipeline" threat-model section: what
  pseudonymization does and does not buy you against an adversarial LLM provider,
  with explicit wording constraints (pseudonymization ≠ anonymization under
  GDPR / PIPL).
- CI: sdist install gate (builds + installs from sdist in a fresh venv, catches
  workspace path-dependency vendoring bugs), pure-Rust `cargo test -p
  argus-redact-core`, and a member-level `Cargo.lock` shadow guard.

### Compatibility

- **No Python API change. Python users: zero migration — `pip install -U`.**
  The `_core` module name and `.so` filename are preserved; the public API is
  frozen at v0.6.10 and unchanged.
- New: Rust consumers can depend on `argus-redact-core` from crates.io.

## v0.6.12 — 2026-06-15 — zh L1 Coverage (HK/Macao permits + housing fund)

### Added

Three new zh PII types closing L1 fast-mode coverage gaps reported by a
downstream privacy-gateway consumer:

- `eep` — **往来港澳通行证** (Exit-Entry Permit for Travelling to/from HK and
  Macao; mainland residents → HK/Macao). `C` + 8 digits, or (since
  2018-12-03) `C` + 1 letter (I/O excluded) + 7 digits. `sensitivity=4`,
  `strategy=remove`.
- `hrp` — **港澳居民来往内地通行证 / 回乡证** (Mainland Travel Permit for
  HK/Macao Residents; HK/Macao residents → mainland). `[HM]` + 8 digits,
  with an optional 2-digit renewal-count suffix. `sensitivity=4`.
- `housing_fund` — **公积金账号** (housing provident fund account).
  Context-anchored only (`公积金账号/账户` + digit run) because account
  formats vary by city with no national standard. `sensitivity=3`.

All three are **context-anchored** (the keyword is baked into the regex with
a named capture group) because none carries a public checksum — the anchor,
not a check digit, controls false positives. Bare formats (e.g. a stray
`C12345678` with no permit keyword nearby) are deliberately **not** matched.
The two permits are direction-opposite documents with distinct prefixes
(`C` vs `[HM]`) and are kept as separate types — a `C`-prefixed string is
never typed as `hrp`, and vice versa.

### Notes

- Detection lives in both `lang/zh/patterns.py` (runtime fast-mode list) and
  the `specs/zh.py` registry (catalog/fixtures/metadata); the two regexes
  are byte-identical.
- `mode="ner"` does not add coverage for these types (HanLP MSRA is PER/LOC/ORG
  only) — they are L1-regex types.
- For PII with no national format (e.g. housing fund in cities argus does not
  cover), tenants can add custom patterns downstream.

### Compatibility

- No breaking changes. Purely additive detection. No Python API change.

## v0.6.11 — 2026-06-04 — Adapter Surface

### Added

- `argus_redact.compose.register_pii_type` — public re-export of
  `argus_redact.specs.registry.register`. Adapter authors can register
  custom PII types at runtime; the type then flows through `redact()` /
  `restore()` round-trip with stable pseudonyms.
- `argus_redact.compose.PIITypeDef` — public re-export of the type-definition
  dataclass.
- `argus_redact.compose.PatternMatch` — public re-export of the entity-result
  dataclass used by the `_pre_detected=` adapter hook.

  All three primitives were already importable from internal locations
  (`argus_redact.specs.registry`, `argus_redact._types`) and stable since
  v0.6.5 / v0.6.6 / v0.6.8 respectively. v0.6.11 attaches Layer 2 best-effort
  SLA — signatures may evolve in minor releases with a deprecation cycle.
- `tests/architecture/test_compose_signatures.py` — Layer 2 best-effort
  signature snapshot. Drift = update snapshot + note Layer 2 evolution
  in next release's CHANGELOG (not a major-version requirement).
- `tests/core/test_redact_return_shapes.py` — locks `redact()` return-shape
  precedence: `report > detailed > with_types > default`.
- `docs/recipes/writing-an-adapter.md` — full PresidioBridge-style adapter
  tutorial, including the `_pre_detected=` stability promise.

### Fixed

- Full-FF salt (`b"\xff" * 32`) no longer raises `OverflowError`. Modular
  arithmetic on the `(pseudo_seed_int + _type_seed_offset)` sum (applied
  at all three `PseudonymGenerator` construction sites) keeps the u64
  conversion safe. No observable behavior change for non-saturated salts.
- `redact()` return-shape precedence locked across `with_types` / `detailed`
  / `report` flag combinations. Dispatch refactored to a single ordered
  if/elif chain. Observed precedence already matched the spec; refactor
  is non-behavioral.
- `tests/security/property/test_state_round_trip.py` hypothesis flake
  resolved by filtering the chunks strategy through `scan_for_pollution()`
  (the same check `StreamingRedactor` enforces in `strict_input=True`
  mode). The bit-equality assertion is preserved; only the input domain
  was narrowed to match the production contract.

### Internal

- 2 new KDF replay vectors covering full-FF salt and 10KB single-entity
  input (`tests/security/test_pseudonym_chain_replay.py`).
- `glue/redact.py` return-shape dispatch refactored to a clean if/elif
  chain (one branch per precedence level, each commented with its flag
  combination).

### Stability promise

- `_pre_detected=` kwarg on `redact()` remains private but **stable through
  v0.6.x and v1.0** (no rename, no removal). If a public `pre_detected`
  (no underscore) ships in v1.1+, it will land with a deprecation cycle.
  Adapter authors using `_pre_detected=` today are safe through the v1.0
  freeze.

### Compatibility

- No breaking changes. All adapter primitives are pure re-exports; the
  underlying APIs at `argus_redact.specs.registry` and `argus_redact._types`
  remain importable.
- Test count: 1936 (v0.6.10) → 1958 (+22 across the 6 commits).

## v0.6.10 — 2026-06-04 — Pre-1.0 Subtract + Hardening

### Removed

- `RedactMiddleware` (was a no-op stub — `__init__` only, no `__call__`).
  Use `redact_body` endpoint helper from
  `argus_redact.integrations.fastapi_middleware` (already the recommended
  path; see module docstring).
- `argus_redact.glue._streaming_buffer` and its `_StreamingBuffer` class
  (private; replaced by StreamingRestorer buffer logic in v0.5.x).
- `argus_redact.pure.pseudonym.generate_pseudonym()` standalone function
  (private; duplicated `PseudonymGenerator` class API). The class is
  unchanged.

### Deprecated

- `from argus_redact import StreamingRedactor` now emits `DeprecationWarning`.
  Canonical path: `from argus_redact.compose import StreamingRedactor`. The
  top-level symbol still resolves (lazy via PEP 562 `__getattr__`); removal
  deferred to v1.0.

### Hardened

- Server `/restore` bearer comparison now uses `secrets.compare_digest`
  (constant-time, closes the timing side-channel).
- New `argus_redact._safe_io.safe_read_text` mirrors `safe_write_text` —
  POSIX `O_NOFOLLOW` on key-file + config-file read paths
  (`cli/main.py`, `glue/redact.py`, `pure/restore.py`).
- `demo/app.py` `DEMO_SALT` now carries an explicit warning comment
  pointing at `secrets.token_bytes(32)` for production deployments.
- `.github/workflows/release.yml` manylinux + musllinux x86_64 containers
  pinned to digests (replacing `:latest`) — closes the quay.io
  `manifests/latest` resolution endpoint as a release-blocking surface.
  aarch64 rows continue using maturin-action's default GHCR cross-images.

### Added (CI guards)

- `tests/architecture/test_frozen_api.py` — Layer 1 signature lock for
  v1.0 freeze. 7 function signatures + 3 exception-class parent chains;
  drift requires a major version (v2.0+).
- `tests/security/test_pseudonym_chain_replay.py` — KDF replay vectors.
  Locks the SHAKE-256 / HMAC derivation chain across releases (12
  vectors covering all 8 PII types + zh/en edges).

### Internal

- `argus_redact._core_loader.py` consolidates 4 duplicated
  `try: from argus_redact import _core` blocks across pure/glue modules.
- `pure/replacer.py` magic numbers extracted to module constants
  (`_CIRCLED_DIGITS`, `_MAX_NUMERIC_COLLISION_SUFFIX`,
  `_TYPE_SEED_OFFSET_MOD`, `_DEFAULT_REDACT_LABEL`).
- `glue/redact.py` telemetry: `layer_1b_person_en_ms` merged into
  `layer_1b_person_ms` (layer-level aggregation only; lang-suffix variant
  removed).

### Compatibility

- Top-level `StreamingRedactor` symbol still resolves; warning only. No
  caller code stops working in v0.6.10. Removal scheduled for v1.0.
- Internal-only removals (`_StreamingBuffer`, `generate_pseudonym`):
  blast radius zero (private symbols, never in `__init__.py`).
- `RedactMiddleware`: callers using it got no redaction anyway (no-op
  stub); `redact_body` endpoint helper is the working path.

## v0.6.9 — 2026-06-01 — Compose Helpers Ship for Real

### Features

- `compose.prompt_anchor(key, lang) -> str` — real implementation. Returns a
  multi-line system-prompt addendum (detailed 3-rule template, zh + en)
  asking the LLM to preserve redaction placeholders verbatim. Empty key
  returns empty string. Snapshot-tested.
- `compose.expand_aliases(key, lang) -> dict` — real implementation. Returns
  a copy of `key` with surname+title composite aliases added for each
  Person entry (P-NNNNN prefix). 5 zh titles (先生/女士/总/老师/医生),
  5 en titles (Mr./Mrs./Ms./Dr./Prof.). Handles compound zh surnames
  (欧阳/司马/...) and multi-token en names with trailing initials. Original
  dict not mutated. Alias direction: alias → original (single-pass restore).
- New recipes: `docs/recipes/compose-prompt-anchor.md`,
  `docs/recipes/compose-expand-aliases.md`.

### Chores

- Refreshed `tests/benchmark/baseline.json` (ubuntu-latest runner image
  20260525.161.1 drift). PR #16 perf gate unblocked.
- Merged dependabot PR #16: `docker/setup-qemu-action` bumped from 4.0.0
  to 4.1.0 SHA pin in `.github/workflows/release.yml`.

### Compatibility

- No breaking changes.
- Both compose helpers replace v0.6.7 stubs (NotImplementedError → real).
  Signatures unchanged.

## v0.6.8 — 2026-06-01 — API Surface SSOT

### Breaking changes

- **`seed=` keyword removed from all 9 public entry points.** Use `salt=` instead.
  Canonical type: `salt: int | bytes | None` (int coerced internally to 8-byte BE).
  Affects: `redact`, `redact_pseudonym_llm`, `StreamingRedactor`, `redact_json`,
  `redact_csv`, `RedactRunnable`, `RedactTransform`, `PresidioBridge.redact`,
  `redact_body`. CLI `--seed N` flag unchanged.

  Migration: `grep -rn "seed=" your_code/ | xargs sed -i 's/seed=/salt=/g'`

### Features

- 3 new PII types registered with default strategies: `phone_landline`
  (`mask`, prefix `LL`), `date` (`remove`, prefix `DATE`), `url` (`remove`,
  prefix `URL`).
- `PIITypeDef.strategy` is now the runtime single source of truth. The
  parallel `DEFAULT_STRATEGIES` dict in `pure/replacer.py` is removed;
  `replace()` reads strategy directly from the type registry via a new
  `_resolve_default_strategy()` helper. Per-language test (zh + en + shared)
  replaces the previous zh-only drift guard.
- Public `redact()` gains a new private kwarg
  `_pre_detected: list[PatternMatch] | None = None`. Integration adapters
  (e.g., `PresidioBridge`) pass pre-detected entities through this hook,
  inheriting all pipeline guarantees (MAX_INPUT_SIZE / `isinstance(text, str)` /
  profile / telemetry / normalization / `types` filter / key persistence).
  The kwarg is underscore-prefixed and NOT part of the public stability
  contract.
- `PresidioBridge.redact()` refactored to call `argus_redact.redact()` via
  the new hook — no longer reaches into `pure.merger` / `pure.replacer`.

### Docs

- `README.zh.md` brought to 1:1 parity with `README.md` — 5+ previously
  missing sections added (North Star, Detection accuracy, Risk Assessment
  CLI, Security, Contributors, plus full Documentation table). Pinned code
  blocks in zh README are enforced by `tests/test_readme_examples.py`.
- `README.md` link "All 52 types" → "All PII types" (drops drift-prone
  count).
- `README.md` "PIPL ~85%" → "Meets PIPL Art.28 sensitive PII categories"
  (qualitative wording aligned with README.md:305 existing claim).

### Compatibility

- **Breaking**: `seed=` keyword. Migrate to `salt=`.
- No public symbol additions to `argus_redact.*` top-level.
- `_pre_detected` is private (underscore-prefixed). Not documented in
  api-reference.md. May evolve.
- `DEFAULT_STRATEGIES` dict removed — was an internal `pure/replacer.py`
  module attribute; downstream code reading it directly will break.
  Use `argus_redact.specs.registry.lookup(type)[0].strategy` instead.

## v0.6.7 — 2026-06-01 — Layer Codification

### Features

- New `argus_redact.compose` namespace consolidates the Layer 2 public surface:
  - `StreamingRedactor` / `StreamingRestorer` (re-exported from `argus_redact.streaming`)
  - `redact_pseudonym_llm` (re-exported from `argus_redact.glue.redact_pseudonym_llm`)
  - `prompt_anchor(key, lang)` — stub raising NotImplementedError; full implementation ships in v0.6.9
  - `expand_aliases(key, lang)` — stub raising NotImplementedError; full implementation ships in v0.6.9
- Top-level `argus_redact.{StreamingRedactor, redact_pseudonym_llm}` aliases remain functional (no DeprecationWarning until v0.6.10). `StreamingRestorer` is reachable only via the new compose namespace — its first public path.

### Tooling

- New `tests/architecture/test_layer_purity.py` — AST guard ensuring `src/argus_redact/pure/` never imports network / subprocess / LLM clients / higher-layer modules. The Layer 1 frozen-at-1.0 promise is now mechanically enforced.
- `src/argus_redact/__init__.py` `__all__` annotated with inline Layer 1 / Layer 2 / Compliance metadata / Type aliases / SSOT / Version section dividers.
- `src/argus_redact/glue/redact.py` consumes the `layers.py` SSOT constants (`LAYER_REGEX` / `LAYER_NER` / `LAYER_SEMANTIC`) instead of raw integer literals.

### Fixes

- `scripts/sync_docs_version.py` no longer requires Python 3.11 — replaced `tomllib` import with a regex on `pyproject.toml`. (v0.6.6 CI failure on py3.10.)

### Docs

- `docs/architecture-layers.md` and `docs/architecture.md` now cross-reference each other, disambiguating the three coexisting "layer" taxonomies (public Primitive/Compose/Downstream vs. internal Pure/Impure/Glue vs. detection-pipeline L1/L1b/L2/L3).
- `docs/known-issues.md` updated: compose layer status flipped from "v0.7+" to "namespace stubs since v0.6.7; helpers ship v0.6.9".

### Compatibility

- No API removals. No renames. No breaking changes.
- New importable symbols: `argus_redact.compose.{StreamingRedactor, StreamingRestorer, redact_pseudonym_llm, prompt_anchor, expand_aliases}`.

## v0.6.6 — 2026-05-31 — Reader Contract

### Security

- `RestoreRunnable` / `RestoreTransform` raise `SessionStateError` when paired
  redact runnable has no key. Previously returned text unchanged — masked
  the multi-tenant cross-session leak vector. (audit HIGH-1, HIGH-2)
- Strip dead `_current_key` ContextVar machinery from `integrations/langchain.py` —
  class docstring no longer claims thread-safe-via-contextvars.

### Docs

- README hero example switched to `张三的电话+身份证号` (was `王五在协和医院` which
  triggered detector Person+Org merge boundary). Default fast-mode behavior, no
  NER dep, three entity types. Pin-tested. (audit HIGH-3)
- `0% PII leak` headline rewritten to list actual PRvL LLMs (GPT-5 /
  Claude-Opus-4.5 / Gemini-2.5-Pro / GLM-4.5) and disclose 96%/Bronze cell.
  (audit HIGH-4)
- ai4privacy numbers regenerated on 0.6.6 baseline (fast + ner, 500 samples;
  auto mode skipped on the maintainer's host — see notes in result JSON).
  Results committed under `tests/benchmark/results/`; `docs/benchmark-report.md`
  is the single source of truth. (audit HIGH-5)

### Tooling

- New `tests/test_readme_examples.py` — every `<!-- pin -->` ```python``` block
  in README.md / README.zh.md is exec'd in CI; mismatch fails.
- New `scripts/sync_docs_version.py` + `make sync-docs-version[-check]` —
  single-source version strings across pyproject / __init__.py / README / docs;
  CI guards against drift on every PR.

### Compatibility

- New exception `argus_redact.SessionStateError(RuntimeError)`. Downstream
  callers of `RestoreRunnable` / `RestoreTransform` that relied on silent
  no-op on unset key should construct one pair per logical session, or
  catch `SessionStateError`.
- No API rename; no removed symbols.
