# Changelog

All notable changes to argus-redact. Maintained from v0.6.6 forward. Prior releases documented in git history and `docs/known-issues.md` "Recently Fixed".

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
