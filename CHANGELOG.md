# Changelog

All notable changes to argus-redact. Maintained from v0.6.6 forward. Prior releases documented in git history and `docs/known-issues.md` "Recently Fixed".

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
