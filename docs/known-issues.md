# Known Issues

> **v0.5.x zero-debt milestone**: as of v0.5.8 there are no open Unresolved entries.
> All remaining items are explicit **Design Constraints** — permanent trade-offs
> documented for transparency, not a backlog. New defects discovered post-v0.5.8
> will reappear in an `## Unresolved` section above.

## Design Constraints

Each entry follows three lines:

- **What** — one-sentence description of the constraint.
- **Why we won't fix** — the design / external trade-off it reflects.
- **What you should do** — caller-side mitigation.

### `199-99` mobile sub-segment requires annual review

- **What**: The realistic-mode `199-99-XXXXXX` mobile range relies on this
  sub-segment remaining unassigned by 工信部 (MIIT). Numbering plans are revised
  periodically.
- **Why we won't fix**: External regulatory authority controls this allocation.
  argus-redact cannot anticipate when (or whether) it will be assigned.
- **What you should do**: Re-verify against MIIT public allocations annually.
  If the sub-segment gets assigned, switch to a different unassigned sub-segment
  via configuration (the choice is a single constant in
  `specs/fakers_zh_reserved.py`).

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

## Recently Fixed

| Issue | Version | Fix |
|-------|---------|-----|
| HK / TW / Macau / Taiwan ARC ID types not covered | v0.5.10 | Four new PII types registered: `hk_id`, `tw_id`, `macau_id`, `taiwan_arc`. HKID + TWID have full check-digit validators; Macau and Taiwan ARC are format-only. The `Out of scope (v0.5.x)` section has been removed from this file and from the auto-generated `docs/pii-types.md` catalog. |
| `assess_risk` PIPL/GDPR/HIPAA inference hardcoded | v0.5.9 | Compliance metadata moved to `PIITypeDef.pipl_articles` / `gdpr_special_category` / `hipaa_phi_category` fields. Rules centralized in `specs/_compliance.py`; downstream DPIA generators read via `specs.get(lang, name)` without mirroring rules. |
| No public way to ask "is this strategy reversible?" | v0.5.9 | New `is_strategy_reversible(strategy)` public helper + `PIITypeDef.is_reversible` derived property. |
| L1/L1b/L2/L3 layer naming had no SSOT | v0.5.9 | New `argus_redact.layers` module exposes `LAYER_REGEX` / `LAYER_NER` / `LAYER_SEMANTIC` / `LAYER_NAMES`. Downstream docs import rather than coining their own. |
| No machine-readable PII type catalog | v0.5.9 | `docs/pii-types.md` auto-generated from registry via `make catalog`; CI drift check fails when out of sync. |
| L1b ±20 char window + 50/150 PII proximity tiers undocumented | v0.5.9 | `docs/architecture.md` documents both distance mechanisms; `tests/detection/lang/test_zh_person.py` adds 4 lockdown tests. |
| Default `remove` strategy output mistaken for `[label]` literal | v0.5.9 | README + configuration.md + getting-started.md show actual `ID-NNNNN` form prominently with explicit ⚠️ callouts. |
| Cross-language LLM rewrites not auto-restored | v0.5.8 | New `KeyEntry` dataclass with `aliases`. Person fakers (zh + en) emit pinyin / Chinese-transliteration aliases. `restore()` accepts `result.key_entries` and matches both canonical fake and aliases back to the original. |
| `StreamingRedactor` default mode required complete logical-unit chunks | v0.5.8 | `incremental=True` is now the default — sentence-bounded buffering handles cross-chunk entities transparently. `incremental=False` opt-out emitted `DeprecationWarning` in v0.5.8 and was removed in v0.6.0. |
| Windows CI test fixture encoding | v0.5.8 hotfix | `tests/conftest.py:load_examples`, `tests/safety/test_*.py` JSON loaders, and CLI `read_text/write_text` test helpers all pin `encoding="utf-8"` for cross-platform compat. |
| zh fast-mode over-redacts pronouns / 3-char co-occurrences (issue #12) | v0.5.7 | (a) `self_reference` now defaults to new `keep` strategy — pronouns / kinship phrases preserved verbatim, never become `P-NNN`. (b) zh person candidate generator propagates `not_names.txt` blocks to 3-char extensions, blocking false positives like `任何评`. |
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
