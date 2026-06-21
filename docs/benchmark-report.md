# Benchmark Report

> **Currency** (per-row, mixed across two releases for v0.7.10):
> - **English sets** (`ai4privacy`, `kaggle_piilo`) were **re-run on v0.7.10** —
>   this release's detection-correctness work is **English-only** (the
>   evidence-gated person detector), so the English benchmarks are the ones that
>   can move.
> - **Chinese suite** (`pii_bench_zh`) is **carried from v0.7.9 unchanged** — it
>   was **not re-measured** for v0.7.10. v0.7.10's person work is EN-only, and the
>   container/self-reference merger fix produced **no golden change** on the
>   Chinese suite, so the v0.7.9 numbers stand as-is.
>
> Runs are on Apple M1 Max, Python 3.11. There is **no random sampling** — each
> run streams the first N rows of the dataset in deterministic order; `salt=42`
> fixes the pseudonym mapping. `auto` (LLM) mode is **skipped** on the
> maintainer's machine (qwen2.5:32b inference exceeded the 60s read timeout —
> rerun on a host with adequate memory, or use a smaller LLM like qwen2.5:7b).
>
> | Benchmark | Samples | Re-run for v0.7.10? | Reproduce | Pinned JSON |
> |---|---|---|---|---|
> | pii_bench_zh (zh, self-authored) | 1000 | No — carried from v0.7.9 | `python -m tests.benchmark pii_bench_zh --lang zh --mode fast,ner --limit 1000 --save tests/benchmark/results/pii_bench_zh_0.7.9.json` | `tests/benchmark/results/pii_bench_zh_0.7.9.json` |
> | ai4privacy (en) | 500 | Yes | `python -m tests.benchmark ai4privacy --lang en --mode fast,ner --limit 500 --save tests/benchmark/results/ai4privacy_0.7.10.json` | `tests/benchmark/results/ai4privacy_0.7.10.json` |
> | kaggle_piilo (en, real essays) | 500 | Yes | `python -m tests.benchmark kaggle_piilo --lang en --mode fast,ner --limit 500 --save tests/benchmark/results/kaggle_piilo_0.7.10.json` | `tests/benchmark/results/kaggle_piilo_0.7.10.json` |
>
> The earlier `tests/benchmark/results/ai4privacy_0.6.6.json` is retained as a
> historical baseline (it backs a schema-guard test); the report now pins the
> v0.7.10 English result files and the carried-forward v0.7.9 Chinese file above.

## Executive Summary

argus-redact combines PII detection with **reversible encryption and per-message keys**. On checksum-validated structured PII (phone, ID, email, bank card, license plate), it shows high precision and recall on the self-authored Chinese suite (100.0% on each of those types in the measured run below). On Chinese PII specifically, it is **the only bundled tool here with out-of-the-box Chinese PII support** — Presidio ships no out-of-the-box Chinese recognizer (one can be added via custom recognizers).

|  | argus-redact | Presidio |
|--|:-----------:|:--------:|
| Reversible | **Yes** (per-message key) | No (one-way; reversible only via custom operator) |
| Chinese PII out-of-the-box | **Yes** (8 types) | No (add via custom recognizers) |
| 7 languages | **Yes** | Configurable (mostly English) |
| Local / offline | **Yes** | **Yes** |
| Semantic detection | **Yes** (Layer 3 LLM) | No (add via custom recognizer) |

---

## 1. Chinese PII Detection (pii_bench_zh, 1000 samples)

**No other open-source tool benchmarks against Chinese PII.** This dataset is
**self-authored** (`wan9yu/pii-bench-zh`) — created by us to fill this gap, so
treat it as an internal coverage check, not a third-party-audited score.
Numbers below are measured on the v0.7.9 development HEAD (commit `f17ad8a`).

> **Carried from v0.7.9 — not re-measured for v0.7.10.** This release's detection
> work is English-only (the evidence-gated person detector); the
> container/self-reference merger fix produced no golden change on the Chinese
> suite. The v0.7.9 numbers below therefore stand unchanged.

### argus-redact, `mode="fast"` (regex + name scoring)

| Entity type | Precision | Recall | F1 | Notes |
|-------------|-----------|--------|-----|-------|
| email | 100.0% | 100.0% | 100.0% | |
| id_number | 100.0% | 100.0% | 100.0% | MOD 11-2 checksum validation |
| license_plate | 100.0% | 100.0% | 100.0% | |
| phone | 100.0% | 100.0% | 100.0% | |
| bank_card | 100.0% | 100.0% | 100.0% | Luhn + BIN prefix |
| passport | 100.0% | 72.9% | 84.4% | recall gap — see analysis |
| address | 71.7% | 71.7% | 71.7% | Complex multi-part matching |
| person | 91.5% | 86.5% | 88.9% | Candidate generation + evidence scoring |
| **Overall** | **94.6%** | **92.1%** | **93.3%** | |

### argus-redact, `mode="ner"` (+ HanLP)

| Entity type | Precision | Recall | F1 |
|-------------|-----------|--------|-----|
| email | 100.0% | 100.0% | 100.0% |
| id_number | 100.0% | 100.0% | 100.0% |
| license_plate | 100.0% | 100.0% | 100.0% |
| phone | 100.0% | 100.0% | 100.0% |
| bank_card | 100.0% | 100.0% | 100.0% |
| passport | 100.0% | 72.9% | 84.4% |
| address | 71.7% | 71.7% | 71.7% |
| person | 92.1% | 88.0% | 90.0% |
| **Overall** | **94.7%** | **92.6%** | **93.7%** |

_Result JSON: `tests/benchmark/results/pii_bench_zh_0.7.9.json`. `auto` (LLM)
mode skipped — see currency note._

**Presidio:** ships no out-of-the-box Chinese recognizer (one can be added via a spaCy zh model + custom recognizers), so it is not benchmarked here.

**Key takeaway:** Checksum-validated structured PII (phone, email, ID, bank
card, license plate) stays at 100% precision **and** 100% recall on this suite.
Person names are detected by candidate generation + evidence scoring (surname +
CJK sequences scored against PII proximity, context words, honorific suffixes) —
no NER model required: `fast` gets 86.5% recall at 91.5% precision, and HanLP in
`ner` mode adds only ~1.5 points of recall (88.0%) for a ~30x speed cost, so
`fast` is the recommended default.

**Honest deltas vs. the previous (v0.7.8-era, never-pinned) numbers:** these
v0.7.9 numbers are measured against the published `wan9yu/pii-bench-zh` rows and
are lower than the prior unpinned table (which claimed 98.5% person recall,
100% passport, 88.8% address, 97.4% overall F1). Those earlier figures were
never committed as a result JSON and do not reproduce against the published
dataset, so they are replaced rather than relabeled. Two real recall gaps
remain on this dataset: (1) **passport** — the suite includes single-letter +
8-digit passport numbers (e.g. `G10122691`) that the current pattern does not
fully cover (precision stays 100%, no false positives); (2) **address** —
multi-part informal address spans still under-match. These are tracked in
Limitations below.

---

## 2. English PII Detection — ai4privacy (400K dataset, 500 samples)

Re-run on v0.7.10, first 500 English rows. ai4privacy has **no person type**, and
v0.7.10's only detection change is the English person evidence-gate, so the
`fast`-mode numbers are **identical to v0.7.9** (81.6 / 31.9 / 45.8). The
`ner`-mode row moved by tenths between runs — that is **spaCy NER run jitter on
the location type**, not a v0.7.10 code effect (the `fast` path, which is what
v0.7.10 touches, is bit-identical).

### argus-redact

| Mode | Precision | Recall | F1 |
|---|---|---|---|
| fast (regex)          | 81.6% | 31.9% | 45.8% |
| ner (+ spaCy)         | 74.8% | 42.9% | 54.5% |
| auto (+ Ollama 32B)   | _skipped this run — see currency note_ | | |

_Result JSON: `tests/benchmark/results/ai4privacy_0.7.10.json`._

### Per-type breakdown (same 500-sample run)

| Entity type | Mode | Precision | Recall | F1 |
|-------------|------|-----------|--------|-----|
| email | fast | 99.6% | 99.6% | 99.6% |
| email | ner | 99.6% | 99.1% | 99.3% |
| credit_card | fast | 100.0% | 10.4% | 18.9% |
| credit_card | ner | 100.0% | 8.3% | 15.4% |
| location | fast | _100.0%_ | 0.0% | 0.0% |
| location | ner | 59.4% | 33.3% | 42.7% |
| address | fast | 0.0% | 0.0% | 0.0% |
| address | ner | 0.0% | 0.0% | 0.0% |

(`location` fast precision is 100% only because `fast` detects zero locations —
no false positives, no true positives either.)

**Analysis:** Email is essentially solved (99.6% precision/recall). Recall is
limited overall because ai4privacy uses European formats (Dutch, German, French)
that don't match the US-centric structured patterns, and the dataset's
`address`/`STREET` spans don't align with the detector's address model (0%, and
the `fast` false positives there pull precision down). The NER layer adds
location recall (0% → 33.3%) at the cost of location precision (59.4%). The
v0.7.9 Phase 2 person-detection work had already lifted both modes over the
v0.7.8-era table (fast 78.3/30.3/43.7, ner 72.8/41.4/52.8); v0.7.10 leaves the
`fast` numbers byte-identical (no person type to gate here) and the `ner` row
moves only by spaCy run jitter on the location type — no regression on this
dataset.

---

## 3. Real Student Essays — Kaggle PIILO (7K dataset, 500 samples)

This is the only benchmark with **real (non-synthetic) text**. argus-redact
numbers are re-run on v0.7.10, which is where the English person evidence-gate
shows up.

| Tool | Mode | Precision | Recall | F1 | Speed |
|------|------|-----------|--------|-----|-------|
| argus-redact | fast | 73.1% | 28.2% | 40.7% | 16 docs/s |
| argus-redact | ner | 24.6% | 45.0% | 31.8% | 2 docs/s |
| **Presidio** | — | 35.1% | 47.1% | 40.2% | 5 docs/s |

_argus-redact result JSON: `tests/benchmark/results/kaggle_piilo_0.7.10.json`.
The Presidio row was measured on an earlier run and is **not re-measured** for
v0.7.10 — keep it as a scoped historical reference, not a head-to-head on
identical code._

### Per-type breakdown (argus-redact, same 500-sample run)

| Entity type | Mode | Precision | Recall | F1 |
|-------------|------|-----------|--------|-----|
| email | fast | 100.0% | 100.0% | 100.0% |
| email | ner | 100.0% | 100.0% | 100.0% |
| person | fast | 71.6% | 29.8% | 42.1% |
| person | ner | 23.5% | 49.7% | 31.9% |
| phone | fast/ner | 33.3% | 33.3% | 33.3% |
| id_number | fast/ner | 100.0% | 0.0% | 0.0% |
| url | fast/ner | 100.0% | 0.0% | 0.0% |

**Analysis:** On this dataset, person name detection dominates (85%+ of entities
are names), so the v0.7.9 Phase 2 recall work moves the headline numbers the
most — and the tradeoff is visible in both directions:

- **`fast` recall jumped 2.9% → 29.8%** (and F1 5.6% → 41.6%) thanks to the
  unicode-aware tokenizer and grown surname pools picking up many more student
  names without an NER model.
- **`fast` precision dropped 90.0% → 68.9%.** This is a real regression to
  report plainly: broader name detection on free-form essay text adds false
  positives (person FP went up to 81 in `fast`). The net F1 still improves
  because the recall gain dominates, but the precision cost is genuine on
  noisy English prose.
- **`ner` mode** trades precision hard for recall (person precision 24.0% at
  51.6% recall) — spaCy NER over-fires on capitalized non-name tokens in essay
  text. On this dataset `fast` is the better-balanced mode despite lower recall.

Presidio's spaCy NER + regex combination still gives better overall F1 here
because it is tuned for English name detection out of the box; argus-redact's
structural strength (email 100%, phone, ID) is under-exercised because this
dataset is almost entirely names.

**The critical difference:** Presidio's detected PII is **permanently deleted**. argus-redact's detected PII is **reversibly encrypted** — the downstream LLM output can be restored to contain real names afterward. These are fundamentally different use cases.

---

## 4. Performance

### Latency

`redact(mode="fast")` p50 — Apple M-series, Python 3.11. Reproduce with
`python tests/benchmark/bench_l1_rust_vs_python.py`. The NER column is the
Layer 1+2 path and is approximate (not re-measured by the same script).

| Text size | Layer 1 (fast) | Layer 1+2 (NER) |
|-----------|-----------------|-----------------|
| Short (17 chars) | 0.03ms | ~15ms |
| Medium (770 chars) | 0.75ms | ~30ms |
| Long (10K chars) | 9.3ms | ~100ms |
| `restore()` | <0.01–0.18ms | <0.01–0.18ms |

### Throughput

`mode="fast"`, same machine/corpus as above:

| Scenario | argus-redact (fast) | Presidio |
|----------|:------------------:|:--------:|
| Short docs | ~29,000 docs/s | ~5 docs/s |
| Medium docs | ~1,330 docs/s | ~5 docs/s |

argus-redact in `fast` mode is **~1000x faster** than Presidio for regex-detectable PII, because Presidio always runs NER models even for pattern-based entities.

---

## 5. Feature Comparison

| Capability | argus-redact | Presidio | Tonic Textual | anonLLM |
|-----------|:-----------:|:--------:|:-------------:|:-------:|
| **Reversible encryption** | **Yes** | No | No | Yes (OpenAI) |
| **Per-message keys** | **Yes** | No | No | No |
| **Chinese PII** (phone, ID, card) | **Yes** | No | Limited | No |
| **7 languages** | **Yes** | Configurable | 50+ (claimed) | 1 |
| **Fully local** | **Yes** | **Yes** | No (SaaS) | No (OpenAI) |
| **Semantic detection** | **Yes** (local LLM) | No | Yes | No |
| **Two-line API** | **Yes** | No | No | Yes |
| **Structured data** (JSON/CSV) | **Yes** | No | **Yes** | No |
| **Streaming restore** | **Yes** | No | No | No |
| **MCP Server** | **Yes** | No | Yes (commercial) | No |
| Regex speed | ~29K docs/s | ~5 docs/s | N/A | N/A |
| Open source | Apache 2.0 | Apache 2.0 | Proprietary | MIT |

---

## 6. v0.5.x PRvL Baseline (pseudonym-llm profile)

**Status:** Test infrastructure landed in v0.5.4 (`tests/benchmark/test_prvl_v0_5_x.py`); LLM-driven scoring runs locally with `POE_API_KEY`. Numbers below are populated as the maintainer or contributors run the suite. Empty cells = "not yet captured for this release".

**Scenarios** (each runs against GPT-4o, Claude 3.7 Sonnet, Gemini 2.0 Flash):

| ID | Description | Probe text | Task |
|---|---|---|---|
| `zh_fast` | zh fast-mode redact, summarize | 客户王建国电话13912345678... | reference |
| `en_fast` | en fast-mode redact (v0.5.3 surname list), summarize | Call John Smith at (415) 555-1234... | reference |
| `mixed_auto` | zh+en mixed, lang="auto" translate | 客户Wang at user@company.com... | reference |
| `streaming` | 3 chunks via StreamingRedactor | 请联系王建国。/ ... | reference |

**Metrics**:
- `R_default`: PII recovered after default placeholder profile + LLM round-trip + restore (0–1)
- `R_realistic`: PII recovered after `pseudonym-llm` profile + LLM round-trip + restore (0–1)
- `U_realistic`: downstream LLM usability (LLM produced an on-task response, judged 0–1 by maintainer)
- `L_match`: language of LLM output matches input (yes/no)

**Recipe to populate** (anyone with Poe access can refresh):
```bash
POE_API_KEY=... pytest tests/benchmark/test_prvl_v0_5_x.py::TestPRvLv0_5xBaselineRun -v -s -m semantic
# Hand-score U_realistic; commit numbers to tests/benchmark/fixtures/prvl_v0_5_x_baseline.json
```

**Performance check** (v0.5.4 restore cache, **Python fallback path only**):

The `_compile_alternation` cache fires when the Rust `_core` extension is unavailable (source-only installs / unsupported platforms / CI environments without the prebuilt wheel). Production wheels load Rust by default — its scan is already fast and the compile cost is internal to the Rust crate, so the Python-side cache is a no-op there.

```
Python fallback, 1000 restore() calls on 100-entry key dict:
   pre-v0.5.4:  ~600ms (recompile alternation each call)
   v0.5.4:      <100ms (cache hit on second+ call with same key set)
```

Streaming hot path (`StreamingRestorer.feed` × N sentences) is the primary beneficiary on the Python path — its key dict is stable across the session, so cache hit rate ≈ 1.

---

## 7. When to Use What

| Scenario | Best tool | Why |
|----------|-----------|-----|
| LLM pipeline (need to restore PII after) | **argus-redact** | Only tool with reversible per-message encryption |
| Chinese text processing | **argus-redact** | Only open tool with Chinese PII coverage |
| High-throughput batch (regex PII) | **argus-redact fast** | 1000x faster than alternatives |
| English name detection only | Presidio | Better English NER out of the box |
| Compliance audit / permanent deletion | Presidio | One-way deletion is the explicit goal |
| SaaS with maximum entity coverage | Tonic Textual | 50+ languages, commercial support |

---

## 8. Limitations & Roadmap

**Current limitations (v0.7.9 measurements):**
- Chinese address detection (~72% F1 on pii_bench_zh) — multi-part informal
  address spans under-match
- Chinese passport recall (72.9%) — single-letter + 8-digit formats (e.g.
  `G10122691`) are not yet fully covered by the pattern (precision stays 100%)
- English/European address detection essentially unsupported (0% on ai4privacy
  `STREET` spans; `fast` even emits false positives there)
- Person name precision on noisy real English prose — the v0.7.9 recall work
  (unicode tokenizer + grown surname pools) raised Kaggle PIILO `fast` recall
  (2.9% → 29.8%) but dropped `fast` precision (90% → 69%); broader detection
  adds false positives on free-form essay text

**Planned improvements:**
- Add the single-letter + 8-digit Chinese passport format to the pattern set
- Recover person-name precision on noisy English (expand negative dictionary +
  scoring signals) without giving back the v0.7.9 recall gains
- Improve Chinese address patterns for informal formats
- Improve English/European address patterns
- Fine-tune name detection for Kaggle-style educational text
- Expand pii-bench-zh to 10K+ samples with more diverse templates

---

*Benchmarked with [argus-redact benchmark framework](../tests/benchmark/README.md). Reproduce: `python -m tests.benchmark [dataset] --mode fast,ner`*
