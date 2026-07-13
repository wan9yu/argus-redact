# Benchmark Report

> **Currency:** every detection number in this report is from the **v0.7.16** run —
> all three datasets, both argus modes, and Presidio, on the same code and the same
> gold labels.
>
> Runs are on Apple M1 Max, Python 3.11. There is **no random sampling** — each
> run streams the first N rows of the dataset in deterministic order; `salt=42`
> fixes the pseudonym mapping. `auto` (LLM) mode is **skipped** on the
> maintainer's machine (qwen2.5:32b inference exceeded the 60s read timeout —
> rerun on a host with adequate memory, or use a smaller LLM like qwen2.5:7b).
>
> | Benchmark | Samples | Reproduce | Pinned JSON |
> |---|---|---|---|
> | pii_bench_zh (zh, self-authored) | 1000 | `python -m tests.benchmark pii_bench_zh --lang zh --mode fast,ner --limit 1000 --save tests/benchmark/results/pii_bench_zh_0.7.16.json` | `tests/benchmark/results/pii_bench_zh_0.7.16.json` |
> | ai4privacy (en) | 500 | `python -m tests.benchmark ai4privacy --lang en --mode fast,ner --limit 500 --save tests/benchmark/results/ai4privacy_0.7.16.json` | `tests/benchmark/results/ai4privacy_0.7.16.json` |
> | kaggle_piilo (en, real essays) | 500 | `python -m tests.benchmark kaggle_piilo --lang en --mode fast,ner --limit 500 --save tests/benchmark/results/kaggle_piilo_0.7.16.json` | `tests/benchmark/results/kaggle_piilo_0.7.16.json` |
> | Presidio, same three datasets | 500 / 500 / 1000 | `python tests/benchmark/presidio_eval.py <dataset> --limit N --save tests/benchmark/results/presidio_<dataset>_0.7.16.json` | `tests/benchmark/results/presidio_*_0.7.16.json` |
>
> The Presidio rows are measured by `tests/benchmark/presidio_eval.py`, which reuses
> the **same dataset adapters, the same gold labels and the same scoring** as the
> argus runs — only the detector changes, and Presidio runs with its **default
> out-of-the-box recognizers** (no crippling, no custom config).
>
> The earlier `tests/benchmark/results/ai4privacy_0.6.6.json` is retained as a
> historical baseline (it backs a schema-guard test); the report pins the v0.7.16
> files above.

## Executive Summary

argus-redact combines PII detection with **reversible encryption and per-message keys**. On checksum-validated structured PII (phone, ID, email, bank card, license plate), it shows high precision and recall on the self-authored Chinese suite (100.0% on each of those types in the measured run below). Chinese is where its out-of-the-box detection leads: Presidio ships no Chinese NLP engine or recognizer, so out of the box it reaches 27.9 F1 on that suite against argus's 93.3 (`fast`) — a gap a Presidio user can close with a spaCy zh model and custom recognizers (§1).

**On English, the honest result is the reverse:** Presidio's out-of-the-box recognizers beat argus on both English datasets in this report (ai4privacy 61.1 F1 vs 54.5; Kaggle PIILO 43.2 F1 vs 40.7). argus's case for an LLM pipeline rests on the reversible, per-message-keyed round-trip and Chinese coverage — not on English detection breadth.

|  | argus-redact | Presidio |
|--|:-----------:|:--------:|
| Reversible | **Yes** (per-message key) | No (one-way; reversible only via custom operator) |
| Chinese PII out-of-the-box | **Yes** (8 types) | No (add via custom recognizers) |
| 7 languages | **Yes** | Configurable (mostly English) |
| Local / offline | **Yes** | **Yes** |
| Semantic detection | **Yes** (Layer 3 LLM) | No (add via custom recognizer) |

**Benchmark coverage is `zh` + `en` only.** The other six packs
(`de`, `uk`, `br`, `in`, `ja`, `ko`) ship L1 patterns and NER adapters but have
**no measured recall** in this report — they are best-effort and reach them via
an explicit `lang="…"` (they are not auto-selected under `lang="auto"`; see
[language-packs.md](language-packs.md#benchmark-status)). The "7 languages" row
above is a coverage claim, not a benchmarked-recall claim.

---

## 1. Chinese PII Detection (pii_bench_zh, 1000 samples)

This dataset is **self-authored** (`wan9yu/pii-bench-zh`) — created by us to fill a
gap (no widely-used open Chinese PII benchmark existed), so the scores below —
argus **93.3 F1 (`fast`) / 93.7 F1 (`ner`)** — are from a **self-authored**
benchmark: treat them as an internal coverage check, not a third-party-audited
score. Measured on the v0.7.16 run.

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

_Result JSON: `tests/benchmark/results/pii_bench_zh_0.7.16.json`. `auto` (LLM)
mode skipped — see currency note._

### Presidio on the same 1000 samples

| Tool | Precision | Recall | F1 |
|------|-----------|--------|-----|
| Presidio (out-of-the-box) | 71.8% | 17.3% | 27.9% |

_Result JSON: `tests/benchmark/results/presidio_pii_bench_zh_0.7.16.json`._

**Read this row carefully — it is not "Presidio is bad at Chinese".** Presidio
ships **no out-of-the-box Chinese NLP engine or recognizer**, so this run analyzes
Chinese text with Presidio's **English** engine (`en_core_web_lg`). Only its
*language-agnostic* recognizers fire — phone (90.5% P / 51.3% R) and email —
while its spaCy NER contributes nothing, hence person recall 0% and the low
overall recall. What this row measures is exactly the **out-of-the-box** gap: a
Presidio user who wires up a spaCy zh model plus custom zh recognizers would score
substantially higher, and Presidio is a toolkit designed for precisely that. It is
not a claim that Presidio *cannot* do Chinese.

**Key takeaway:** Checksum-validated structured PII (phone, email, ID, bank
card, license plate) stays at 100% precision **and** 100% recall on this suite.
Person names are detected by candidate generation + evidence scoring (surname +
CJK sequences scored against PII proximity, context words, honorific suffixes) —
no NER model required: `fast` gets 86.5% recall at 91.5% precision, and HanLP in
`ner` mode adds only ~1.5 points of recall (88.0%) for a ~30x speed cost, so
`fast` is the recommended default.

**Honest deltas vs. the previous (v0.7.8-era, never-pinned) numbers:** the
numbers above are measured against the published `wan9yu/pii-bench-zh` rows and
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

Measured on the v0.7.16 run, first 500 English rows. ai4privacy has **no person
type** — the labelled types here are `email`, `credit_card`, `location` and
`address`.

### argus-redact vs. Presidio (same 500 samples, same gold, same scoring)

| Tool / mode | Precision | Recall | F1 |
|---|---|---|---|
| argus fast (regex)          | 81.6% | 31.9% | 45.8% |
| argus ner (+ spaCy)         | 74.8% | 42.9% | 54.5% |
| argus auto (+ Ollama 32B)   | _skipped this run — see currency note_ | | |
| **Presidio** (out-of-the-box) | **80.9%** | **49.1%** | **61.1%** |

**Presidio wins this dataset.** Its 61.1 F1 beats argus's best mode (54.5) on both
recall (49.1% vs 42.9%) and F1, and it matches argus on precision. We state that
up front rather than bury it: on English free text, Presidio's out-of-the-box
recognizer fleet is stronger than argus's detection layers.

_argus result JSON: `tests/benchmark/results/ai4privacy_0.7.16.json`. Presidio
result JSON: `tests/benchmark/results/presidio_ai4privacy_0.7.16.json`._

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

**Analysis:** Email is essentially solved (99.6% precision/recall; Presidio gets
100/100). Recall is limited overall because ai4privacy uses European formats
(Dutch, German, French) that don't match the US-centric structured patterns, and
the dataset's `address`/`STREET` spans don't align with the detector's address
model (0%, and the `fast` false positives there pull precision down). The NER
layer adds location recall (0% → 33.3%) at the cost of location precision
(59.4%).

**Where Presidio's lead comes from:** almost entirely the `location` type — 50.0%
recall at 60.0% precision (F1 54.5) against argus `ner`'s 33.3% / 59.4% (F1 42.7).
On the other types the two are close or tied: email 100/100 (Presidio) vs
99.6/99.6 (argus `fast`), credit card 12.5% recall (Presidio, at 75.0% precision)
vs 10.4% (argus `fast`, at 100% precision), and **both tools score 0% recall on
the `address`/`STREET` spans** — that gap is not argus-specific.

---

## 3. Real Student Essays — Kaggle PIILO (7K dataset, 500 samples)

This is the only benchmark with **real (non-synthetic) text**. All rows below are
from the v0.7.16 run.

| Tool | Mode | Precision | Recall | F1 |
|------|------|-----------|--------|-----|
| argus-redact | fast | 73.1% | 28.2% | 40.7% |
| argus-redact | ner | 27.4% | 45.0% | 34.1% |
| **Presidio** | out-of-the-box | **36.7%** | **52.6%** | **43.2%** |

_argus-redact result JSON: `tests/benchmark/results/kaggle_piilo_0.7.16.json`.
Presidio result JSON: `tests/benchmark/results/presidio_kaggle_piilo_0.7.16.json`
— same 500 samples, same gold, same scoring, only the detector changes._

**Presidio wins this dataset too** (43.2 F1 vs argus's best 40.7). This benchmark
is ~85% person names, which is Presidio's strongest out-of-the-box axis.

### Per-type breakdown (argus-redact, same 500-sample run)

| Entity type | Mode | Precision | Recall | F1 |
|-------------|------|-----------|--------|-----|
| email | fast | 100.0% | 100.0% | 100.0% |
| email | ner | 100.0% | 100.0% | 100.0% |
| person | fast | 71.6% | 29.8% | 42.1% |
| person | ner | 26.2% | 49.7% | 34.3% |
| phone | fast/ner | 33.3% | 33.3% | 33.3% |
| id_number | fast/ner | 100.0% | 0.0% | 0.0% |
| url | fast/ner | 100.0% | 0.0% | 0.0% |

**Analysis:** On this dataset person-name detection dominates (85%+ of entities
are names), so the person row *is* the headline, and the precision/recall tradeoff
between the two argus modes is stark:

- **`fast` is the precision mode**: person 71.6% precision at 29.8% recall (62 FP
  against 156 TP). Overall `fast` precision is **73.1%** — the structured types
  it does fire on are reliable (email 100/100).
- **`ner` is the recall mode, and it pays for it**: person recall rises to 49.7%,
  but precision collapses to 26.2% (734 FP against 260 TP) — spaCy NER over-fires
  on capitalized non-name tokens in essay prose. Overall `ner` precision is
  **27.4%**, and the recall gain does not pay for it: overall F1 is **34.1**,
  *below* `fast`'s **40.7**. On this dataset **`fast` is the better mode** despite
  detecting fewer names.
- **Presidio lands between the two and ahead of both on F1** (36.7% precision /
  52.6% recall / 43.2 F1; its person row is 33.8 / 52.4 / 41.1). It is tuned for
  English name detection out of the box, and it also picks up the dataset's `url`
  spans (86.1% recall) that argus does not detect at all (0%).

argus-redact's structural strength (email 100/100, checksum-validated IDs) is
under-exercised here because this dataset is almost entirely names. Both tools
score 0% recall on the dataset's `id_number` spans.

**The critical difference:** Presidio's detected PII is **permanently deleted**. argus-redact's detected PII is **reversibly encrypted** — the downstream LLM output can be restored to contain real names afterward. These are fundamentally different use cases.

---

## 4. Performance

### Latency and throughput (`mode="fast"`)

Apple M1 Max, Python 3.11, 500 iterations per workload. Reproduce:

```bash
python tests/benchmark/perf_profile.py --output tests/benchmark/results/perf_profile_0.7.16.json
```

Result JSON: `tests/benchmark/results/perf_profile_0.7.16.json` (full percentile
distribution per workload). A Layer-1 Rust-vs-Python component breakdown is in
`tests/benchmark/results/bench_l1_0.7.16.txt`
(`python tests/benchmark/bench_l1_rust_vs_python.py`).

| Workload | Doc size | `redact(mode="fast")` p50 | p99 | Throughput |
|---|---|---|---|---|
| en, short | 141 B | 0.22 ms | 0.35 ms | ~4,500 docs/s |
| en, ~1 KB | 846 B | 0.97 ms | 1.21 ms | ~1,030 docs/s |
| en, long | 8.5 KB | 9.4 ms | 9.97 ms | ~106 docs/s |
| zh, short | 175 B | 0.34 ms | 0.40 ms | ~2,940 docs/s |
| zh, ~1 KB | 1.4 KB | 2.03 ms | 2.44 ms | ~490 docs/s |
| zh, long | 14 KB | 20.3 ms | 24.5 ms | ~49 docs/s |

Throughput is single-threaded and scales inversely with document size — quote it
with the workload attached, never as a bare headline number.

**These are Layer-1 (`fast`) numbers only.** We do **not** publish `ner`
(Layer 1+2) or `auto` (Layer 3) latency figures: no committed harness measures
them, so any number here would be an estimate, and the NER/LLM cost is dominated
by the model and host you pick, not by argus.

**On "argus is faster than Presidio":** we have **not committed a like-for-like
Presidio timing run**, so this report publishes **no speed multiplier** against
Presidio. The *architectural* reason to expect argus's `fast` mode to be cheaper
for regex-detectable PII is real and stateable without a number: argus's Layer 1
is regex + validators (no model loaded), whereas Presidio's default pipeline runs
its spaCy NER model over every document even for purely pattern-based entities.
How large that gap is on your hardware and your documents is a measurement nobody
here has committed — treat any specific ratio as unsubstantiated until it is.

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
| Open source | Apache 2.0 | Apache 2.0 | Proprietary | MIT |

(No cross-tool speed row: we have not committed a like-for-like timing run for the
other tools. argus's own `fast`-mode latency/throughput is in §4.)

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
| High-throughput batch (regex PII) | **argus-redact fast** | Regex + validators, no NER model in the hot path (§4: 0.22 ms p50 on a 141 B doc) |
| English name detection only | Presidio | Better English NER out of the box — and it measures that way here (§2, §3) |
| Compliance audit / permanent deletion | Presidio | One-way deletion is the explicit goal |
| SaaS with maximum entity coverage | Tonic Textual | 50+ languages, commercial support |

---

## Re-identification risk (PRvL+ X axis)

Can an LLM re-identify a redacted subject from residual quasi-identifiers + a known
candidate pool? Closed-world synthetic set (N=24 clustered personas with overlapping
quasi-identifiers), `python -m tests.benchmark.reid_eval` (snapshot:
`tests/benchmark/results/reidentification_0.7.12.json`). **Lower = better.**

| Model | raw (upper bound) | argus `fast` (prior) | argus `fast` (with condition + hobby detection) |
|-------|:-----------------:|:--------------------:|:-----------------------------------------------:|
| deepseek-chat | 100% | 83.3% | **79.2%** |
| qwen-plus | 100% | 91.7% | **79.2%** |
| deepseek-chat (via OpenRouter) | 100% | 79.2% | **79.2%** |

**What moved it:** this version added evidence-gated zh **medical-condition/allergy**
and **hobby** detection (+ a region parent-city recall fix), all feeding the default
`remove` path. They lowered residual re-id from 83.3% / 91.7% to **79.2% across all
three models**. The effect is **complementary by provider**: condition removal helped
DeepSeek (−1 persona, Qwen unchanged); hobby removal helped Qwen (−3 personas, DeepSeek
unchanged). Different models re-identify via different residual signals, so detection
*breadth* helps across models even when any single detector is provider-specific.
(Single `temperature=0` runs on N=24 carry ±1–2 persona noise — directional, not exact.)

**Read this honestly:** even after removing name / phone / ID / age / employer /
job-title / **condition** / **hobby** / bare-region, the subject is **still
re-identifiable ~79% of the time** on this set. *Removing explicit PII (and these
quasi-identifiers) is not anonymization.* The residual is the **combination** of what
remains (gender, masked-value fragments such as the visible `139****5678` phone digits
under the default `mask`, and the closely-clustered persona structure), not any single
field — which is also why coarsening one field (the explored-and-removed `generalize`
experiment, see
[why coarsening one field didn't help](design-quasi-identifier-generalization.md))
did not help: removal is at least as good. A **directional indicator on a small
closed-world synthetic set, per model — not a real-world guarantee.** The
re-identification tooling here is eval/defensive only. A separate research spike
([streaming cross-turn linkage](design-streaming-cross-turn-linkage.md)) explores the
multi-turn case.

---

## 8. Limitations & Roadmap

**Current limitations (v0.7.16 measurements):**
- Chinese address detection (~72% F1 on pii_bench_zh) — multi-part informal
  address spans under-match
- Chinese passport recall (72.9%) — single-letter + 8-digit formats (e.g.
  `G10122691`) are not yet fully covered by the pattern (precision stays 100%)
- English/European address detection essentially unsupported (0% on ai4privacy
  `STREET` spans; `fast` even emits false positives there — though Presidio also
  scores 0% recall on those spans)
- English person-name detection is the weakest axis, in both directions: on Kaggle
  PIILO `fast` reaches only 29.8% person recall (at 71.6% precision), while `ner`
  buys recall (49.7%) at a precision collapse (26.2%). Presidio out-of-the-box
  beats argus on F1 on both English datasets in this report

**Planned improvements:**
- Add the single-letter + 8-digit Chinese passport format to the pattern set
- Recover person-name precision on noisy English (expand negative dictionary +
  scoring signals) without giving back recall
- Improve Chinese address patterns for informal formats
- Improve English/European address patterns
- Fine-tune name detection for Kaggle-style educational text
- Expand pii-bench-zh to 10K+ samples with more diverse templates

---

*Benchmarked with [argus-redact benchmark framework](../tests/benchmark/README.md). Reproduce: `python -m tests.benchmark [dataset] --mode fast,ner`*
