# Benchmark Report

> **Environment:** Apple M1 Max, Python 3.11, argus-redact v0.4.8, Presidio 2.2.362, spaCy 3.8 (en_core_web_sm)
>
> **Date:** 2026-03-26

## Executive Summary

argus-redact is the only tool that combines PII detection with **reversible encryption and per-message keys**. On structured PII (phone, ID, email, bank card), it achieves near-perfect precision. On Chinese PII specifically, it is **the only viable open-source option** — Presidio has no Chinese support.

|  | argus-redact | Presidio |
|--|:-----------:|:--------:|
| Reversible | **Yes** (per-message key) | No (one-way) |
| Chinese PII | **Yes** (8 types) | No |
| 7 languages | **Yes** | Configurable (mostly English) |
| Local / offline | **Yes** | **Yes** |
| Semantic detection | **Yes** (Layer 3 LLM) | No |

---

## 1. Chinese PII Detection (pii_bench_zh, 1000 samples)

**No other open-source tool benchmarks against Chinese PII.** This dataset was created by us to fill this gap.

### argus-redact (regex + name scoring, `mode="fast"`)

| Entity type | Precision | Recall | F1 | Notes |
|-------------|-----------|--------|-----|-------|
| email | 100.0% | 100.0% | 100.0% | |
| id_number | 100.0% | 100.0% | 100.0% | MOD 11-2 checksum validation |
| license_plate | 100.0% | 100.0% | 100.0% | |
| passport | 100.0% | 100.0% | 100.0% | |
| phone | 100.0% | 100.0% | 100.0% | |
| bank_card | 100.0% | 100.0% | 100.0% | Luhn + BIN prefix |
| address | 88.8% | 88.8% | 88.8% | Complex multi-part matching |
| person | 92.9% | 98.5% | 95.6% | Candidate generation + evidence scoring |
| **Overall** | **96.5%** | **98.5%** | **97.4%** | |

**Presidio:** Not applicable — no Chinese language support.

**Key takeaway:** Person name detection uses a candidate generation + evidence scoring approach: surname + CJK sequences are scored against PII proximity, context words, and honorific suffixes. This achieves 98.5% recall without any NER model — a leap from the prior 49% recall with simple context-prefix heuristics.

---

## 2. English PII Detection — ai4privacy (400K dataset, 500 samples)

### argus-redact

| Mode | Precision | Recall | F1 | Speed |
|------|-----------|--------|-----|-------|
| `fast` (regex) | 78.3% | 30.3% | 43.7% | 57 docs/s |
| `ner` (regex + spaCy) | 77.4% | 46.1% | 57.7% | 3 docs/s |

### Per-type breakdown (ner mode, 200 samples)

| Entity type | Precision | Recall | F1 |
|-------------|-----------|--------|-----|
| email | 95.4% | 93.7% | 94.5% |
| credit_card | 100.0% | 10.5% | 19.0% |
| location | 64.2% | 34.7% | 45.0% |
| address | 0.0% | 0.0% | 0.0% |

**Analysis:** High precision across the board. Recall is limited because ai4privacy uses European formats (Dutch, German, French) that don't match US-centric regex patterns. The NER layer adds +16% recall for location entities.

---

## 3. Real Student Essays — Kaggle PIILO (7K dataset, 500 samples)

This is the only benchmark with **real (non-synthetic) text**.

| Tool | Mode | Precision | Recall | F1 | Speed |
|------|------|-----------|--------|-----|-------|
| argus-redact | fast | 90.0% | 2.9% | 5.6% | 35 docs/s |
| argus-redact | ner | 20.8% | 40.5% | 27.5% | 2 docs/s |
| **Presidio** | — | 35.1% | 47.1% | 40.2% | 5 docs/s |

### Per-type breakdown (argus-redact ner, 200 samples)

| Entity type | Precision | Recall | F1 |
|-------------|-----------|--------|-----|
| email | 100.0% | 100.0% | 100.0% |
| person | 19.5% | 43.0% | 26.9% |
| id_number | 100.0% | 0.0% | 0.0% |
| url | 100.0% | 0.0% | 0.0% |

**Analysis:** On this dataset, person name detection dominates (85%+ of entities are names). Presidio's spaCy NER + regex combination gives better overall F1 because it's optimized for English name detection. argus-redact's strength is in structured PII (email: 100%, phone, ID) — but this dataset has very few of those.

**The critical difference:** Presidio's detected PII is **permanently deleted**. argus-redact's detected PII is **reversibly encrypted** — the downstream LLM output can be restored to contain real names afterward. These are fundamentally different use cases.

---

## 4. Performance

### Latency (M1 Max)

| Text size | Layer 1 (regex) | Layer 1+2 (NER) |
|-----------|-----------------|-----------------|
| Short (17 chars) | 0.06ms | ~15ms |
| Medium (770 chars) | 0.36ms | ~30ms |
| Long (10K chars) | 4.84ms | ~100ms |
| `restore()` | 0.01ms | 0.01ms |

### Throughput

| Scenario | argus-redact (fast) | Presidio |
|----------|:------------------:|:--------:|
| Short docs | 36,353 docs/s | ~5 docs/s |
| Medium docs | 2,802 docs/s | ~5 docs/s |

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
| Regex speed | 36K docs/s | ~5 docs/s | N/A | N/A |
| Open source | MIT | Apache 2.0 | Proprietary | MIT |

---

## 6. When to Use What

| Scenario | Best tool | Why |
|----------|-----------|-----|
| LLM pipeline (need to restore PII after) | **argus-redact** | Only tool with reversible per-message encryption |
| Chinese text processing | **argus-redact** | Only open tool with Chinese PII coverage |
| High-throughput batch (regex PII) | **argus-redact fast** | 1000x faster than alternatives |
| English name detection only | Presidio | Better English NER out of the box |
| Compliance audit / permanent deletion | Presidio | One-way deletion is the explicit goal |
| SaaS with maximum entity coverage | Tonic Textual | 50+ languages, commercial support |

---

## 7. Limitations & Roadmap

**Current limitations:**
- Chinese address detection (~89% F1) — complex multi-part matching has room to improve
- English address detection needs improvement
- HanLP (Chinese NER) requires upgrade for current environment
- Person name false positives (~7%) — negative dictionary coverage can be expanded

**Planned improvements:**
- Expand negative dictionary and scoring signals for person name precision
- Improve Chinese address patterns for informal formats
- Improve English/European address patterns
- Fine-tune name detection for Kaggle-style educational text
- Expand pii-bench-zh to 10K+ samples with more diverse templates

---

*Benchmarked with [argus-redact benchmark framework](../tests/benchmark/README.md). Reproduce: `python -m tests.benchmark [dataset] --mode fast,ner`*
