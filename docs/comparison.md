# Comparison with Other Tools

## Feature Matrix

| Feature | argus-redact | Presidio | AVA Protocol | Tonic Textual | anonLLM |
|---------|:-----------:|:--------:|:------------:|:-------------:|:-------:|
| Reversible | **Yes** (key) | Partial | Yes (vault) | No (synthesis) | Yes |
| Per-message keys | **Yes** | No | No | No | No |
| Chinese-native PII | **Yes** | No | No | Limited | No |
| Fully local | **Yes** | Yes | Yes | No (SaaS) | **No** (OpenAI) |
| Semantic detection | **Yes** (Ollama) | No | No | Yes | No |
| Two-line API | **Yes** | No | No | No | Yes |
| MCP Server | **Yes** | No | No | Yes (commercial) | No |
| 7 languages | **Yes** | Configurable | No | 50+ (claimed) | 1 |

## Why Per-Message Keys Matter

[ETH Zurich research (2026)](https://arxiv.org/abs/2602.16800) demonstrated that LLM agents can deanonymize users for $1-4/person at 67% recall / 90% precision. The attack relies on correlating pseudonymous activity across requests.

Fixed pseudonym tools (where "张三" always maps to "PERSON_1") are vulnerable. argus-redact generates a **fresh random key per call** — each request uses completely unrelated pseudonyms.

## Positioning

argus-redact is **not** a Presidio replacement. They solve different problems:

- **Presidio** detects and masks PII (one-way)
- **argus-redact** encrypts PII reversibly with per-message keys

Use both together via the [Presidio bridge](../docs/integration-frameworks.md):

```python
from argus_redact.integrations.presidio import PresidioBridge

bridge = PresidioBridge()
redacted, key = bridge.redact("John Smith called 555-123-4567", language="en")
restored = bridge.restore(llm_output, key)
```

## Benchmark: ai4privacy/pii-masking-300k

Tested on the [ai4privacy PII benchmark](https://huggingface.co/datasets/ai4privacy/pii-masking-300k) (English, 200 examples):

| Mode | Precision | Recall | F1 | Speed |
|------|-----------|--------|-----|-------|
| `fast` (regex only) | 67.2% | 13.8% | 22.9% | 84 docs/s |
| `ner` (regex + spaCy) | 41.0% | 32.8% | 36.5% | 4 docs/s |
| `auto` (regex + NER + Ollama 3B) | 45.1% | 34.8% | 39.3% | 1.0 docs/s |
| `auto` (regex + NER + Ollama 32B) | 48.5% | 34.8% | 40.5% | 0.2 docs/s |

**Email detection: P=92% R=94%**

> argus-redact is the only tool in this comparison that offers reversible PII encryption with per-message keys. Other tools achieve higher recall by permanently destroying PII.

## Full benchmark suite

We evaluate against 8 public datasets across multiple languages and PII types. See [Benchmarks](../tests/benchmark/README.md) for details.

```bash
python -m tests.benchmark all --mode fast,ner --limit 1000
```

| Dataset | Samples | Languages | Focus |
|---------|---------|-----------|-------|
| ai4privacy | 400K+ | en, de, fr, es, it, nl | General PII |
| nemotron | 100K | en | 55+ PII/PHI types |
| wikiann | 282 langs | zh, en, ja, ko, de, uk | Multilingual NER |
| gretel_finance | 56K | en, de, fr, es, it, nl, sv | Financial docs |
| conll2003 | 20K | en | Classic NER baseline |
| kaggle_piilo | 7K | en | Real student essays |
| n2c2_2014 | 1.3K | en | Clinical de-identification |
| pii_bench_zh | 5K | zh | Chinese PII (ours, first open benchmark) |
