# Comparison with Other Tools

## Feature Matrix

| Feature | argus-redact | Presidio | AVA Protocol | Tonic Textual | anonLLM |
|---------|:-----------:|:--------:|:------------:|:-------------:|:-------:|
| Reversible | Yes (per-call key) | Yes via custom operator | Yes (vault) | No (synthesis) | Yes |
| Per-message keys (default) | **Yes** | Custom code | No (account-scoped vault) | No | No |
| Chinese-native PII out-of-the-box | **Yes** (HanLP + native validators) | Add via spaCy zh model + custom recognizers | No | Limited | No |
| Fully local | Yes | Yes | Yes | No (SaaS) | No (calls OpenAI) |
| Semantic / LLM-assisted detection | Yes (local Ollama — implicit PII) | Yes (built-in transformer/GLiNER; LLM detection path expanding) | No | Yes | No |
| Two-line `redact / restore` API | Yes | Multi-step (analyze → anonymize → custom restore) | No | No | Yes |
| MCP Server | Yes (built-in) | No (community) | No | Commercial only | No |
| Multi-language | 8 (built-in) | Many via spaCy/Stanza recognizers (configurable) | Limited | 50+ (claimed) | 1 |

**Reading this table:** Presidio is a *toolkit* — most "No" cells against Presidio above mean *"not in the box"*, not *"impossible"*. With custom recognizers and a vault, Presidio can do most of what's listed here. We compare *out-of-the-box behavior for an LLM-pipeline use case* — that's the workload argus-redact is shaped for. If your team already runs a Presidio recognizer fleet, the [Presidio bridge](../docs/integration-frameworks.md) lets you keep it.

Presidio is also **actively expanding** — recent releases add more country recognizers, transformer-based detection (GLiNER via ONNX, run locally), and an emerging LLM-based detection path. So the durable distinction is **not** any single detection capability (those converge); it's the *combination* argus-redact defaults to: **reversible** substitution with **per-message keys**, **native Chinese** out of the box, and a **local semantic tier** for *implicit* PII (symptoms → diagnosis) rather than entity recognition alone.

## Why Per-Message Keys Matter

[ETH Zurich research (2026)](https://arxiv.org/abs/2602.16800) demonstrated that LLM agents can deanonymize users for $1-4/person at 67% recall / 90% precision. The attack relies on correlating pseudonymous activity across requests.

Fixed pseudonym tools (where "张三" always maps to "PERSON_1") are vulnerable. argus-redact generates a **fresh random key per call** — each request uses completely unrelated pseudonyms.

## Positioning

argus-redact is **not** a Presidio replacement. They solve different problems:

- **Presidio** detects and masks PII (one-way)
- **argus-redact** encrypts PII reversibly with per-message keys

The core approach — replacing PII with **realistic, same-type** values using
**on-premise** models so a downstream LLM keeps its reasoning — is independently
articulated in *Anonymous-by-Construction* ([arXiv:2603.17217](https://arxiv.org/abs/2603.17217)),
which formalizes local LLM redaction via type-consistent fakes. We read it as
convergent external validation of the "encrypt PII, not meaning, locally" thesis;
argus-redact adds **reversibility + per-message keys** on top, so the substitution
round-trips back to the original instead of being a one-way synthesis.

Use both together via the [Presidio bridge](../docs/integration-frameworks.md):

```python
from argus_redact.integrations.presidio import PresidioBridge

bridge = PresidioBridge()
redacted, key = bridge.redact("John Smith called 555-123-4567", language="en")
restored = bridge.restore(llm_output, key)
```

## Benchmark: ai4privacy/pii-masking-400k

Tested on the [ai4privacy PII benchmark](https://huggingface.co/datasets/ai4privacy/pii-masking-400k) (English, first 500 samples, deterministic order, `salt=42`), measured on the v0.7.9 development HEAD:

| Mode | Precision | Recall | F1 |
|------|-----------|--------|-----|
| `fast` (regex only) | 81.6% | 31.9% | 45.8% |
| `ner` (regex + spaCy) | 74.9% | 42.8% | 54.4% |
| `auto` (regex + NER + Ollama) | _skipped this run — see benchmark report_ | | |

**Email detection (`fast`): P=99.6% R=99.6%**

_Numbers match `tests/benchmark/results/ai4privacy_0.7.9.json`. See the
[full benchmark report](benchmark-report.md) for the per-type breakdown and the
`auto`-mode skip note._

> argus-redact is the only tool in this comparison that offers reversible PII encryption with per-message keys. Other tools achieve higher recall by permanently destroying PII.

## Full benchmark suite

We evaluate against 9 public datasets across multiple languages and PII types. See [Benchmarks](../tests/benchmark/README.md) for details.

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
| pii_bench_zh_chat | 3K | zh | Chinese chat noise stress test (ours) |
