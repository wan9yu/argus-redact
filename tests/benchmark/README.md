# argus-redact Benchmarks

Evaluate argus-redact against public PII datasets. Measure precision, recall, F1 per entity type.

## Why this matters

Most PII tools only benchmark against English regex patterns. We evaluate across **three dimensions**:

1. **Multi-layer detection** — regex alone misses names, addresses, and context-dependent PII. We measure how each layer (regex → NER → semantic) adds recall without sacrificing precision.
2. **Multilingual coverage** — 7 languages, each with locale-specific PII formats. WikiANN covers all of them; most other tools only benchmark English.
3. **Reversibility** — unique to argus-redact. Other tools delete PII permanently. We measure whether every detected entity can be perfectly restored from the key, which no other benchmark considers.

## Datasets

| Dataset | Samples | Languages | PII types | Focus |
|---------|---------|-----------|-----------|-------|
| **ai4privacy** | 400K+ | en, de, fr, es, it, nl | email, phone, SSN, ID, passport, credit card | General PII, largest open dataset |
| **nemotron** | 100K | en | 55+ types (names, SSN, medical, financial) | Highest quality, broadest type coverage |
| **wikiann** | 282 langs | zh, en, ja, ko, de, uk + more | PER, ORG, LOC | Multilingual NER, covers all our languages |
| **gretel_finance** | 56K | en, de, fr, es, it, nl, sv | names, addresses, financial IDs | Realistic financial documents |
| **conll2003** | 20K | en | PER, ORG, LOC, MISC | Classic NER baseline |
| **kaggle_piilo** | 7K | en | names, email, phone, address, ID, URL | Real student essays (not synthetic) |
| **n2c2_2014** | 1.3K | en | 25 PHI subtypes (names, dates, IDs, locations) | Clinical de-identification gold standard |

## Quick start

```bash
pip install datasets  # one-time dependency

# List available datasets
python -m tests.benchmark list

# Run a single dataset
python -m tests.benchmark ai4privacy --lang en --mode fast --limit 500

# Compare regex vs NER
python -m tests.benchmark ai4privacy --mode fast,ner --limit 200

# Run all datasets
python -m tests.benchmark all --mode fast --limit 1000

# Save results as JSON snapshots
python -m tests.benchmark nemotron --mode fast --limit 1000 --save

# Via build.sh
./build.sh bench en 500
```

## Architecture

```
tests/benchmark/
├── README.md
├── __main__.py              # CLI: python -m tests.benchmark
├── model.py                 # Sample, Entity, Result, TypeMetrics
├── evaluator.py             # Unified evaluation engine
├── report.py                # Terminal table + JSON snapshots
├── adapters/
│   ├── base.py              # DatasetAdapter ABC
│   ├── ai4privacy.py        # ai4privacy/pii-masking-300k
│   ├── nemotron.py          # nvidia/Nemotron-PII
│   ├── wikiann.py           # unimelb-nlp/wikiann (PAN-X)
│   ├── gretel_finance.py    # gretelai/synthetic_pii_finance_multilingual
│   └── conll2003.py         # eriktks/conll2003
├── data/                    # Cached downloads (.gitignore'd)
├── results/                 # JSON result snapshots (git-tracked)
├── test_benchmark.py        # Hand-labeled zh/en precision/recall
├── test_ai4privacy.py       # Regex-only ai4privacy evaluation
├── test_ai4privacy_full.py  # Three-layer comparison
├── test_prvl.py             # PRvL three-axis benchmark
├── test_performance.py      # Latency and throughput
└── test_concurrency.py      # Thread-safe concurrent redaction
```

### Adding a new dataset

Write one file in `adapters/`, implement `load()` → `Iterator[Sample]`, add `@register`:

```python
from . import register
from .base import DatasetAdapter

@register
class MyAdapter(DatasetAdapter):
    name = "my_dataset"
    url = "https://huggingface.co/datasets/org/my_dataset"
    languages = ["en", "zh"]

    def load(self, *, lang=None, limit=1000):
        from datasets import load_dataset
        ds = load_dataset("org/my_dataset", split="test", streaming=True)
        for ex in ds:
            # normalize to Sample(text, lang, entities=[Entity(text, type)])
            yield sample
```

Then import it in `adapters/__init__.py`. Done — CLI, evaluator, and reports all work automatically.

## Matching strategies

- **value** (default) — compare `(entity_text, entity_type)` sets. Good for regex evaluation.
- **span** — compare `(start, end, type)` with character tolerance. Better for NER evaluation where boundaries may differ slightly.

```bash
python -m tests.benchmark wikiann --match span --lang zh --limit 500
```

## Our approach: three-layer evaluation

Unlike tools that only report overall F1, we break down results by **layer contribution**:

```
Layer 1 (regex):    phone ✓  email ✓  SSN ✓  ID ✓  — high precision, limited scope
Layer 2 (NER):      person ✓  location ✓  org ✓   — adds name coverage
Layer 3 (semantic): context-dependent PII            — catches what patterns miss
```

Running `--mode fast` measures Layer 1 only. Running `--mode ner` measures Layers 1+2. The delta between them shows exactly what NER adds. This per-layer breakdown helps us focus improvement efforts where they matter most.

## Existing benchmark tests

Besides the dataset framework above, `tests/benchmark/` contains targeted benchmark tests:

| Test file | What it measures |
|-----------|-----------------|
| `test_benchmark.py` | Precision/recall against hand-labeled zh/en fixtures |
| `test_ai4privacy.py` | Regex-only evaluation on ai4privacy (streaming, 1K samples) |
| `test_ai4privacy_full.py` | Three-layer comparison (fast vs ner vs auto) on ai4privacy |
| `test_prvl.py` | PRvL three-axis score: Privacy, Reversibility, Language preservation |
| `test_performance.py` | Latency and throughput (short/medium/long text, batch, multi-lang) |
| `test_concurrency.py` | Thread-safe concurrent redaction |

Run all: `pytest tests/benchmark/ -v -s -p no:recording`

## Results

Results from `python -m tests.benchmark ... --save` are stored as JSON in `tests/benchmark/results/`. Each snapshot records dataset, mode, language, sample count, per-type metrics, and timestamp for regression tracking.
