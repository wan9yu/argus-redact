# Contributing to argus-redact

Thank you for your interest! argus-redact is an open-source PII encryption tool and we welcome contributions of all kinds.

## Quick Start

```bash
git clone https://github.com/wan9yu/argus-redact.git
cd argus-redact
pip install -e ".[dev]"
./build.sh                    # lint + test + build
./build.sh integration        # includes NER tests (needs hanlp/spacy)
```

## Good First Issues

### Add a Language Pack (easiest)

Each language pack is a Python file with regex patterns. Example — adding Brazilian PII:

1. Create `src/argus_redact/lang/br/patterns.py`:
```python
PATTERNS = [
    {
        "type": "cpf",
        "label": "[CPF]",
        "pattern": r"\d{3}\.\d{3}\.\d{3}-\d{2}",
        "description": "Brazilian CPF number",
    },
]
```
2. Create `src/argus_redact/lang/br/__init__.py`
3. Register in `src/argus_redact/glue/redact.py` (`_LANG_PATTERNS`)
4. Add test fixtures in `tests/fixtures/br_patterns.json`
5. Add test in `tests/lang/test_br.py`

### Add Test Scenarios

Add realistic test cases to `tests/fixtures/realistic_scenarios.json`. Each case needs:
- Synthetic (fake) PII — never use real data
- Clear description
- Expected PII values

### Add a Benchmark Dataset

We evaluate against public PII datasets via the `tests/benchmark/` framework. Adding a new dataset:

1. Create `tests/benchmark/adapters/your_dataset.py`
2. Implement `DatasetAdapter.load()` → normalize to `Sample(text, lang, entities)`
3. Add `@register` decorator, import in `adapters/__init__.py`
4. Run: `python -m tests.benchmark your_dataset --limit 100`

See [Benchmarks](tests/benchmark/README.md) for details and existing adapters.

### Add a Framework Integration

We have LangChain, LlamaIndex, FastAPI, Presidio, MCP. Missing:
- Dify plugin
- FastGPT plugin
- CrewAI tool
- Haystack pipeline

## Development Workflow

1. **Tests first** — write failing tests, then implement
2. **BDD naming** — `test_should_xxx_when_xxx`
3. **Run `./build.sh`** before committing — it formats, lints, tests, and builds
4. **Small commits** — one logical change per commit

## Code Structure

```
src/argus_redact/
├── pure/           # Deterministic, no side effects (Rust-ready)
│   ├── patterns.py     # match_patterns()
│   ├── replacer.py     # replace()
│   ├── restore.py      # restore()
│   ├── merger.py        # merge_entities()
│   └── pseudonym.py     # PseudonymGenerator
├── impure/         # I/O, models
│   ├── ner.py           # NERAdapter + detect_ner()
│   ├── semantic.py      # SemanticAdapter + detect_semantic()
│   └── ollama_adapter.py
├── glue/           # Composes pure + impure
│   └── redact.py        # redact() public API
├── lang/           # Language packs
│   ├── zh/ en/ ja/ ko/ de/ uk/ in_/
│   └── shared/
├── specs/          # PII type registry (single source of truth)
│   ├── registry.py     # PIITypeDef + global registry
│   ├── zh.py           # Chinese PII type definitions
│   └── fakers_zh.py    # Fake data generators (canonical data pools)
├── integrations/   # Framework adapters
└── cli/            # CLI commands
```

## Test Data

All test data in `tests/fixtures/*.json` is **synthetic**. Never commit real PII.

Test data format:
```json
{
  "id": "descriptive_snake_case",
  "input": "synthetic text with PII",
  "should_match": true,
  "type": "phone",
  "expected_text": "13812345678",
  "description": "what this tests"
}
```

## Questions?

Open an issue at https://github.com/wan9yu/argus-redact/issues
