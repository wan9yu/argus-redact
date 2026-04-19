# Contributing to argus-redact

Thank you for your interest! argus-redact is an open-source PII encryption tool and we welcome contributions of all kinds.

Please read our [Code of Conduct](CODE_OF_CONDUCT.md). For security issues, see [SECURITY.md](SECURITY.md) — **do not open public issues for vulnerabilities**.

## Scope

argus-redact is a PII detection and pseudonymization **library**. It does not include:

- HTTP routing, proxy middleware, or API gateway features
- Admin UIs, audit logs, or compliance evidence chains
- LLM upstream adapters (OpenAI / Anthropic / Ollama / etc.) beyond the basic integration examples in `src/argus_redact/integrations/`
- License or subscription management

Wrap argus-redact in your own service, or use a downstream product built on top of it. PRs outside this scope will be redirected.

## Quick Start

**Users:** Pre-built wheels available — just `pip install argus-redact`. No Rust needed.

**Developers:** Need Rust toolchain to build from source:

```bash
git clone https://github.com/wan9yu/argus-redact.git
cd argus-redact

# Install Rust toolchain (required for development)
brew install rust        # macOS
# or: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install in development mode (maturin builds Rust automatically)
pip install maturin
pip install -e ".[dev]"

# Run tests
pytest -m "not ner and not semantic and not slow"
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

## Releasing

Pushing a version tag triggers GitHub Actions to publish everywhere automatically.

### Steps

```bash
# 1. Bump version in two files
#    - pyproject.toml:   version = "0.x.x"
#    - src/argus_redact/__init__.py:  __version__ = "0.x.x"
#    - Update version references in: README.md, docs/benchmark-report.md,
#      docs/cli-reference.md, docs/known-issues.md, tests/cli/test_cli.py

# 2. Commit
git commit -am "release: v0.x.x — summary"

# 3. Tag and push (or: make release)
make release
```

`make release` reads the version from `__init__.py`, creates a git tag, and pushes. GitHub Actions (`.github/workflows/release.yml`) then:

1. Runs tests
2. Builds the package
3. Publishes to **PyPI** (trusted publishing)
4. Creates a **GitHub Release** with auto-generated notes
5. Deploys the **HF Space** (`demo/` folder)

### One-time setup (already done)

- **PyPI:** Trusted publisher configured at pypi.org → project settings → publishing
- **HF Token:** `HF_TOKEN` secret in GitHub repo settings → Secrets → Actions

## Code Structure

```
rust/src/           # Rust core (PyO3) — hot-path functions
├── lib.rs              # Module entry point
├── types.rs            # PatternMatch struct
├── patterns.rs         # match_patterns() — regex engine
├── merger.rs           # merge_entities()
├── restore.rs          # restore()
└── pseudonym.rs        # PseudonymGenerator

src/argus_redact/
├── pure/           # Python wrappers (delegate to Rust, fallback to Python)
│   ├── patterns.py     # match_patterns()
│   ├── replacer.py     # replace() — stays in Python (config dispatch)
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
│   ├── zh/ en/ ja/ ko/ de/ uk/ in_/ br/
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

## License

By contributing, you agree that your code will be licensed under Apache License 2.0, the same as the rest of the project. No separate CLA is required.
