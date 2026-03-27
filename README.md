# argus-redact

[![Tests](https://github.com/wan9yu/argus-redact/actions/workflows/test.yml/badge.svg)](https://github.com/wan9yu/argus-redact/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/wan9yu/argus-redact/graph/badge.svg)](https://codecov.io/gh/wan9yu/argus-redact)
[![PyPI](https://img.shields.io/pypi/v/argus-redact)](https://pypi.org/project/argus-redact/)
[![Demo](https://img.shields.io/badge/🤗-Live_Demo-yellow)](https://huggingface.co/spaces/wan9yu/argus-redact)

**Encrypt PII, not meaning. Locally.**

Other tools shred your PII — it's gone forever. argus-redact encrypts it — with a different key every time.

```python
from argus_redact import redact, restore

redacted, key = redact("王五在协和医院做了体检，手机13812345678", names=["王五"])
# "P-83811在[LOCATION]做了体检，手机138****5678"

llm_output = call_llm(redacted)     # LLM never sees real identities
restored = restore(llm_output, key)  # one line to get everything back
```

```bash
pip install argus-redact
```

## Why

| | Traditional encryption | argus-redact |
|-|----------------------|--------------|
| LLM can process? | No | **Yes** |
| Reversible? | Yes | **Yes**, with per-message key |
| Key leaked? | Plaintext exposed | Identities exposed (that session only) |

[ETH Zurich research](https://arxiv.org/abs/2602.16800) shows LLMs can deanonymize users for $1-4/person when pseudonyms are fixed. argus-redact generates a **fresh random key per call** — the cloud sees unrelated pseudonyms every time.

## Three Layers

```
Layer 1  Regex+Score  phone, ID, bank card, email, address, person names   <1ms
Layer 2  NER          locations, organizations, standalone names           10-100ms
Layer 3  Local LLM    "那个地方", nicknames, implicit PII                   ~1s
```

Use what you need: `mode="fast"` (Layer 1 only) → `mode="ner"` (+ NER) → `mode="auto"` (all three).

## 7 Languages

| | zh | en | ja | ko | de | uk | in |
|-|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| Phone | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| National ID | MOD11-2 | SSN | My Number | RRN | Tax ID | NINO | Aadhaar |
| Bank/Card | Luhn | Luhn | — | — | IBAN | — | PAN |
| Person names | HanLP | spaCy | spaCy | spaCy | spaCy | spaCy | spaCy |
| Email | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

Mix freely: `lang=["zh", "en", "de"]`. Pass known names: `names=["王一", "张三"]`.

## Performance

| | M1 Max | Raspberry Pi Zero 2W |
|-|--------|---------------------|
| Throughput | 42,789 docs/sec | 3,433 docs/sec |
| Medium text (770 chars) | 0.28ms | 4.29ms |
| restore() | <0.01ms | 0.04ms |

[ai4privacy benchmark](https://huggingface.co/datasets/ai4privacy/pii-masking-400k): Email P=95% R=94%. Chinese PII F1=97%. [Benchmarks →](tests/benchmark/README.md) | [Performance →](docs/performance.md)

## North Star — Six Dimensions of PII

We evaluate ourselves on six core capabilities. This scorecard evolves with each release.

| Dimension | What it measures | Current (v0.1.9) | Target |
|-----------|-----------------|:-----------------:|:------:|
| **Detection** | Find PII without miss or false alarm | P=96% R=98% F1=97%; person names via candidate+scoring | — (achieved) |
| **Semantic Preservation** | Redacted text stays meaningful for LLM | Pseudonym replacement keeps context readable | — (achieved) |
| **Reversibility** | Restore original from key, per-message isolation | Per-message random key, full restore | — (achieved) |
| **Security** | PII never leaves device, resist correlation attacks | Fully local, fresh key per call | Add key rotation & TTL |
| **Performance** | Fast enough for real-time pipelines | Regex 36K docs/s, NER 3 docs/s | NER >50 docs/s (Rust core) |
| **Integration** | Drop into any stack in minutes | 2-line API, 6 frameworks, MCP, Docker | Dify, CrewAI, Haystack |

**Our moat is Semantic Preservation + Reversibility.** Other tools delete PII permanently — we encrypt it and give it back. In the LLM era, this is the difference between a privacy tool and a privacy-aware pipeline.

[Full benchmark report →](docs/benchmark-report.md)

## Integrations

| | Install |
|-|---------|
| [LangChain / LlamaIndex / FastAPI](docs/integration-frameworks.md) | core |
| [Presidio bridge](docs/integration-frameworks.md) | `pip install argus-redact[presidio]` |
| [MCP Server](docs/cli-reference.md#mcp-server) (Claude Desktop / Cursor) | `pip install argus-redact[mcp]` |
| [HTTP API Server](docs/cli-reference.md) | `pip install argus-redact[serve]` |
| [Structured data](docs/api-reference.md) (JSON / CSV) | core |
| [Streaming restore](docs/api-reference.md) | core |
| [Docker](Dockerfile) | slim 157MB / full 5GB |

## Security & Compliance

PII never leaves your device. Per-message keys prevent cross-request profiling. [Full security model →](docs/security-model.md)

**PIPL** · **GDPR** · **HIPAA** — technical control layer for cross-border LLM usage. [Details →](docs/security-model.md#regulatory-context)

## Documentation

| | |
|-|-|
| [Getting Started](docs/getting-started.md) | Install, first redact/restore, key management |
| [API Reference](docs/api-reference.md) | All parameters, return types, streaming, structured data |
| [CLI Reference](docs/cli-reference.md) | Commands, flags, serve, MCP server |
| [Configuration](docs/configuration.md) | Per-type strategies, enterprise mask rules, false positive reduction |
| [Architecture](docs/architecture.md) | Three-layer engine, pure/impure separation |
| [Language Packs](docs/language-packs.md) | Adding new languages |
| [Security Model](docs/security-model.md) | Threat model, compliance, per-message keys |
| [Benchmarks](tests/benchmark/README.md) | Evaluation against 9 public PII datasets |
| [Performance](docs/performance.md) | Latency, throughput, benchmark results |

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) — language packs, test scenarios, framework integrations welcome.

## License

[MIT](LICENSE)
