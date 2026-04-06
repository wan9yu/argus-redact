# argus-redact

[![PRvL](https://img.shields.io/badge/PRvL-Gold-brightgreen)](docs/prvl-standard.md) [![PII Leak](https://img.shields.io/badge/PII%20Leak-0%25-brightgreen)](docs/prvl-standard.md) [![Rust](https://img.shields.io/badge/core-Rust%20%2B%20PyO3-orange)](Cargo.toml) [![Demo](https://img.shields.io/badge/🤗-Demo-yellow)](https://huggingface.co/spaces/wan9yu/argus-redact)
[![PyPI](https://img.shields.io/pypi/v/argus-redact)](https://pypi.org/project/argus-redact/) [![Downloads](https://img.shields.io/pypi/dm/argus-redact)](https://pypi.org/project/argus-redact/) [![Tests](https://github.com/wan9yu/argus-redact/actions/workflows/test.yml/badge.svg)](https://github.com/wan9yu/argus-redact/actions/workflows/test.yml) [![codecov](https://codecov.io/gh/wan9yu/argus-redact/graph/badge.svg)](https://codecov.io/gh/wan9yu/argus-redact)

**Encrypt PII, not meaning. Locally.**

The privacy layer between you and AI. Your identity stays on your device — AI gets the meaning, not you.

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

## Three Promises

| | Promise | How |
|-|---------|-----|
| 🛡️ | **Protected** — your PII never leaves your device | 3-layer local detection: regex → NER → local LLM |
| 🧠 | **Usable** — AI can still understand and help you | Pseudonym replacement preserves meaning and context |
| 🔄 | **Reversible** — you get everything back, intact | Per-message key, one-line restore |

Other tools shred your PII — it's gone forever. argus-redact encrypts it with a different key every time. [ETH Zurich research](https://arxiv.org/abs/2602.16800) shows LLMs can deanonymize users for $1-4/person when pseudonyms are fixed. We generate **fresh random keys per call** — the cloud sees unrelated pseudonyms every time.

## Privacy Levels

argus-redact evaluates your text from **your perspective**, not a regulator's:

```
🟢 Safe      — nothing about you is exposed
🟡 Caution   — contains personal info, not dangerous alone
🟠 Danger    — can narrow down to you specifically
🔴 Exposed   — directly identifies you
```

```python
from argus_redact import redact

report = redact("身份证110101199003074610，手机13812345678，确诊糖尿病", report=True)
report.risk.level    # "critical"
report.risk.score    # 1.0
report.risk.reasons  # ("id_number (critical)", "phone (high)", "medical (critical)", ...)
```

This is what compliance frameworks don't tell you: **how dangerous is it to share this specific text with AI?**

## Three Layers, Collaborative

```
Layer 1  Rust+Regex   phone, ID, bank card, email, self-reference, ...    <0.2ms
             │
         produce_hints() → text_intent, pii_density, self_reference_tier
             │
Layer 2  NER ← hints   locations, organizations, standalone names         10-100ms
Layer 3  Local LLM      implicit PII — symptoms→disease, behavior→belief  ~20s
```

Layers are not independent — L1 passes **hints** to L2, enabling collaborative detection. Instruction text ("帮我看看这段代码") skips NER entirely. High PII density lowers NER thresholds. Cross-layer agreement boosts confidence.

Unicode-hardened: NFKC normalization, zero-width stripping, Cyrillic/Greek confusable defense, Chinese digit detection (一三八零零一三八零零零 → detected as phone).

Core engine (regex matching, entity merging, restore, pseudonym generation) is written in **Rust via PyO3** for maximum performance. Python handles orchestration, NER models, and LLM integration.

~47 PII types across 4 levels — from phone numbers to medical diagnoses, religious beliefs, political opinions. Use what you need: `mode="fast"` (Layer 1 only) → `mode="ner"` (+ NER) → `mode="auto"` (all three).

**Telemetry:** `ARGUS_PERF_LOG=perf.jsonl` for per-call timing breakdown. [Details →](docs/api-reference.md#performance-telemetry)

## 8 Languages

| | zh | en | ja | ko | de | uk | in | br |
|-|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| Phone | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| National ID | MOD11-2 | SSN | My Number | RRN | Tax ID | NINO | Aadhaar | CPF/CNPJ |
| Bank/Card | Luhn | Luhn | — | — | IBAN | — | PAN | — |
| Person names | HanLP | spaCy | spaCy | spaCy | spaCy | spaCy | spaCy | spaCy |
| Email | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

Mix freely: `lang=["zh", "en", "de"]`. Pass known names: `names=["王一", "张三"]`.

## Performance

Rust core (PyO3) — M1 Max, `mode="fast"`:

| Text | redact() | restore() | Throughput |
|------|:--------:|:---------:|:----------:|
| Short (17 chars) | 0.07ms | 0.04ms | 13,036 docs/sec |
| Medium (770 chars) | 1.00ms | 0.05ms | 1,031 docs/sec |
| Long (10K chars) | 22.2ms | 0.05ms | 45 docs/sec |

Pre-built wheels for all major platforms — no Rust toolchain needed to install:

```
✓ Linux x86_64 (glibc + musl/Alpine)
✓ Linux aarch64 (Raspberry Pi + Alpine ARM)
✓ macOS (Apple Silicon + Intel)
✓ Windows x64
× Python 3.10 / 3.11 / 3.12 / 3.13
```

[ai4privacy benchmark](https://huggingface.co/datasets/ai4privacy/pii-masking-400k): Email P=95% R=94%. Chinese PII F1=97%. [Benchmarks →](tests/benchmark/README.md) | [Performance →](docs/performance.md)

## North Star

| Dimension | Current (v0.4.6) | Next milestone |
|-----------|:----------------:|:---:|
| **Protected** | ~47 PII types, L1-L4. PII leak 0% across GPT-4o / Claude / Gemini. Cross-layer hints | Adversarial testing |
| **Usable** | PRvL U=100%. Pseudonym codes preserve trigger words | More task types |
| **Reversible** | PRvL R by task: reference 100%, extract 50%, creative 0% (by design) | Task-aware guidance |
| **Compliance** | PIPL ~85%, risk + audit PDF | PIPL/GDPR/HIPAA (byproduct) |
| **Coverage** | 8 langs, 4 LLMs benchmarked, 6 frameworks | Browser extension |

## Risk Assessment & Audit

```python
# Assess risk before sending to AI
report = redact(text, report=True)
report.risk.level         # "critical"
report.risk.pipl_articles # ("PIPL Art.28", "PIPL Art.51", ...)

# Generate compliance audit report
from argus_redact import generate_report_pdf
generate_report_pdf(report, "audit-report.pdf")
```

```bash
# CLI
argus-redact assess -f json  <<< "身份证110101199003074610"
argus-redact assess -f pdf -o report.pdf <<< "身份证110101199003074610"
```

Compliance profiles: `redact(text, profile="pipl")` / `"gdpr"` / `"hipaa"`.
Type filtering: `redact(text, types=["phone", "id_number"])` / `types_exclude=["address"]`.

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

## Security

PII never leaves your device. Per-message keys prevent cross-request profiling. [Full security model →](docs/security-model.md)

Meets **PIPL** · **GDPR** · **HIPAA** technical requirements as a byproduct of its privacy-first design. [Details →](docs/security-model.md#regulatory-context)

## Documentation

| | |
|-|-|
| [Getting Started](docs/getting-started.md) | Install, first redact/restore, key management |
| [API Reference](docs/api-reference.md) | All parameters, return types, streaming, structured data |
| [CLI Reference](docs/cli-reference.md) | Commands, flags, serve, MCP server |
| [Configuration](docs/configuration.md) | Per-type strategies, enterprise mask rules, false positive reduction |
| [Sensitive Info](docs/sensitive-info.md) | Taxonomy, privacy levels, roadmap |
| [Architecture](docs/architecture.md) | Three-layer engine, cross-layer hints, pure/impure separation |
| [Language Packs](docs/language-packs.md) | Adding new languages |
| [Security Model](docs/security-model.md) | Threat model, compliance, per-message keys |
| [**PRvL Standard**](docs/prvl-standard.md) | **Open evaluation standard: Privacy × Reversibility × Language** |
| [Layer 3 Benchmark](docs/layer3-benchmark.md) | LLM model comparison, prompt design, regulatory analysis |
| [Benchmarks](tests/benchmark/README.md) | Evaluation against 9 public PII datasets |
| [Performance](docs/performance.md) | Latency, throughput, benchmark results |

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) — language packs, test scenarios, framework integrations welcome.

## Contributors

| Who | Contribution |
|-----|-------------|
| [@aiedwardyi](https://github.com/aiedwardyi) | Brazilian Portuguese language pack (CPF, CNPJ, phone) |

## License

[Apache 2.0](LICENSE)
