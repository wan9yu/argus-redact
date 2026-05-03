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

## Default redaction output

`redact()` emits **per-type pseudonym codes**, not Chinese label literals:

```python
>>> redact("员工张三，身份证110101199003074610，电话13812345678", mode='fast', lang='zh')
('员工P-83811，身份证ID-89732，电话138****5678',
 {'P-83811': '张三', 'ID-89732': '110101199003074610', '138****5678': '13812345678'})
```

| Type group | Default output | Strategy | Reversible |
|---|---|---|:---:|
| `person` / `organization` | `P-NNNNN` / `O-NNNNN` | `pseudonym` | ✓ |
| `phone` / `email` / `bank_card` | `138****5678` (partial digits visible) | `mask` | ✗ |
| `id_number` / `medical` / `ssn` / ... | `ID-NNNNN` / `MED-NNNNN` / `SSN-NNNNN` | `remove` → per-type code | ✓ |
| `self_reference` | `我` / `我妈` (kept verbatim) | `keep` | ✓ |

To **unify all reversible types** under one prefix (hides PII type from the LLM):

```python
redact(
    text,
    unified_prefix="R",
    config={
        "phone": {"strategy": "remove"},   # mask types must opt in to participate
        "email": {"strategy": "remove"},
    },
)
# → "员工R-83811，身份证R-89732，电话R-12345"
```

`<TYPE_N>` 1-based sequential token style is on the future-release candidate list (no committed timeline). See [docs/configuration.md](docs/configuration.md#unified-prefix-hide-pii-type) for the current strategy reference.

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

~47 PII types across 4 levels — from phone numbers to medical diagnoses, religious beliefs, political opinions. Default is `mode="fast"` (Layer 1 only, zero deps, sub-ms). Opt in: `mode="ner"` (+ NER models) → `mode="auto"` (all three layers).

**Telemetry:** `ARGUS_PERF_LOG=perf.jsonl` for per-call timing breakdown. [Details →](docs/api-reference.md#performance-telemetry)

## Limitations & When NOT to Rely on This

argus-redact is a PII **data minimization aid**, not an anonymization or compliance certification:

- **L1 fast (regex)** matches well-defined formats. Novel or obfuscated variants, cross-field inference attacks pass through.
- **L2 NER** is statistical inference; out-of-distribution text (informal, typo-heavy, minority names) has higher miss rate. See [benchmark results](docs/benchmark-report.md) for measured numbers.
- **No guarantee against adversarial inputs** — attackers can craft text that evades detection.
- **Not a GDPR / PIPL anonymization framework** — anonymization is a compliance process decision, not a single-library output.

**When to use argus-redact**: reversible pseudonymization for LLM pipelines where you need `redact() → LLM → restore()` with zero PII crossing the network boundary.

**When to consider alternatives**: if you need one-way English PII masking with a single model call, [OpenAI Privacy Filter](https://huggingface.co/openai/privacy-filter) and similar model-based maskers may fit better. argus-redact's niche is Chinese-optimized multi-layer detection + reversibility.

Combine argus-redact with audit logging, rate limiting, and upstream policy — no single layer is sufficient.

## 8 Languages

| | zh | en | ja | ko | de | uk | in | br |
|-|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| Phone | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| National ID | MOD11-2 + 15位旧版 | SSN | My Number | RRN | Tax ID | NINO | Aadhaar | CPF/CNPJ |
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

| Dimension | Current (v0.6.0) | Next milestone |
|-----------|:----------------:|:---:|
| **Protected** | ~47 PII types, L1-L4. PII leak 0% across GPT-4o / Claude / Gemini. Cross-layer hints in 8 langs (zh/en/ja/ko/de/uk/in/br). MCP token-only key handling. Windows CI | Adversarial testing |
| **Usable** | PRvL U=100%. Pseudonym codes + realistic mode (zh + en + RFC shared) + per-call strategy overrides + `keep` strategy + resumable streaming sessions + incremental streaming default + cross-language alias restore (zh ↔ en) | Task-aware guidance |
| **Reversible** | PRvL R by task: reference 100%, extract 50%, creative 0% (by design). Cross-language LLM rewrites (`张三` → `Zhang San`) auto-restored via `result.aliases` + `restore(text, key, aliases=...)` | Task-aware guidance |
| **Compliance** | PIPL ~85%, risk assessment + profiles | PIPL/GDPR/HIPAA (byproduct) |
| **Coverage** | 8 langs, 4 LLMs benchmarked, 6 frameworks | Browser extension |

## Risk Assessment

```python
# Assess risk before sending to AI
report = redact(text, report=True)
report.risk.level         # "critical"
report.risk.pipl_articles # ("PIPL Art.28", "PIPL Art.51", ...)
report.entities           # detected PII details
report.stats              # per-layer timing
```

```bash
# CLI
argus-redact assess <<< "身份证110101199003074610"
```

Compliance profiles: `redact(text, profile="pipl")` / `"gdpr"` / `"hipaa"`.
Type filtering: `redact(text, types=["phone", "id_number"])` / `types_exclude=["address"]`.

## Realistic Redaction (`pseudonym-llm` profile)

Default redaction emits placeholder labels (`[TEL-79329]`, `P-164`) — clear for audit, but breaks downstream LLM reasoning because the message structure is gone. The `pseudonym-llm` profile replaces PII with **realistic-looking but reserved-range fake values** (e.g., `19999...` mobile, `999...` ID, `999999...` bank card). LLMs reason correctly; humans can still tell it's synthetic if they know the convention.

Each call returns **three text forms** sharing one key dict:

| Form | Example | Use for |
|------|---------|---------|
| `audit_text` | `请拨打 [TEL-79329] 联系 P-164` | Compliance archive — placeholder labels are auditable |
| `downstream_text` | `请拨打 19999123456 联系张明` | LLM input — semantic structure preserved |
| `display_text` | `请拨打 19999123456ⓕ 联系张明ⓕ` | UI rendering — visible `ⓕ` marker prevents confusion |

```python
from argus_redact import redact_pseudonym_llm, restore

# Chinese
zh = redact_pseudonym_llm("请拨打 13912345678 联系王建国", lang="zh")
zh.downstream_text  # "请拨打 19999123456 联系张明"           → LLM
zh.display_text     # "请拨打 19999123456ⓕ 联系张明ⓕ"        → UI

# English
en = redact_pseudonym_llm("Call (415) 555-1234, SSN 123-45-6789", lang="en")
en.downstream_text  # "Call (555) 555-0142, SSN 999-37-2811" → LLM
en.audit_text       # "Call [PHONE-23801], SSN [SSN-15772]"  → audit

# Mixed (auto-detect)
mx = redact_pseudonym_llm("客户Wang at user@company.com", lang="auto")

# Round-trip works on any of the three forms, in any language
restore(zh.downstream_text, zh.key)   # → original
restore(en.downstream_text, en.key)   # → original
restore(mx.downstream_text, mx.key)   # → original
```

```bash
# CLI emits all three forms as JSON
echo "Call (415) 555-1234" | \
  argus-redact redact -k key.json --profile pseudonym-llm -l en | \
  jq .downstream_text
# "Call (555) 555-0142"
```

**Reserved ranges**:
- **zh**: `199-99-XXXXXX` mobile (sub-segment unassigned by 工信部), `099-` landline (no such area code), `999XXX` ID address code (GB/T 2260 unassigned), `999999` bank BIN (银联 unassigned), 滨海市 fictional city.
- **en**: `(555) 555-01XX` phone (FCC permanent fictional reservation), `999-XX-XXXX` SSN (SSA never assigns 9XX), `999999` credit card BIN, John Doe / Jane Roe person, 1313 Mockingbird Lane address.
- **shared (RFC)**: `example.com` / `.org` / `.net` email (RFC 2606), `192.0.2.0/24` / `198.51.100.0/24` / `203.0.113.0/24` IPv4 (RFC 5737), `2001:db8::/32` IPv6 (RFC 3849), `00:00:5E:00:53:xx` MAC (RFC 7042).

**Argus Gateway integration**: response headers should include `X-Argus-Redact-Profile: pseudonym-llm`; UI clients render `display_text`, LLM clients consume `downstream_text`. Storage of `downstream_text` as business truth is unsafe — it's synthetic by design.

**Real users named like canonical fakes** (e.g., a real customer named `张三` or `John Doe`): pass `reserved_names={"person_zh": ()}` (or `person_en`) to disable that locale's canonical-name pollution detection so the real user's name flows through normal redaction.

### Streaming

For chat sessions or long-form input where text arrives in chunks, use `StreamingRedactor` (input side) and `StreamingRestorer` (output side). Both require **complete logical units** per chunk (sentence / paragraph / turn) — entities split across chunk boundaries are not handled.

```python
from argus_redact.streaming import StreamingRedactor, StreamingRestorer

# Input side: redact each chunk; same original value across chunks → same fake
r = StreamingRedactor(salt=b"my-secret-salt", lang="zh")
for chunk in input_stream:                  # one sentence/paragraph/turn each
    res = r.feed(chunk)
    send_to_llm(res.downstream_text)

# Output side: restore LLM output stream at sentence boundaries
restorer = StreamingRestorer(r.aggregate_key())
for chunk in llm_output_stream:
    restored = restorer.feed(chunk)
    if restored:
        print(restored, end="")
print(restorer.flush(), end="")
```

True byte-level streaming (entities crossing chunk boundaries) needs full incremental detection and is roadmapped for a later release.

> ⚠️ Realistic-mode output **must not be re-redacted** (it would corrupt the key dict). `redact_pseudonym_llm` will raise `PseudonymPollutionError` if called on already-faked input — call `restore()` first.

[Full API →](docs/api-reference.md#redact_pseudonym_llm) · [Design constraints →](docs/known-issues.md#design-constraints)

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
| [PII Type Catalog](docs/pii-types.md) | All 52 types — strategy, sensitivity, PIPL/GDPR/HIPAA mapping (auto-generated) |
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
