# argus-redact

[![Tests](https://github.com/wan9yu/argus-redact/actions/workflows/test.yml/badge.svg)](https://github.com/wan9yu/argus-redact/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/wan9yu/argus-redact/graph/badge.svg)](https://codecov.io/gh/wan9yu/argus-redact)

**Encrypt PII, not meaning. Locally.**

> *Like GPG for personal data in LLM pipelines — your text goes to the cloud, your identity stays home.*

---

## Install

```bash
pip install argus-redact              # core (regex only, zero heavy deps)
pip install argus-redact[zh]          # + Chinese NER (person/location/org names)
pip install argus-redact[en]          # + English NER
pip install argus-redact[full]        # + all languages + semantic layer
pip install argus-redact[presidio]   # + Presidio bridge (reversible Presidio)
pip install argus-redact[mcp]        # + MCP server for Claude Desktop / Cursor
```

Python 3.10+. No GPU. Runs on CPU.

## Two Functions, One Key

```python
from argus_redact import redact, restore  # requires: pip install argus-redact[zh]

# encrypt
redacted, key = redact("王五和张三在星巴克讨论了去阿里面试的事")
# redacted = "P-037和P-012在[咖啡店]讨论了去[某公司]面试的事"
# key      = {"P-037": "王五", "P-012": "张三", "[咖啡店]": "星巴克", "[某公司]": "阿里"}

# send redacted text to any LLM — your identity stays local
llm_output = call_llm(redacted)

# decrypt
restored = restore(llm_output, key)
```

The `key` is a plain dict. Treat it like a private key — if it leaks, your identity is exposed.

```bash
# Same workflow, Unix-style
cat journal.txt | argus-redact redact -k key.json > redacted.txt
cat redacted.txt | llm "summarize" > llm_output.txt
cat llm_output.txt | argus-redact restore -k key.json
```

> **Core install without `[zh]`?** Regex-only — catches phone numbers, ID cards, emails, bank cards. Person/location/org names require NER (`[zh]` or `[en]`).

## Why

The most valuable data for LLMs is the data you should never send to the cloud — journals, conversations, medical notes, consulting records.

argus-redact is **semantic encryption**: it hides identity while preserving meaning, so LLMs can still reason about your text.

| | Traditional encryption | argus-redact |
|-|----------------------|--------------|
| Output | Unreadable ciphertext | Readable text, no identities |
| LLM can process? | No | **Yes** |
| Reversible? | Yes, with key | Yes, with key |
| Key leaked = ? | Plaintext exposed | Identities exposed |

## Performance

Regex layer (mode="fast"), no GPU required:

| | Apple M1 Max | Raspberry Pi Zero 2W |
|-|-------------|---------------------|
| Short text (17 chars) | 0.06ms | 0.98ms |
| Medium text (770 chars) | 0.28ms | 4.29ms |
| Long text (10K chars) | 3.70ms | 52.93ms |
| restore() | <0.01ms | 0.04ms |
| Throughput | 42,789 docs/sec | 3,433 docs/sec |
| 4-language overhead | 2.5x | 2.0x |

The cloud LLM call (500-3000ms) dominates any pipeline. argus-redact adds negligible latency.

## Per-Message Random Keys

Every `redact()` call generates a fresh random key — like a new encryption key per message.

```python
_, key1 = redact("王五和张三讨论了面试")  # P-037, P-012
_, key2 = redact("王五和张三讨论了面试")  # P-003, P-071
```

Two requests → two unrelated pseudonym sets. The cloud cannot link them by pseudonym. (Context-based inference is still possible — see [Security Model](docs/security-model.md).)

Reuse a key for batch consistency:

```python
text1, key = redact("王五给张三发了资料")
text2, key = redact("张三给王五回了消息", key=key)  # same key → same pseudonyms
```

No key = new session. Pass key = same session. One parameter, no separate `batch()` API.

## Deterministic Testing with `seed`

`redact()` is non-deterministic by design (random pseudonyms). For testing, pass `seed` to make output reproducible:

```python
# Production: random (secure)
redacted, key = redact("张三 13812345678")           # P-??? — different each time

# Testing: deterministic (assertable)
redacted, key = redact("张三 13812345678", seed=42)   # P-037 — always the same
redacted, key = redact("张三 13812345678", seed=42)   # P-037 — identical
```

`restore()` is always deterministic — it's pure string replacement.

## Mixed Language

```python
# Chinese + English
redacted, key = redact(
    "王五给John发了邮件，讨论了Apple的offer，电话13812345678",
    lang=["zh", "en"],
)

# All four languages
redacted, key = redact(
    "手机13812345678，SSN 123-45-6789，携帯090-1234-5678，전화010-1234-5678",
    lang=["zh", "en", "ja", "ko"],
)
```

Each language's patterns run independently, results merged automatically.

## What Gets Redacted

Three layers, bottom-up:

```
Layer 1  Pattern   Regex — phone numbers, ID cards, bank cards, emails
Layer 2  Entity    NER models — person names, locations, organizations
Layer 3  Semantic  Local small LLM — implicit PII, context-dependent sensitivity
```

```
Input: "老王说他上周在那个地方见了老李，聊了聊那件事"

Layer 1 (Regex):  no match
Layer 2 (NER):    老王 → PERSON, 老李 → PERSON
Layer 3 (LLM):    "那个地方" → sensitive location, "那件事" → sensitive topic
```

### Supported Languages & PII Types

| PII Type | Chinese (zh) | English (en) | Japanese (ja) | Korean (ko) |
|----------|-------------|-------------|--------------|-------------|
| Phone | 1xx-xxxx-xxxx, landline | (xxx) xxx-xxxx | 0x0-xxxx-xxxx, landline | 01x-xxxx-xxxx, landline |
| National ID | 18-digit, MOD 11-2 | SSN (xxx-xx-xxxx) | My Number (12-digit) | RRN (YYMMDD-XXXXXXX) |
| Bank card | 16-19 digits (Luhn) | Credit card (Luhn) | — | — |
| License plate | 京A12345 | — | — | — |
| Address | Structured (省/市/区/路/号) | — | — | — |
| Passport | X12345678 | — | — | — |
| Person names | NER (HanLP) | NER (spaCy) | — | — |
| Locations | NER + semantic | NER + semantic | — | — |
| Organizations | NER + semantic | NER + semantic | — | — |
| Email | Shared regex | Shared regex | Shared regex | Shared regex |
| Implicit PII | Layer 3 (Ollama) | Layer 3 (Ollama) | Layer 3 (Ollama) | Layer 3 (Ollama) |

Mixed language — combine any languages with `lang=["zh", "en", "ja", "ko"]`.

## LLM Integration

```python
from argus_redact import redact, restore
from openai import OpenAI

client = OpenAI()

def safe_ask(text: str, prompt: str) -> str:
    redacted, key = redact(text)
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": prompt},
            {"role": "user", "content": redacted},
        ],
    )
    return restore(response.choices[0].message.content, key)

answer = safe_ask("王五在协和医院检查了身体", "You are a health advisor.")
# LLM never sees 王五 or 协和医院
```

## Security Model

```
┌─── YOUR DEVICE ──────────────────────────────────────────┐
│                                                           │
│  plaintext ──→ redact() ──→ redacted text ──→ NETWORK    │
│                   │                                       │
│                  key (dict, in-memory)                    │
│                   │         NEVER leaves device           │
│                   ▼                                       │
│  restored  ←── restore() ←── LLM response ←── NETWORK   │
│                                                           │
└───────────────────────────────────────────────────────────┘
```

**Honest limitations:**
- This is **semantic encryption, not mathematical encryption**. Context inference attacks are possible ("the CEO of [company] in [city]" might be guessable). Layer 3 tries to catch these, but no guarantee.
- The key is a plaintext dict. Protect it like a private key.
- `seed` makes output deterministic — **never use `seed` in production**, only in tests.

See [docs/security-model.md](docs/security-model.md) for the full threat model.

## Compliance

**China PIPL**: Cross-border data transfer rules (2026-01) require PII removal before sending to overseas LLM APIs. argus-redact provides the technical control — PII is replaced locally, only pseudonymized text crosses the border, per-session keys prevent cross-request profiling.

**EU AI Act / GDPR**: Data minimization requirements for AI systems. argus-redact ensures only identity-removed text is processed by external services.

> argus-redact is a technical tool, not a legal certification. Consult legal counsel for your specific requirements.

## Architecture: Pure Core

argus-redact separates pure functions (testable, deterministic) from impure functions (I/O, models):

```
Pure (Rust-ready)          Impure (Python)           Glue
─────────────────          ───────────────           ────
match_patterns()           detect_ner()              redact()
replace()                  detect_semantic()
restore()                  read/write key file
merge_entities()           generate_random_seed()
generate_pseudonym()
```

- **Pure layer:** Deterministic with `seed`. Zero deps. Future Rust via PyO3.
- **Impure layer:** Model loading, LLM inference, file I/O. Stays in Python.
- **`restore()` is always pure.** Same input + same key = same output. No models, no randomness.

See [docs/architecture.md](docs/architecture.md) for the full purity model.

## Comparison

| Feature | argus-redact | Presidio | AVA Protocol | Tonic Textual | anonLLM |
|---------|-------------|----------|-------------|--------------|---------|
| Reversible | **Yes** (key) | Partial | Yes (vault) | No (synthesis) | Yes |
| Per-message keys | **Yes** | No | No | No | No |
| Chinese-native PII | **Yes** | No | No | Limited | No |
| Fully local | **Yes** | Yes | Yes | No (SaaS) | **No** (uses OpenAI) |
| Semantic detection | **Yes** (Ollama) | No | No | Yes | No |
| Two-line API | **Yes** | No | No | No | Yes |
| Deterministic testing | **Yes** (`seed`) | No | No | No | No |

> **Why per-message keys matter:** [Research shows](https://arxiv.org/abs/2602.16800) LLMs can deanonymize users for $1-4/person when pseudonyms are fixed across requests. argus-redact generates a fresh random key per `redact()` call — the cloud sees unrelated pseudonyms every time.

**Already using Presidio?** argus-redact is complementary. Presidio detects and masks PII. argus-redact adds reversible pseudonymization with per-session key rotation, optimized for the redact → LLM → restore workflow. You can use both.

## Presidio Bridge

Already using Presidio? Add reversible per-message keys in one line:

```python
from argus_redact.integrations.presidio import PresidioBridge

bridge = PresidioBridge()
redacted, key = bridge.redact("John Smith called 555-123-4567", language="en")
# Presidio detects → argus-redact encrypts with per-message key

llm_output = call_llm(redacted)
restored = bridge.restore(llm_output, key)
```

`pip install argus-redact[presidio]`

## MCP Server

Use argus-redact as an MCP tool in Claude Desktop or Cursor:

```bash
pip install argus-redact[mcp]
python -m argus_redact.integrations.mcp_server
```

Add to Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "argus-redact": {
      "command": "python",
      "args": ["-m", "argus_redact.integrations.mcp_server"]
    }
  }
}
```

Exposes three tools: `redact`, `restore`, `info`.

## Roadmap

### Next

- Japanese / Korean NER adapters (GiNZA, KoNLPy)
- Rust core via PyO3 for hot paths

## Contributing

We welcome contributions:

- **NER adapters** — spaCy English, GiNZA Japanese, KoNLPy Korean
- **Regex patterns** — Country-specific PII formats
- **Benchmarks** — PII detection test cases (synthetic only, no real PII)
- **Integrations** — LangChain, LlamaIndex, FastAPI middleware

## License

[MIT](LICENSE)

## References

- [LOPSIDED: Semantically-Aware Privacy Agent (arXiv 2510.27016)](https://arxiv.org/abs/2510.27016)
- [PAPILLON: Privacy Preservation from Local LM Ensembles (NAACL 2025)](https://aclanthology.org/2025.naacl-long.173/)
- [PRvL: LLM PII Redaction Benchmark (arXiv 2508.05545)](https://arxiv.org/abs/2508.05545)
