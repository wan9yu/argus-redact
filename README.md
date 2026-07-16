# argus-redact

English · [中文说明](README.zh.md)

[![PyPI](https://img.shields.io/pypi/v/argus-redact)](https://pypi.org/project/argus-redact/) [![crates.io](https://img.shields.io/badge/crates.io-v0.8.1-orange)](https://crates.io/crates/argus-redact-core) [![Tests](https://github.com/wan9yu/argus-redact/actions/workflows/test.yml/badge.svg)](https://github.com/wan9yu/argus-redact/actions/workflows/test.yml) [![codecov](https://codecov.io/gh/wan9yu/argus-redact/graph/badge.svg)](https://codecov.io/gh/wan9yu/argus-redact) [![Demo](https://img.shields.io/badge/🤗-Demo-yellow)](https://huggingface.co/spaces/wan9yu/argus-redact)

**Encrypt PII, not meaning. Locally.**

The privacy layer between you and AI. Your identity stays on your device — AI gets the meaning, not you.

Rated **[PRvL-Gold](docs/prvl-standard.md)** on the PRvL reference suite — see the spec for what it measures.

<!-- pin -->
```python
from argus_redact import redact

redacted, key = redact("张三的电话是13812345678，身份证号110101199003074610", names=["张三"], lang="zh", salt=42)
print(redacted)
# expected: P-83811的电话是138****5678，身份证号ID-03292

print(sorted(key.items()))
# expected: [('138****5678', '13812345678'), ('ID-03292', '110101199003074610'), ('P-83811', '张三')]
```

```bash
pip install argus-redact
```

## Three Promises

| | Promise | How |
|-|---------|-----|
| 🛡️ | **Protected** — your PII never leaves your device | 3-layer local detection: regex → NER → local LLM |
| 🧠 | **Usable** — AI can still understand and help you | Pseudonym replacement preserves meaning and context |
| 🔄 | **Reversible** — substring-level inverse via per-message key | One-line `restore()` for verbatim LLM echoes; paraphrase / coref handled by [compose layer](docs/architecture-layers.md), best-effort |

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

60+ PII types across 3 layers — from phone numbers to medical diagnoses, religious beliefs, political opinions. Default is `mode="fast"` (Layer 1 only, zero deps, sub-ms). Opt in: `mode="ner"` (+ NER models) → `mode="auto"` (all three layers).

**Telemetry:** `ARGUS_PERF_LOG=perf.jsonl` for per-call timing breakdown. [Details →](docs/api-reference.md#performance-telemetry)

**Deployment fit** — modes have very different latency budgets; pick by where you sit in the request path:

| Mode | Latency (per doc) | Suitable as |
|---|:---:|---|
| `fast` | <1ms | Inline gateway plugin / hot LLM proxy path |
| `ner` | 10–100ms | Sidecar / pre-flight middleware |
| `auto` | ~20s (LLM-bound) | Async batch / offline review queue |

Don't put `auto` in front of an interactive LLM call. Use `fast` inline + `auto` in a parallel audit lane.

## Limitations & When NOT to Rely on This

argus-redact is a PII **data minimization aid**, not an anonymization or compliance certification:

- **L1 fast (regex)** matches well-defined formats. Novel or obfuscated variants, cross-field inference attacks pass through.
- **L2 NER** is statistical inference; out-of-distribution text (informal, typo-heavy, minority names) has higher miss rate. See [benchmark results](docs/benchmark-report.md) for measured numbers.
- **No guarantee against adversarial inputs** — attackers can craft text that evades detection.
- **Removing explicit PII ≠ anonymity.** LLM agents can re-identify individuals by combining residual, individually-non-identifying cues with public data — even on redacted text, even during benign tasks ([Ko et al. 2026](https://arxiv.org/abs/2603.18382)). Reversible substitution protects explicit identifiers and preserves LLM utility; it does **not** defend against inference-based re-identification, which a per-document redactor cannot fully prevent — the residual comes from *combinations* of quasi-identifiers, not single fields ([why coarsening one field doesn't fix it](docs/design-quasi-identifier-generalization.md); [and why detecting more English quasi-identifiers didn't reduce re-id either](docs/design-english-detection-breadth.md)).
- **Not a GDPR / PIPL anonymization framework** — anonymization is a compliance process decision, not a single-library output.

- **Restore is a substitution pass, not an authorization check.** An unguarded restore (`guard=False`) substitutes originals into *any* text carrying the right pseudonyms — including a reply an attacker steered the model into producing. As of v0.8.0 the default is `guard=True`, which fails closed without a valid anchor; use the [guarded round-trip](#security) to bind a restore to the exchange that produced the key.

**When to use argus-redact**: reversible pseudonymization for LLM pipelines where you need `redact() → LLM → guarded_restore()` with zero PII crossing the network boundary.

**When to consider alternatives**: if you need one-way English PII masking with a single model call, [OpenAI Privacy Filter](https://huggingface.co/openai/privacy-filter) and similar model-based maskers may fit better. argus-redact's strongest suit is **reversible** pseudonymization with **per-message keys**; Chinese has the deepest support (HanLP + native validators), the other 7 languages have regex + spaCy NER coverage. Pick by the workload, not by exclusivity.

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

**Benchmark scope:** only **zh** and **en** have committed recall benchmarks. The other six packs (**de, uk, br, in, ja, ko**) ship L1 patterns + NER adapters but have no measured recall — treat them as **best-effort** and reach them with an explicit `lang="…"`. They are not auto-selected under `lang="auto"`, whose script-only detection resolves all Latin-script text to `en`. See [language-packs.md](docs/language-packs.md#benchmark-status).

## Performance

Rust core (PyO3), `mode="fast"` — `redact()` p50 over 500 iterations, Apple M1 Max,
Python 3.11. Reproduce with `python tests/benchmark/perf_profile.py`:

| Document | en | zh |
|----------|:--:|:--:|
| Short (141 B en / 175 B zh) | 0.22 ms · ~4,500 docs/sec | 0.34 ms · ~2,900 docs/sec |
| ~1 KB (846 B / 1.4 KB) | 0.97 ms · ~1,030 docs/sec | 2.03 ms · ~490 docs/sec |
| Long (8.5 KB / 14 KB) | 9.4 ms · ~106 docs/sec | 20.3 ms · ~49 docs/sec |

Throughput depends heavily on document size and language, so the workload sizes are
stated rather than a single headline number. Committed run:
[`perf_profile_0.7.16.json`](tests/benchmark/results/perf_profile_0.7.16.json).

Pre-built wheels for all major platforms — no Rust toolchain needed to install:

```
✓ Linux x86_64 (glibc + musl/Alpine)
✓ Linux aarch64 (Raspberry Pi + Alpine ARM)
✓ macOS (Apple Silicon + Intel)
✓ Windows x64
× Python 3.10 / 3.11 / 3.12 / 3.13
```

**Detection accuracy**

| Mode | Precision | Recall | F1 |
|---|---|---|---|
| fast (regex)          | 81.6% | 31.9% | 45.8% |
| ner (+ spaCy)         | 74.8% | 42.9% | 54.5% |
| auto (+ Ollama 32B)   | _skipped this run_ | | |

_ai4privacy en, 500 samples, v0.7.16 run (`tests/benchmark/results/ai4privacy_0.7.16.json`). `auto` mode skipped on the maintainer's hardware — see [benchmark-report.md](docs/benchmark-report.md) for full matrix + reproduction commands._

For context: `fast` mode is high-precision / low-recall by design — it only emits formats it can validate (Luhn, MOD11-2, etc.). Recall comes from `ner` and `auto` at the cost of latency. Pick the mode for your deployment shape (see *Deployment fit* above). [Full benchmarks →](docs/benchmark-report.md) | [Performance →](docs/performance.md)

## North Star

| Dimension | Current (v0.8.1) | Next milestone |
|-----------|:----------------:|:---:|
| **Protected** | 60+ PII types, L1-L3. In the [PRvL](docs/prvl-standard.md) reference suite (24 cases, 42 PII instances per model), the **`default` profile leaked nothing across all four models** — GPT-5, Claude-Opus-4.5, Gemini-2.5-Pro, GLM-4.6. The reversible profiles are not clean: `pseudonym` leaked 1 of 42 on both Claude-Opus-4.5 and GLM-4.6, and `realistic` leaked 1 of 42 on Claude-Opus-4.5. A reference suite is not a guarantee against adversarial input — see prvl-standard.md for the full matrix. Cross-layer hints in 8 langs (zh/en/ja/ko/de/uk/in/br). SHAKE-256 derivation + full-salt entropy + faker identity-pass guard. State export omits salt by default; HTTP server refuses no-auth start; CLI writes O_NOFOLLOW + key files mode 0600; MCP token store TTL+LRU (v0.6.2). Windows CI + property-tested invariants + mutation-tested core (v0.6.3) + perf budget CI gate (v0.6.4) + session-isolation in integrations (v0.6.6) + README pinned-to-doctest + version-sync CI guard (v0.6.6) + compose namespace + pure-layer purity guard (v0.6.7) + seed→salt API rename + PIITypeDef SSOT + Presidio bridge through public redact + 3 new types (v0.6.8) + compose helpers shipped (v0.6.9) + Layer 1 freeze guards + KDF replay vectors + dead code subtract + manylinux digest pin (v0.6.10) + Adapter authoring surface (compose.register_pii_type / PIITypeDef / PatternMatch) + KDF replay edge cases (full-FF salt fix) + Layer 2 signature snapshot (v0.6.11) + HK/Macao travel permits + housing-fund zh L1 coverage (v0.6.12). **v0.7.x — 100% Rust core SSOT**: `argus-redact-core` crate + crates.io publish, with patterns/validators/normalization/replace+restore/fakers/person-scoring + the full L1 redact/restore engine ported to Rust (v0.7.0–v0.7.8) + fail-closed hardening & detection-correctness (v0.7.9–v0.7.10) + in-browser **wasm** build (v0.7.11). **v0.7.12 — quasi-identifier detection breadth**: evidence-gated zh bare-region, occupation, medical condition/allergy, and **hobby** (new type) detection via a shared `evidence_detector` framework, plus a re-identification eval (PRvL+ X-axis); the unreleased `generalize` strategy removed. **v0.7.18–v0.7.20 — guarded restore**: `restore()` gained a deterministic guard (per-call provenance nonce + scope-binding), closing the window where an injected pseudonym in LLM output would silently restore (v0.7.18); a Luhn-valid card PAN that passed through `mode="fast"` verbatim in six of the eight language packs (ja/ko/de/uk/in/br — those with no native card pattern) is now detected regardless of surrounding script (v0.7.19); the whole flow is one public `guarded_restore()` that all five integrations wrap (v0.7.20). **v0.8.0 (breaking)** — `guard=True` is now the default (a bare restore fails closed without an anchor); `residual_personal_data` reports honestly for mask configs; a `unified_prefix` pseudonym-collision that could misattribute a restore is fixed | Adversarial testing |
| **Usable** | PRvL U=100%. Pseudonym codes + realistic mode (zh + en + RFC shared) + per-call strategy overrides + `keep` strategy (whitelisted) + resumable streaming sessions + incremental streaming default + cross-language alias restore (zh ↔ en) | Task-aware guidance |
| **Reversible** | PRvL R by task: reference 100%, extract 50%, creative 0% (by design). Cross-language LLM rewrites (`张三` → `Zhang San`) auto-restored via `result.aliases` + `restore(text, key, aliases=...)` | Task-aware guidance |
| **Compliance** | Meets PIPL Art.28 sensitive PII categories, risk assessment + profiles | PIPL/GDPR/HIPAA (byproduct) |
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

**Guarded round-trip.** `guarded_restore()` binds a restore to the exchange that produced the key. Two deterministic checks: the reply must echo a per-call nonce (**provenance**), and only the pseudonyms *this* call emitted are substituted (**scope**). Both fail closed — pseudonyms are returned unchanged, with a `SecurityWarning`, rather than PII being substituted into an attacker-shaped reply. A supplementary injection heuristic is advisory by default.

```python
from argus_redact import redact, guarded_restore, make_anchor
from argus_redact.compose import prompt_anchor

redacted, key = redact("张三的电话是13812345678", names=["张三"], lang="zh")
anchor = make_anchor(key)          # per-call nonce + the pseudonym scope of this call

system = prompt_anchor(key, lang="zh", anchor=anchor)   # asks the model to echo the nonce
reply = call_llm(redacted, system=system)

restored = guarded_restore(reply, key, redacted=redacted, anchor=anchor)
# strict=True raises RestoreGuardError instead of returning un-restored text
```

As of v0.8.0, `restore(text, key)` defaults to `guard=True` and fails closed without a valid anchor; pass `guard=False` for the legacy unguarded substitution, or use the guarded round-trip with an anchor. [Guarded restore →](docs/security-model.md#guarded-restore)

Meets **PIPL** · **GDPR** · **HIPAA** technical requirements as a byproduct of its privacy-first design. [Details →](docs/security-model.md#regulatory-context)

## Documentation

| | |
|-|-|
| [Getting Started](docs/getting-started.md) | Install, first redact/restore, key management |
| [API Reference](docs/api-reference.md) | All parameters, return types, streaming, structured data |
| [CLI Reference](docs/cli-reference.md) | Commands, flags, serve, MCP server |
| [Configuration](docs/configuration.md) | Per-type strategies, enterprise mask rules, false positive reduction |
| [Sensitive Info](docs/sensitive-info.md) | Taxonomy, privacy levels, roadmap |
| [PII Type Catalog](docs/pii-types.md) | All PII types — strategy, sensitivity, PIPL/GDPR/HIPAA mapping (auto-generated) |
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
