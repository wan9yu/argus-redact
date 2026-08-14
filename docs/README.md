# argus-redact Documentation

## Core Concepts

argus-redact has two functions and one data type:

```
redact(plaintext)              → (redacted_text, key)
restore(text, key, anchor=...) → original text   # guarded by default since v0.8.0
key                            = dict[str, str]   # {"P-00037": "王五", ...}
```

Since v0.8.0 `restore()` defaults to `guard=True`: pass an `anchor` from
`make_anchor(key)` (or `guarded_restore(...)`) so the round-trip fails closed on a
tampered reply. A bare `restore(text, key)` with no anchor now fails closed;
`guard=False` is the explicit opt-out for a plain substitution.

Everything else is optional.

## Guides

| Document | Description |
|----------|-------------|
| [Getting Started](getting-started.md) | Install, first redact/restore, key management |
| [Configuration](configuration.md) | Strategies, enterprise mask rules, false positive reduction |
| [Security Model](security-model.md) | Threat model, per-message keys, compliance (PIPL/GDPR/HIPAA) |

## Reference

| Document | Description |
|----------|-------------|
| [Python API](api-reference.md) | All parameters, return types, streaming, structured data |
| [CLI Reference](cli-reference.md) | Commands, flags, serve, setup, MCP server |
| [Performance](performance.md) | Latency, throughput, benchmark results |
| [Benchmark Report](benchmark-report.md) | Full comparison: argus-redact vs Presidio across 3 datasets |
| [Benchmarks](../tests/benchmark/README.md) | Evaluation framework with 9 public PII datasets |
| [Comparison](comparison.md) | vs Presidio, Tonic Textual, anonLLM feature matrix |

## Integration

| Document | Description |
|----------|-------------|
| [LLM Pipelines](integration-llm.md) | OpenAI, Anthropic, Ollama, local LLM patterns |
| [Frameworks](integration-frameworks.md) | LangChain, LlamaIndex, FastAPI, Presidio bridge |

## Extending

| Document | Description |
|----------|-------------|
| [Language Packs](language-packs.md) | Adding new languages (regex, NER adapter, semantic prompts) |
| [Sensitive Info Taxonomy](sensitive-info.md) | Four levels of sensitivity, compliance profiles, roadmap |
| [Architecture](architecture.md) | Three-layer engine internals, data flow, PII type registry |
| [Known Issues](known-issues.md) | Current limitations and recently fixed issues |
