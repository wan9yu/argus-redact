# argus-redact Documentation

## Core Concepts

argus-redact has two functions and one data type:

```
redact(plaintext)       → (redacted_text, key)
restore(text, key)      → plaintext
key                     = dict[str, str]   # {"P-00037": "王五", ...}
```

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
| [Architecture](architecture.md) | Three-layer engine internals, data flow |
