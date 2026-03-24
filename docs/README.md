# argus-redact Documentation

## Core Concepts

argus-redact has two functions and one data type:

```
redact(plaintext)       → (redacted_text, key)
restore(text, key)      → plaintext
key                     = dict[str, str]   # {"P-037": "王五", ...}
```

Everything else is optional.

## Guides

| Document | Description |
|----------|-------------|
| [Getting Started](getting-started.md) | Install, first redact/restore, key management |
| [Configuration](configuration.md) | Redaction strategies, per-entity-type settings |
| [Security Model](security-model.md) | Threat model, what's protected, what's not |

## Reference

| Document | Description |
|----------|-------------|
| [Python API](api-reference.md) | `redact()`, `restore()`, return types, all parameters |
| [CLI Reference](cli-reference.md) | Commands, flags, stdin/stdout, `-k` keyfile |
| [Performance](performance.md) | Latency budgets, text scale, memory, Rust strategy |

## Integration

| Document | Description |
|----------|-------------|
| [LLM Pipelines](integration-llm.md) | OpenAI, Anthropic, local LLM patterns |
| [Frameworks](integration-frameworks.md) | LangChain, LlamaIndex, FastAPI middleware |

## Extending

| Document | Description |
|----------|-------------|
| [Language Packs](language-packs.md) | Adding new languages (regex, NER adapter, semantic prompts) |
| [Architecture](architecture.md) | Three-layer engine internals, data flow |
