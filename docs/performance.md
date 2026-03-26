# Performance

## Latency Budget

A typical `redact() → LLM → restore()` pipeline:

```
redact()                              LLM API call              restore()
┌─────────────────────────┐     ┌──────────────────────┐     ┌──────────┐
│ L1    L2       L3       │     │                      │     │          │
│ regex  NER     LLM      │     │   500-3000ms         │     │  <1ms    │
│ <1ms  10-100ms 200-2000ms│     │   (network + inference)│    │          │
└─────────────────────────┘     └──────────────────────┘     └──────────┘
         ↑                                ↑                       ↑
    1-2100ms                         500-3000ms                  <1ms
```

**The cloud LLM call dominates.** argus-redact adds 1-100ms in typical use (Layer 1+2), which is noise compared to a 1-3 second API call.

## Per-Layer Breakdown

> **Note:** Latency numbers below are from actual benchmarks on Apple M1 Max and Raspberry Pi Zero 2W. See README for summary.

| Layer | What it does | Estimated latency | Scales with |
|-------|-------------|----------------|-------------|
| Layer 1 (regex) | Pattern matching | < 1ms | Text length (linear) |
| Layer 2 (NER) | Model inference | 10-100ms | Text length (chunked at 512 tokens) |
| Layer 3 (semantic) | Small LLM inference | 200-2000ms | Text length + model size |
| Key generation | Random codes + dict | < 0.1ms | Entity count |
| `restore()` | String replacement | < 1ms | Text length × entity count |

### First-call overhead

NER models (Layer 2) need to be loaded into memory on first use:

| Model | Load time | Memory |
|-------|-----------|--------|
| HanLP (Chinese NER) | 2-5s | ~500MB |
| spaCy en_core_web_sm | 1-2s | ~50MB |
| Layer 3 LLM (Qwen 1.5B Q4) | 3-8s | ~1GB |

After first load, models stay cached in memory for subsequent calls.

**CLI impact:** Each CLI invocation is a new process → model reloads every time. Mitigations:

1. **`mode="fast"` (regex only)** — no model loading, < 1ms total. Good default for CLI pipes.
2. **Python API** — models load once, cached across calls within the same process.
3. **Future: `argus-redact serve`** — daemon mode, models stay loaded, CLI communicates via Unix socket.

## Text Scale

### Single document

| Text length | Layer 1 | Layer 2 | Layer 3 |
|-------------|---------|---------|---------|
| 100 chars | < 1ms | ~15ms | ~300ms |
| 1,000 chars | < 1ms | ~30ms | ~500ms |
| 10,000 chars | ~1ms | ~100ms | ~2s |
| 100,000 chars | ~5ms | ~500ms | ~15s |

Layer 2 and 3 process text in chunks (512 tokens). Latency scales linearly with chunk count.

`redact()` accepts any text length. Internally:
- Layer 1 runs on the full text (regex is fast)
- Layer 2 splits into sentences, batches into 512-token chunks, runs NER per chunk
- Layer 3 processes per chunk with overlap to preserve cross-sentence context

### Batch processing

For bulk workloads (thousands of documents), throughput matters more than latency:

| Documents | Layer 1 only | Layer 1+2 | All layers |
|-----------|-------------|-----------|------------|
| 100 docs × 1K chars | ~50ms | ~3s | ~50s |
| 1,000 docs × 1K chars | ~500ms | ~30s | ~8min |
| 10,000 docs × 1K chars | ~5s | ~5min | ~80min |

`restore()` is always fast — pure string replacement, < 1ms per document regardless of layers used.

## Mode Selection Guide

| Scenario | Recommended mode | Why |
|----------|-----------------|-----|
| Single text → cloud LLM | `auto` (default) | LLM API latency dwarfs everything. Use best detection. |
| CLI pipe, one-shot | `fast` | No model loading overhead. Catches phone/ID/email/cards. |
| Batch 1K+ documents | `ner` (Layer 1+2) | Good balance. Layer 3 too slow for bulk. |
| Real-time stream | `fast` | Sub-millisecond. |
| Maximum privacy | `auto` with Layer 3 | Catches implicit PII that regex and NER miss. |

```python
# Choose mode based on your scenario
redacted, key = redact(text, mode="fast")   # regex only, < 1ms
redacted, key = redact(text, mode="ner")    # regex + NER, 10-100ms
redacted, key = redact(text, mode="auto")   # all layers, 10-2000ms
```

## Memory Usage

| Component | Memory | When |
|-----------|--------|------|
| Core (regex + key) | ~5MB | Always |
| HanLP Chinese NER | ~500MB | When `lang="zh"` with Layer 2 |
| spaCy English NER | ~50MB | When `lang="en"` with Layer 2 |
| Qwen 1.5B Q4 (Layer 3) | ~1GB | When Layer 3 enabled |
| Key (in-memory) | ~1KB per 100 entities | Per session |

Minimum viable: **~5MB** (regex only, `mode="fast"`).

Full stack: **~1.5GB** (Chinese NER + Layer 3 LLM).

## Benchmark Suite

We evaluate detection quality against 9 public PII datasets. Run benchmarks with:

```bash
pip install datasets
python -m tests.benchmark all --mode fast --limit 1000     # all datasets, regex only
python -m tests.benchmark ai4privacy --mode fast,ner        # compare modes
python -m tests.benchmark wikiann --lang zh --limit 500     # Chinese NER evaluation
```

Results are saved as JSON snapshots for regression tracking. See [Benchmarks](../tests/benchmark/README.md) for full documentation.

## Implementation Language Strategy

v0.1 is Python. Performance-critical paths are candidates for Rust rewrite (via PyO3):

| Component | Language | Rationale |
|-----------|----------|-----------|
| Layer 1 regex engine | Python → **Rust** | 100x faster regex on bulk workloads |
| `restore()` string replacement | Python → **Rust** | Critical for streaming and bulk |
| Key management | Python → **Rust** | Memory safety — no GC residue of sensitive mappings |
| Layer 2/3 model inference | Python | Bottleneck is the model, not the language |
| CLI binary | Python → **Rust** | Eliminates ~100ms Python startup overhead |
| API / glue | Python | Ecosystem compatibility (pip, integrations) |

Target architecture: **Rust core + Python bindings (PyO3)**, like ruff or polars.

```
┌─────────────────────────────────┐
│         Python API              │  ← pip install argus-redact
│   redact() / restore()          │
├─────────────────────────────────┤
│       PyO3 bindings             │
├─────────────────────────────────┤
│       Rust core                 │  ← regex, replacement, key management
│  ┌──────┐ ┌────────┐ ┌──────┐  │
│  │regex │ │replace │ │ key  │  │
│  │engine│ │engine  │ │mgmt  │  │
│  └──────┘ └────────┘ └──────┘  │
└─────────────────────────────────┘
```

This gives:
- **Python users**: `pip install argus-redact`, same API, faster internals
- **Rust users**: use the core crate directly
- **CLI users**: optional standalone Rust binary, no Python runtime needed
