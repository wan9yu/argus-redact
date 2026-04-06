# Known Issues

## Unresolved

| Issue | Detail | Priority |
|-------|--------|----------|
| Windows untested | encoding="utf-8" applied everywhere, no CI or manual verification | Low |
| HanLP model 500MB | Lightweight NER-only model tested but quality unacceptable (character-level) | Won't fix |
| Ollama cold start 10-20s | Inherent model loading; cached after first call | Won't fix |
| Docker full image ~5GB | Multi-stage build applied; PyTorch dominates | Won't fix |

## Recently Fixed

| Issue | Version | Fix |
|-------|---------|-----|
| Passport false positive (git hash, version numbers) | v0.4.3 | Keyword-triggered pattern (requires "护照" prefix) |
| Person name false positive ("段代码", "方案不") | v0.4.3 | Evidence-gating: requires structural signal |
| German phone too loose | v0.4.3 | Structured format + digit count validation |
| `import secrets` displaced | v0.4.2 | Moved back to module level |
