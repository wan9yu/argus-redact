# Known Issues

## Unresolved

| Issue | Detail | Priority |
|-------|--------|----------|
| Windows untested | encoding="utf-8" applied everywhere, no CI or manual verification | Low |
| HanLP model 500MB | Lightweight NER-only model tested but quality unacceptable (character-level) | Won't fix |
| Ollama cold start 10-20s | Inherent model loading; cached after first call | Won't fix |
| Docker full image ~5GB | Multi-stage build applied; PyTorch dominates | Won't fix |
| hints 语言覆盖 | self_reference/command detection only covers zh+en; other langs fall back to defaults | Low |
| MCP key exposure | MCP server returns key in tool response; key visible in Claude Desktop context | Medium |

## Recently Fixed

| Issue | Version | Fix |
|-------|---------|-----|
| HTTP server default 0.0.0.0 | v0.4.3 | Changed to 127.0.0.1 |
| mask strategy leaks partial PII | v0.4.3 | Compliance profiles (pipl/gdpr/hipaa) force remove strategy |
| restore() injection risk | v0.4.3 | `check_restore_safety()` detects pseudonym amplification |
| In-memory key residue | v0.4.3 | `wipe_key()` + limitation documented in security-model.md |
| L3 silent failure | v0.4.3 | layer_3_status in stats (ok/skipped/error) |
| NER silent failure | v0.4.3 | mode="ner" warns when no models available; layer_2_status in stats |
| Passport false positive (version numbers) | v0.4.3 | Keyword-triggered pattern (requires "护照" prefix) |
| Person name false positive ("段代码") | v0.4.3 | Evidence-gating: requires structural signal |
| German phone too loose | v0.4.3 | Structured format + digit count validation |
| `import secrets` displaced | v0.4.2 | Moved back to module level |
