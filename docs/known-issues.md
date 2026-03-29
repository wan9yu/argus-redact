# Known Issues — v0.1.11

## Unresolved

| Issue | Detail | Priority |
|-------|--------|----------|
| Git hash as passport | `A12345678` matches passport regex; lookbehind narrowed but not eliminated | Low |
| Windows untested | encoding="utf-8" applied everywhere, no CI or manual verification | Low |
| HanLP model 500MB | Lightweight NER-only model tested but quality unacceptable (character-level) | Won't fix |
| Ollama cold start 10-20s | Inherent model loading; cached after first call | Won't fix |
| Docker full image ~5GB | Multi-stage build applied; PyTorch dominates | Won't fix |
| CLI coverage ~0% | Subprocess-based tests not tracked by coverage tool | Low |

## Recently Fixed

| Issue | Version | Fix |
|-------|---------|-----|
| restore() injection | v0.1.2 | Single-pass regex replacement |
| Multi-lang NER first-only | v0.1.2 | Loads all adapters |
| Thread safety | v0.1.2 | Lock + contextvars |
| Pseudonym collision | v0.1.4 | Auto-expand range |
| Config dict-only | v0.1.4 | JSON/YAML file path support |
| Regex false positives | v0.1.4 | Prefix + arithmetic context heuristic |
| No streaming | v0.1.4 | StreamingRestorer |
| server.py 7% coverage | v0.1.4 | Starlette TestClient (81%) |
| German / UK / Indian NER | v0.1.4 | spaCy de_core_news_sm, en_core_web_sm, xx_ent_wiki_sm |

No Medium priority issues remaining.
