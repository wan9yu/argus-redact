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

## pseudonym-llm Limitations

These are inherent properties of the realistic-redaction design, not bugs to fix:

| Limitation | Detail | Mitigation |
|------------|--------|------------|
| **199-99 mobile sub-segment requires annual review** | The `199-99-XXXXXX` reserved range relies on this sub-segment remaining unassigned by 工信部. Numbering plans are revised periodically. | Re-verify against MIIT public allocations annually; if assigned, switch to a different unassigned sub-segment via configuration. |
| **Realistic-mode output must not be re-redacted** | Re-redacting realistic output would silently corrupt the key dict (the same fake value mapping to two different originals). | `redact_pseudonym_llm` raises `PseudonymPollutionError` by default. Call `restore()` first, then re-redact if needed. |
| **Cross-language LLM rewrites not auto-restored** | If an LLM rewrites a fake value across languages (e.g., `张明` → `Zhang Ming`), `restore()` won't match it back. Word-boundary matching covers `张明先生` but not transliteration. | Document the LLM contract: ask the model to preserve fake values verbatim. Out-of-scope: add `aliases` to the key for cross-language equivalents. |
| **Realistic data must not be stored as business truth** | `downstream_text` looks like real PII but is synthetic by design. Storing it in customer/business records causes data pollution that's hard to detect post-hoc. | Always pair `downstream_text` with the key dict; never persist `downstream_text` in business databases. Use `audit_text` for compliance archives. |
| **`StreamingRedactor` requires complete logical-unit chunks** | v0.5.2 streaming requires each `feed()` chunk to be a complete sentence / paragraph / turn. Entities that cross chunk boundaries (e.g., a phone number split across two chunks) are NOT detected and pass through unredacted. | Split inputs at logical boundaries before feeding. True byte-level streaming with realistic-mode requires incremental detection and is roadmapped for a later release. |

## Recently Fixed

| Issue | Version | Fix |
|-------|---------|-----|
| en/person realistic required NER | v0.5.3 | `lang/en/person.py` adds Census surname + SSA given-name list for fast-mode detection |
| Pollution scanner false-positive on canonical names | v0.5.3 | `reserved_names` parameter on `redact_pseudonym_llm` / `StreamingRedactor` lets caller override canonical fake-name tables |
| SSN validation incomplete (666/900-999) | v0.4.10 | Reject invalid area codes per SSA rules |
| Email allows consecutive dots | v0.4.10 | Validate function rejects `..` and leading/trailing dots |
| Age matches 999 | v0.4.10 | Validate function limits to 0-149 |
| 15-digit old ID not detected | v0.4.10 | Separate pattern for pre-1999 format (6+6+3 digits) |
| Unicode email not detected | v0.4.10 | CJK-only local-part pattern (RFC 6531) |
| ID number false positive on 18-digit orders | v0.4.8 | Restore MOD 11-2 checksum validation |
| Near-miss info lost | v0.4.8 | match_patterns returns (entities, near_misses) tuple |
| Report generation removed | v0.4.9 | Use redact(report=True) for raw data, downstream generates reports |
| Unicode bypass (fullwidth, ZWSP, ZWJ, RTL) | v0.4.4 | NFKC normalization + invisible char stripping before regex |
| Input >1MB DoS | v0.4.4 | Input size limit (1MB), rejects with clear error |
| ID number false negative on typos | v0.4.4 | Relaxed checksum: format-valid IDs accepted even with wrong check digit |
| HTTP config path injection | v0.4.4 | Reject config as file path string via HTTP (dict only) |
| NFKC offset mapping bug | v0.4.4 | Per-char normalize instead of broken heuristic |
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
