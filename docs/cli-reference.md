# CLI Reference

## Design

argus-redact CLI follows Unix conventions:

- Text flows through **stdin/stdout** (pipeable)
- The key goes to a **file** via `-k` (like GPG's keyfile)
- One command does one thing

```bash
# The canonical pipeline (three steps — key file bridges redact and restore)
cat input.txt | argus-redact redact -k key.json > redacted.txt
cat redacted.txt | llm "analyze" > llm_output.txt
cat llm_output.txt | argus-redact restore -k key.json
```

---

## redact

Strip PII from text. Text in, redacted text out. Key to file.

```bash
argus-redact redact [input] [options]
```

### Input/Output

| | Source | Description |
|-|--------|-------------|
| **Input** | `[input]` file or stdin | Text to redact. Omit file arg to read stdin. |
| **Output** | stdout or `-o` file | Redacted text. |
| **Key** | `-k` file *(required)* | Session key written to this JSON file. |

### Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `-k, --key` | | *(required)* | Path to write the key file. If file exists, key is loaded and reused (batch mode). |
| `-o, --output` | | stdout | Output file for redacted text. |
| `-l, --lang` | | `zh` | Language(s), comma-separated. `zh`, `en`, `zh,en`. |
| `-m, --mode` | | `fast` | Detection mode: `fast` (regex only), `ner` (regex + NER), `auto` (all layers). |
| `-s, --seed` | | *(random)* | Fixed seed for deterministic pseudonyms. For testing and reproducibility. |
| `-c, --config` | | none | Path to config file (JSON or YAML) with per-type strategy overrides. |
| `--profile` | | none | Compliance profile: `default`, `pipl`, `gdpr`, `hipaa`, or `pseudonym-llm`. |
| `--strategy-override` | | none | Per-type strategy override for `--profile pseudonym-llm`, e.g. `"phone:remove,address:realistic"`. Strategy names: `pseudonym`, `realistic`, `mask`, `remove`, `category`, `name_mask`, `landline_mask`. |
| `--unified-prefix` | | none | Unify all reversible-strategy types under one prefix instead of per-type prefixes, e.g. `--unified-prefix R` → `R-NNNNN`. |

> **Note on `-l uk` / `-l in`.** These are argus locale-pack codes, not
> ISO-639-1 language codes. `uk` selects the **British English** pack
> (ISO-639-1 `uk` is Ukrainian) and `in` selects the **Indian (English)**
> pack (ISO-639-1 `in` is Indonesian, legacy for `id`). Passing `ua` or
> `id` instead raises an error that names the intended pack.

### Examples

```bash
# Pipe mode — most common
cat journal.txt | argus-redact redact -k key.json > redacted.txt

# File mode
argus-redact redact journal.txt -k key.json -o redacted.txt

# Mixed language
cat input.txt | argus-redact redact -k key.json -l zh,en

# Fast mode (regex only, no NER)
cat input.txt | argus-redact redact -k key.json -m fast

# Compliance profile (PIPL / GDPR / HIPAA — text output, same as default)
cat input.txt | argus-redact redact -k key.json --profile pipl

# Batch: reuse key across multiple files
argus-redact redact file1.txt -k shared.json -o out1.txt
argus-redact redact file2.txt -k shared.json -o out2.txt   # same pseudonyms
argus-redact redact file3.txt -k shared.json -o out3.txt   # same pseudonyms
```

### `--profile pseudonym-llm` (JSON output)

The `pseudonym-llm` profile produces realistic-looking but reserved-range fake values
(e.g., `19999...` mobile, `999...` ID, `999999...` bank card) so downstream LLMs can
reason about message structure. It emits **structured JSON** (not plain text) with
three text forms sharing one key dict:

| Field | Purpose |
|-------|---------|
| `audit_text` | Placeholder labels (e.g., `[TEL-79329]`, `P-164`) — for compliance archive |
| `downstream_text` | Realistic reserved-range fake — feed to LLMs |
| `display_text` | Realistic + visible `ⓕ` marker — safe to show to humans |
| `key` | Unified mapping; `argus-redact restore` works on any of the three forms |

```bash
# Get all three forms as JSON
echo "请拨打 13912345678 联系王建国" | \
  argus-redact redact -k key.json --profile pseudonym-llm

# Pipe one form to an LLM
echo "请拨打 13912345678 联系王建国" | \
  argus-redact redact -k key.json --profile pseudonym-llm | \
  jq -r .downstream_text | \
  llm "summarize"

# Round-trip restore (works on any of the three forms)
echo "请拨打 19999123456 联系张明" | argus-redact restore -k key.json

# English (NANP phone, SSN, email)
echo "Call (415) 555-1234, SSN 123-45-6789, email john@company.com" | \
  argus-redact redact -k en-key.json --profile pseudonym-llm -l en
# downstream_text: "Call (555) 555-0142, SSN 999-37-2811, email user42@example.com"

# Per-call strategy override (v0.5.5+) — keep address realistic, force phone
# to placeholder. audit_text always emits placeholders regardless.
echo "电话13912345678 地址北京市朝阳路100号" | \
  argus-redact redact -k key.json --profile pseudonym-llm \
  --strategy-override "phone:remove,address:realistic"
```

> ⚠️ **Do not show `downstream_text` to humans without context** — it looks like
> real data. Use `display_text` for UI rendering or `audit_text` for compliance logs.

### Key File Behavior

- **File doesn't exist:** new key is generated and written.
- **File exists:** key is loaded, existing mappings reused, new entities appended. File is updated.
- This makes batch processing natural — just point multiple `redact` calls at the same `-k` file.

> ℹ️ **Streaming is SDK-only.** The CLI processes one input per invocation. For chunked input with cross-chunk consistency, use `argus_redact.streaming.StreamingRedactor` from Python — see [API reference](api-reference.md#streaming-redact-chunked-input).

---

## restore

Reverse redaction using a key file. Redacted text in, original text out.

```bash
argus-redact restore [input] [options]
```

### Input/Output

| | Source | Description |
|-|--------|-------------|
| **Input** | `[input]` file or stdin | Text with pseudonyms (e.g., LLM output). |
| **Output** | stdout or `-o` file | Restored text with original PII. |
| **Key** | `-k` file *(required)* | Key file from a previous `redact` call. |

### Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `-k, --key` | | *(required)* | Path to key file. |
| `-o, --output` | | stdout | Output file for restored text. |

### Examples

```bash
# Pipe mode
cat llm_output.txt | argus-redact restore -k key.json > restored.txt

# File mode
argus-redact restore llm_output.txt -k key.json -o restored.txt

# Inline
echo "P-037 should talk to P-012" | argus-redact restore -k key.json
# "王五 should talk to 张三"
```

---

## info

Show what's installed and available.

```bash
argus-redact info
```

### Output

```
argus-redact v0.8.14

Languages:
  zh  Chinese    regex (14+ patterns) + NER
  en  English    regex (5 patterns) + NER
  ja  Japanese   regex (4 patterns) + NER
  ko  Korean     regex (4 patterns) + NER
  de  German     regex (4 patterns) + NER
  uk  British    regex (5 patterns) + NER
  in  Indian     regex (4 patterns) + NER
  br  Brazilian  regex (3 patterns)

Layers:
  1 Pattern (regex)       ✓
  2 Entity (NER)          ✓
  3 Semantic (Ollama)     ✓
```

---

## serve

Start an HTTP API server.

```bash
pip install argus-redact[serve]

argus-redact serve                    # default port 8000
argus-redact serve --port 9000        # custom port
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | `127.0.0.1` | Bind address (localhost only; use `--host 0.0.0.0` to expose) |
| `--port` | `8000` | Port number |

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/redact` | Redact PII from text |
| POST | `/restore` | Restore redacted text with key |
| GET | `/info` | Version and capabilities |
| GET | `/health` | Health check |

#### POST `/redact` parameters

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `text` | `string` | *(required)* | Text to redact |
| `lang` | `string` | `"zh"` | Language code(s), comma-separated |
| `mode` | `string` | `"fast"` | Detection mode: `fast`, `ner`, `auto` |
| `report` | `bool` | `false` | Return a full `RedactReport` with risk assessment |
| `profile` | `string` | `null` | Compliance profile: `"default"`, `"pipl"`, `"gdpr"`, `"hipaa"` |
| `types` | `list[string]` | `null` | Only detect these PII types (e.g. `["phone", "email"]`). A bare `string` is rejected with 400, not silently treated as a character set *(v0.8.0+)*. |
| `types_exclude` | `list[string]` | `null` | Exclude these PII types from detection. Same bare-`string` rejection as `types` *(v0.8.0+)*. |

A malformed or empty request body returns 400 (`{"error": "request body must be valid JSON"}`), not a 500.

#### POST `/restore` parameters *(guard-by-default, v0.8.0+)*

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `text` | `string` | *(required)* | Text containing pseudonyms (typically an LLM reply). |
| `key` | `object` | `{}` | The key from `/redact`'s response. A non-object `key` (string, list, number) is rejected with 400. |
| `anchor` | `{"nonce": string, "scope": [string, ...]} \| null` | `null` | Optional provenance/scope anchor. Reconstructed into the same shape `make_anchor(key)` produces. Required for the guard to pass — with `guard` true and no `anchor`, restore fails closed. |
| `guard` | `bool` | `true` | `true` (default) runs the deterministic provenance (P) + scope (S) checks; a request with no `anchor` fails closed. `false` runs a plain, unchecked restore — the explicit opt-out for text that never left your process. |
| `strict` | `bool` | `false` | When `true` and `guard` is `true`, a security event returns 400 with `{"error": ..., "security_events": [...]}` instead of an un-restored 200. |
| `aliases` | `{fake: [alt, ...]} \| null` | `null` | *(v0.8.10+)* Optional alternate-transliteration map — mirrors `restore(text, key, aliases=...)`. Each value must be a list of strings; a bare string is rejected with 400 (it would otherwise iterate character-by-character). |
| `display_marker` | `string \| null` | `null` | *(v0.8.10+)* Optional marker (e.g. `"ⓕ"`) stripped from `text` before key lookup — mirrors `restore(text, key, display_marker=...)`. |

The response always includes a `security_events` array (empty on a clean restore):

```jsonc
// clean restore
{"restored": "王五 should help 张三", "security_events": []}

// fail-closed — no anchor supplied
{"restored": "P-037 should help P-012", "security_events": [
  {"type": "security", "reason_code": "guard_no_anchor", "count": 2, "detail": "no anchor provided"}
]}
```

**Before v0.8.0**, `/restore` defaulted to `guard: null` (the legacy unchecked path) and had no `anchor` field at all. A caller that does not send `anchor` and does not explicitly send `"guard": false` will now get a fail-closed (un-restored) response instead of a plain substitution — update callers accordingly.

---

## MCP Server

Run argus-redact as an [MCP](https://modelcontextprotocol.io) tool server for Claude Desktop, Cursor, or any MCP-compatible client.

```bash
pip install argus-redact[mcp]
python -m argus_redact.integrations.mcp_server
```

### Claude Desktop Configuration

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

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

### Tools

| Tool | Description |
|------|-------------|
| `redact` | Redact PII from text. Returns JSON with the redacted text, a `key_token`, **and an `anchor_prompt` you must inject into the LLM's system prompt**. |
| `restore` | Restore redacted text using `key_token`. Guard-by-default *(v0.7.20+)*: verifies the anchor nonce and the pseudonym scope, and runs the injection heuristic. |
| `info` | Show version and installed capabilities. |
| `assess` | Privacy risk score + entities found. |

### Key handling

The `redact` tool mints a **`key_token`** — a process-scoped reference to the key dict — instead of returning the raw key. This keeps the key out of the LLM's context window so a malicious prompt cannot exfiltrate the mapping back to the user.

Tokens live in the MCP server process, are bounded in number, and expire after an idle period. Restart invalidates them — re-run `redact` to obtain a fresh token if you see `Token not found or expired`.

### `redact` → you MUST inject `anchor_prompt`

The `redact` response has **three** fields:

```jsonc
// redact response
{
  "redacted": "P-12345 的电话是 138****5678",
  "key_token": "Aq1f3-Xb9...",   // pass to restore
  "anchor_prompt": "..."          // pass to the LLM as a system message
}
```

`anchor_prompt` is a system-prompt addendum carrying a **per-call nonce** that the model is instructed to echo back in its reply. It is empty (`""`) when no PII was detected.

**If you do not put `anchor_prompt` into the LLM's system prompt, your pipeline is broken — quietly.** The model never echoes the nonce; `restore` cannot establish that the text it is given actually came from the model it anchored; the guard fails closed; and `restore` hands back the text **un-restored**, with the pseudonyms still in it. You get a plausible-looking string that simply never had the originals substituted. This is the single most common way to misuse this server.

The intended sequence:

1. Call `redact` → keep `key_token`, send `redacted` to the LLM, and pass `anchor_prompt` as (or appended to) the **system** message.
2. Take the LLM's reply verbatim — including the echoed nonce; do not strip it.
3. Call `restore` with that reply and the `key_token`. It strips the nonce for you.

### `restore` — guard-by-default *(v0.7.20+)*

```jsonc
// restore call
{
  "text": "...",                 // the LLM's reply, verbatim
  "key_token": "Aq1f3-Xb9...",
  "strict": false                 // optional, default false
}
```

Before v0.7.20 this tool did a plain key-token substitution with no checks at all. It now runs the full guarded flow:

- **Provenance (P) + scope (S) — deterministic.** The nonce from `anchor_prompt` must appear in `text`, and only pseudonyms bound to that call's scope are restored. If the nonce is missing, restore is **fail-closed**: the text comes back un-restored, nothing substituted.
- **Injection heuristic (H) — advisory.** The server retains the redacted prompt (pseudonyms only) alongside the token, which lets `restore` compare the reply against it and flag suspicious pseudonym use. H is a heuristic: by default it *reports*, it does not block.

The response gains a `security_events` field whenever anything fired (absent on a clean restore):

```jsonc
// restore response — guard tripped
{
  "restored": "P-12345 的电话是 138****5678",   // NOTE: un-restored, guard failed closed
  "security_events": [
    {"type": "security", "reason_code": "provenance_failed", "count": 2,
     "detail": "nonce absent from response"}
  ]
}
```

Reason codes: `guard_no_anchor` / `provenance_failed` (nothing was substituted), `out_of_scope_pseudonym` (those pseudonyms were withheld; the in-scope ones were restored), `injection_suspected` (advisory — the restore **did** proceed and originals *were* substituted).

**Always check for `security_events`.** A fail-closed `restored` string is shape-identical to a successful one; the events field is how you tell them apart.

Pass **`strict: true`** to turn every event into a hard error instead — the tool call fails rather than returning, and no original is substituted on a suspected injection. Use it when a silently-degraded restore is worse for you than a failed one.

These checks raise the cost of forging, replaying or widening a model reply, and they surface what they catch; they are not a guarantee against a determined adversary. See `docs/security-model.md` for the threat model and its limits.

---

## Exit Codes

All commands use the same exit codes:

| Code | Meaning | Testable |
|------|---------|----------|
| 0 | Success | `echo $?` → 0 |
| 1 | Input file not found | Provide nonexistent input path |
| 2 | Invalid CLI argument *(v0.8.0+)* | `--seed abc` (not an integer); `--profile pseudonym-llm` with no `--seed`; malformed or misapplied `--strategy-override` |
| 3 | Language pack not installed, or `redact()` rejected the request (bad `lang`/`mode`/`profile`/`config` combination) | Use `-l ja` without Japanese pack |
| 4 | Key file not found (`restore` only) | Provide nonexistent `-k` path |
| 5 | Key file invalid / corrupted | Provide non-JSON file as `-k` |

*(v0.8.0+)* Argument and detection errors that used to surface as a raw Python traceback
(`--seed abc`, `--profile pseudonym-llm` without `--seed`, a trailing comma in
`--lang`) now print a clean `Error: ...` to stderr and exit non-zero instead.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ARGUS_API_KEY` | *(unset)* | Bearer token for HTTP server auth |
| `ARGUS_PERF_LOG` | *(unset)* | Path to JSONL file for performance telemetry |
| `ARGUS_PERF_SLOW_MS` | `50` | Slow call threshold (ms), always logged |
| `ARGUS_PERF_SAMPLE` | `0.01` | Sampling rate for fast calls (0.0-1.0) |

---

## Full Pipeline Example

A complete workflow: journal entry → redact → LLM summary → restore.

```bash
# 1. Redact the journal
cat ~/journal/2026-03-24.txt \
  | argus-redact redact -k /tmp/session.json -l zh,en \
  > /tmp/redacted.txt

# 2. Send to LLM (using any CLI tool — llm, sgpt, etc.)
cat /tmp/redacted.txt \
  | llm "Summarize this journal entry. Highlight action items." \
  > /tmp/llm_output.txt

# 3. Restore original names
cat /tmp/llm_output.txt \
  | argus-redact restore -k /tmp/session.json \
  > ~/journal/2026-03-24_summary.txt

# 4. Clean up key
rm /tmp/session.json
```

**Why not a single pipe?** Unix pipes start all processes simultaneously. `restore` would try to read `key.json` before `redact` finishes writing it. Always use separate steps or temp files as shown above.
