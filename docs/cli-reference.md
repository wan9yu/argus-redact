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
| `-m, --mode` | | `auto` | Detection mode: `auto`, `fast` (regex only), `ner` (regex + NER). |
| `-c, --config` | | *(built-in)* | Path to `redact_config.yaml`. |
| `-s, --seed` | | *(random)* | Fixed seed for deterministic pseudonyms. For testing and reproducibility. |

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

# Custom config
argus-redact redact input.txt -k key.json -c my_config.yaml -o redacted.txt

# Batch: reuse key across multiple files
argus-redact redact file1.txt -k shared.json -o out1.txt
argus-redact redact file2.txt -k shared.json -o out2.txt   # same pseudonyms
argus-redact redact file3.txt -k shared.json -o out3.txt   # same pseudonyms
```

### Key File Behavior

- **File doesn't exist:** new key is generated and written.
- **File exists:** key is loaded, existing mappings reused, new entities appended. File is updated.
- This makes batch processing natural — just point multiple `redact` calls at the same `-k` file.

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
argus-redact v0.1.0

Languages:
  zh  regex (6 patterns) + NER (HanLP)
  en  regex (5 patterns) + NER (spaCy)

Layers:
  1 Pattern (regex)       ✓
  2 Entity (NER)          ✓
  3 Semantic (LLM)        ✗  (pip install argus-redact[full])
```

---

## Exit Codes

All commands use the same exit codes:

| Code | Meaning | Testable |
|------|---------|----------|
| 0 | Success | `echo $?` → 0 |
| 1 | Input file not found | Provide nonexistent input path |
| 2 | Invalid configuration | Provide malformed YAML |
| 3 | Language pack not installed | Use `-l ja` without Japanese pack |
| 4 | Key file not found (`restore` only) | Provide nonexistent `-k` path |
| 5 | Key file invalid / corrupted | Provide non-JSON file as `-k` |

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ARGUS_REDACT_LANG` | `zh` | Default language. |
| `ARGUS_REDACT_CONFIG` | *(built-in)* | Default config file path. |
| `ARGUS_REDACT_LOG_LEVEL` | `WARNING` | `DEBUG`, `INFO`, `WARNING`, `ERROR`. |

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
