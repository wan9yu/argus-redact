# Getting Started

## Install

```bash
pip install argus-redact[zh]          # Chinese NER (recommended for Chinese text)
```

Other install options:

```bash
pip install argus-redact              # core (regex only, zero heavy deps)
pip install argus-redact[zh]          # + Chinese NER (HanLP)
pip install argus-redact[en]          # + English NER (spaCy)
pip install argus-redact[ja]          # + Japanese NER (spaCy)
pip install argus-redact[ko]          # + Korean NER (spaCy)
pip install argus-redact[full]        # + all NER + semantic layer
pip install argus-redact[presidio]   # + Presidio bridge
pip install argus-redact[mcp]        # + MCP server
pip install argus-redact[serve]      # + HTTP API server
```

**First-run model download:** NER models (~500MB for Chinese HanLP, ~50MB for English/Japanese/Korean spaCy) are downloaded on first `redact()` call, then cached locally. For offline use, run `argus-redact setup -l zh,en` while connected.

### Platform Support

| Platform | Status |
|----------|--------|
| macOS ARM/Intel | ✓ Tested |
| Linux x86_64 | ✓ CI (Python 3.10-3.13) |
| Linux ARM (Raspberry Pi) | ✓ Tested |
| Windows | Untested (encoding fixes applied) |

## Core Concept

argus-redact works like encryption:

```
encrypt(plaintext)       → (ciphertext, key)     # GPG
redact(plaintext)        → (redacted_text, key)   # argus-redact

decrypt(ciphertext, key) → plaintext              # GPG
restore(text, key)       → plaintext              # argus-redact
```

The key is a plain dict mapping pseudonyms to originals. Treat it like a private key.

## First Redaction

With core install (`pip install argus-redact`, regex only):

```python
from argus_redact import redact, restore

redacted, key = redact("张三的手机号是13812345678，身份证号是110101199003071234")

print(redacted)
# "P-042的手机号是138****5678，身份证号是[身份证号已脱敏]"
# 张三 IS detected — nearby phone/ID signals boost name confidence

print(key)
# {
#     "P-042": "张三",
#     "138****5678": "13812345678",
#     "[身份证号已脱敏]": "110101199003071234",
# }
```

**Rule of thumb:** Core install catches structured PII (phone, ID, email, cards) and person names near them. NER install adds standalone person/location/organization names. Layer 3 adds implicit PII.

## Redact → LLM → Restore

```python
from argus_redact import redact, restore
from openai import OpenAI

client = OpenAI()

# Step 1: redact
original = "王五和张三在星巴克讨论了去阿里面试的事，张三很紧张"
redacted, key = redact(original)
# "P-037和P-012在[咖啡店]讨论了去[某公司]面试的事，P-012很紧张"
# Note: 张三 appears twice → same P-012 within this session

# Step 2: send to LLM
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[
        {"role": "system", "content": "You are a career coach."},
        {"role": "user", "content": redacted},
    ],
)
llm_output = response.choices[0].message.content
# "P-012's nervousness is normal. P-037 should help P-012
#  prepare mock interviews for [某公司]."

# Step 3: restore
restored = restore(llm_output, key)
# "张三's nervousness is normal. 王五 should help 张三
#  prepare mock interviews for 阿里."
```

The LLM never sees real names, locations, or organizations.

## Per-Message Random Keys

Every `redact()` generates a fresh key:

```python
_, key1 = redact("王五和张三讨论了面试")  # key1: {P-037: 王五, P-012: 张三}
_, key2 = redact("王五和张三讨论了面试")  # key2: {P-003: 王五, P-071: 张三}
```

Two calls, two completely different pseudonym sets. The cloud cannot link them. See [Security Model](security-model.md) for the full threat analysis.

## Reusing a Key (Batch)

When multiple texts share context, reuse the same key:

```python
text1, key = redact("王五给张三发了面试资料")
text2, key = redact("张三看完后给王五回了消息", key=key)  # always capture updated key
text3, key = redact("两人约了周五在星巴克讨论", key=key)

# All three use the same pseudonyms:
# text1: "P-037给P-012发了面试资料"
# text2: "P-012看完后给P-037回了消息"     ← consistent
# text3: "两人约了周五在[咖啡店]讨论"      ← 星巴克 added to key in this call
```

Always capture the returned key — it may contain new entities discovered in later texts.

No key = new session. Pass key = same session. No separate batch API.

## Mixed Language

Real text mixes languages:

```python
redacted, key = redact(
    "王五给John发了邮件，讨论了Apple的offer，电话13812345678",
    lang=["zh", "en"],
    mode="ner",
)
# "P-037给P-012发了邮件，讨论了[某公司]的offer，电话[手机号已脱敏]"
```

Chinese names → Chinese NER. English names → English NER. Phone patterns → regex. Merged automatically. Default `mode="fast"` would catch the phone via regex and `王五` via L1b proximity scoring, but not `John` or `Apple` — standalone English entities need `mode="ner"` or a `names=[...]` hint.

## Detection Modes

`mode="fast"` is the **default** — regex + L1b person scoring only, zero model loading, sub-ms:

```python
redacted, key = redact("张三的手机号是13812345678")    # mode="fast" implicit
# "P-042的手机号是138****5678"
# 张三 detected via L1b — "的手机号" suffix + phone proximity are strong signals
```

Opt into heavier layers when you need them:

```python
redacted, key = redact(text, mode="ner")    # + NER for standalone names/locations/orgs
redacted, key = redact(text, mode="auto")   # + semantic LLM for implicit PII (requires Ollama)
```

`mode="ner"` and `mode="auto"` require installed language packs (`pip install argus-redact[zh]`, `[en]`, ...) and, for `auto`, a local Ollama server. Fast mode has zero heavy deps.

## Key Management

The key is a plain dict. Save and load it however you want:

```python
import json

# Save
redacted, key = redact(text)
with open("key.json", "w") as f:
    json.dump(key, f)

# Load and restore later
with open("key.json") as f:
    key = json.load(f)
restored = restore(llm_output, key)
```

Or pass a file path directly:

```python
redacted, key = redact(text, key="key.json")    # writes key.json
restored = restore(llm_output, key="key.json")   # reads key.json
```

**Security rules:**
- Key files contain plaintext identity mappings. Protect them like private keys.
- Delete key files after restoration if you don't need them.
- In-memory keys are garbage collected when variables go out of scope.
- Never commit key files to version control.

## CLI

```bash
# Redact: text through pipe, key to file
cat journal.txt | argus-redact redact -k key.json > redacted.txt

# Restore: key from file, text through pipe
cat llm_output.txt | argus-redact restore -k key.json > restored.txt

# With file arguments
argus-redact redact input.txt -o redacted.txt -k key.json
argus-redact restore llm_output.txt -o restored.txt -k key.json

# Mixed language
cat input.txt | argus-redact redact -k key.json -l zh,en > redacted.txt

# Fast mode (regex only)
cat input.txt | argus-redact redact -k key.json -m fast > redacted.txt
```

## Safety Tips

```python
from argus_redact import check_restore_safety, wipe_key

# Before restoring LLM output, check for prompt injection
warnings = check_restore_safety(redacted, llm_output, key)
if warnings:
    print("Suspicious LLM output:", warnings)
else:
    restored = restore(llm_output, key)

# Clear key from memory when done
wipe_key(key)
```

For compliance (PIPL/GDPR/HIPAA), use profiles — they enforce stricter strategies:

```python
redacted, key = redact(text, profile="pipl")  # no partial masking
```

## Performance Monitoring

```bash
# Enable per-call timing logs
ARGUS_PERF_LOG=perf.jsonl python my_app.py

# Slow calls (>50ms) always logged, fast calls 1% sampled
# Analyze: jq 'select(.slow)' perf.jsonl
```

## Next Steps

- [Python API Reference](api-reference.md) — all parameters, return types, edge cases
- [Configuration](configuration.md) — customize strategies per entity type
- [Security Model](security-model.md) — threat model, what's protected and what's not
- [LLM Integration](integration-llm.md) — patterns for OpenAI, Anthropic, local models
