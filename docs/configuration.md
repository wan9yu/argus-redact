# Configuration

argus-redact supports per-entity-type configuration to control redaction strategies. Pass a `config` dict to `redact()`. Without config, built-in defaults are used.

## Usage

```python
# Use built-in defaults
redacted, key = redact(text)

# Pass config as dict
redacted, key = redact(text, config={
    "phone": {"strategy": "remove", "replacement": "[TEL]"},
    "person": {"strategy": "pseudonym", "prefix": "PERSON"},
})
```

---

## Full Configuration Schema

```yaml
# redact_config.yaml

# ──────────────────────────────────────
# Per-type redaction strategies
# ──────────────────────────────────────

person:
  strategy: pseudonym           # P-037, P-012 (random codes)
  rotation: per_session         # per_session | fixed
  prefix: "P"                   # Prefix for pseudonym codes
  code_range: [1, 999]          # Range for random code numbers

location:
  strategy: category            # Replace with category label
  labels:                       # Custom category labels (optional)
    cafe: "[cafe]"
    hospital: "[hospital]"
    school: "[school]"
    default: "[location]"       # Fallback if sub-category unknown

organization:
  strategy: pseudonym
  prefix: "O"
  code_range: [1, 999]

phone:
  strategy: mask                # 138****1234
  mask_char: "*"
  visible_prefix: 3             # Show first N digits
  visible_suffix: 4             # Show last N digits

id_number:
  strategy: remove              # Replace entirely
  replacement: "[ID number removed]"

email:
  strategy: mask                # z***@example.com
  mask_char: "*"
  preserve_domain: true         # Keep domain visible

bank_card:
  strategy: mask
  mask_char: "*"
  visible_prefix: 4
  visible_suffix: 4

address:
  strategy: generalize          # 北京市朝阳区三里屯SOHO → [北京市某地址]
  keep_city: true               # Preserve city-level info
  keep_province: true           # Preserve province-level info

date_of_birth:
  strategy: remove
  replacement: "[出生日期已脱敏]"

# ──────────────────────────────────────
# Global settings
# ──────────────────────────────────────

global:
  default_strategy: remove      # Fallback for unrecognized entity types
  default_replacement: "[REDACTED]"
  min_confidence: 0.5           # Ignore detections below this confidence
  dedup: true                   # Deduplicate overlapping entity spans

# ──────────────────────────────────────
# Layer-specific settings
# ──────────────────────────────────────

layers:
  layer_1:
    enabled: true
  layer_2:
    enabled: true
    model: "hanlp"              # NER backend: "hanlp", "spacy", "gliner"
  layer_3:
    enabled: false              # Disabled by default (requires model download)
    model: "qwen2.5-3b-q4"     # Local LLM for semantic detection
    max_tokens: 512             # Max output tokens for LLM inference
    temperature: 0.0            # Deterministic output
```

---

## Strategy Reference

### pseudonym

Replace with a random code. Consistent within a session, rotated across sessions.

```
Input:  "张三和李四在聊天"
Output: "P-037和P-012在聊天"     (session 1)
Output: "P-003和P-071在聊天"     (session 2)
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `prefix` | `str` | `"P"` (person), `"O"` (org) | Code prefix |
| `code_range` | `[int, int]` | `[1, 999]` | Random range for code numbers |
| `rotation` | `str` | `"per_session"` | `"per_session"` — new codes every `redact()` call. `"fixed"` — same code for same entity across sessions (requires persistent key storage). |

**When to use `fixed` rotation:**

Only for purely local pipelines where data never leaves your device. Fixed pseudonyms are linkable across requests — the cloud can build a profile.

### category

Replace with a category label. The original is mapped to its semantic category.

```
Input:  "在星巴克中关村店讨论"
Output: "在[cafe]讨论"
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `labels` | `dict` | *(built-in)* | Map of sub-category → display label. |

Built-in sub-categories for locations: `cafe`, `hospital`, `school`, `park`, `restaurant`, `hotel`, `airport`, `station`, `office`, `residential`.

If the sub-category is unknown, uses `labels.default` or `"[location]"`.

### mask

Partially hide the value, keeping some characters visible.

```
Input:  "13812345678"
Output: "138****5678"
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `mask_char` | `str` | `"*"` | Character used for masking. |
| `visible_prefix` | `int` | `3` | Number of leading characters to keep visible. |
| `visible_suffix` | `int` | `4` | Number of trailing characters to keep visible. |
| `preserve_domain` | `bool` | `true` | (email only) Keep domain part visible. |

### remove

Replace entirely with a label.

```
Input:  "身份证号110101199003071234"
Output: "身份证号[身份证号已脱敏]"

# Multiple same-type entities get numbered suffixes:
Input:  "张三的身份证110101199003071234，李四的身份证220102198805061234"
Output: "...身份证[身份证号已脱敏]，...身份证[身份证号已脱敏①]"
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `replacement` | `str` | `"[REDACTED]"` | The replacement label. Collision suffix (①②③) is appended automatically when multiple entities produce the same label. |

### generalize

Replace with a less specific version of the same information.

```
Input:  "北京市朝阳区三里屯SOHO 1号楼"
Output: "[北京市某地址]"
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `keep_city` | `bool` | `true` | Preserve city name. |
| `keep_province` | `bool` | `true` | Preserve province name. |

---

## Built-in Defaults

When no config file is provided, these defaults are used:

| Entity Type | Strategy | Details |
|------------|----------|---------|
| `person` | `pseudonym` | `per_session`, prefix `P`, range 1-999 |
| `location` | `category` | Built-in sub-category labels |
| `organization` | `pseudonym` | `per_session`, prefix `O`, range 1-999 |
| `phone` | `mask` | Show first 3 + last 4 |
| `id_number` | `remove` | `"[身份证号已脱敏]"` |
| `email` | `mask` | Preserve domain |
| `bank_card` | `mask` | Show first 4 + last 4 |
| `address` | `generalize` | Keep city + province |
| `date_of_birth` | `remove` | `"[出生日期已脱敏]"` |
| *(other)* | `remove` | `"[REDACTED]"` |

---

## Validation

Invalid configuration raises `ConfigError` at call time:

```python
redacted, key = redact(text, config={"person": {"strategy": "invalid"}})
# ConfigError: Unknown strategy 'invalid' for entity type 'person'.
#   Valid strategies: pseudonym, category, mask, remove, generalize
```

Missing fields fall back to defaults — you only need to specify what you want to override:

```yaml
# Only override person strategy, everything else uses defaults
person:
  rotation: fixed
```
