# Configuration

argus-redact supports per-entity-type configuration to control redaction strategies. Pass a `config` dict to `redact()`. Without config, built-in defaults are used.

## Default redacted output by strategy

| Strategy | Example output | Reversible |
|---|---|:---:|
| `pseudonym` | `P-83811` (random code with type prefix) | ✓ |
| `realistic` (`pseudonym-llm` profile) | `19999123456` (reserved-range fake) | ✓ |
| `remove` | `ID-89732` (per-type code) — **not** `[身份证号已脱敏]` literal | ✓ |
| `mask` | `138****5678` (partial digits visible) | ✗ |
| `name_mask` | `张*` | ✗ |
| `landline_mask` | `010-****-1234` | ✗ |
| `category` | `[LOCATION]` | ✗ |
| `keep` | original text untouched | ✓ |

> ⚠️ **Common misread**: `remove` strategy emits `ID-NNNNN` codes by default, NOT Chinese label literals like `[身份证号已脱敏]`. The label form only appears if you explicitly pass `config={"id_number": {"replacement": "[身份证号已脱敏]"}}`. See [API reference: is_strategy_reversible](api-reference.md#is_strategy_reversible-v059).

## Unified Prefix (hide PII type)

By default, pseudonym codes still reveal the PII type via prefix: `P-00037` (person), `MED-00123` (medical), `ADDR-05432` (address). To hide type information from the LLM, pass the top-level `unified_prefix=` kwarg:

```python
redact(
    text,
    unified_prefix="R",
    config={
        "phone": {"strategy": "remove"},   # ← mask types must opt in
        "email": {"strategy": "remove"},
    },
)
# All reversible types collapse to R-NNNNN: R-00037, R-00123, R-05432
```

> ⚠️ **v0.6.0 breaking change**: passing `_unified_prefix` as a config key now raises `ValueError`. Use `redact(text, unified_prefix='R', ...)` instead. The same kwarg is available on `redact_pseudonym_llm()`.

> ⚠️ `mask` / `name_mask` / `landline_mask` / `category` strategies don't use prefixes — they emit shape-preserving output by design (`138****5678`, `张*`, `[LOCATION]`). Override those types to `remove` if you want them unified.

`<TYPE_N>` 1-based sequential token style (e.g. `<PHONE_1>`, `<PERSON_1>`) is a future-release candidate (no committed timeline).

## Usage

```python
# Use built-in defaults
redacted, key = redact(text)

# Pass config as dict
redacted, key = redact(text, config={
    "phone": {"strategy": "remove", "replacement": "[TEL]"},
    "person": {"strategy": "pseudonym", "prefix": "PERSON"},
})

# Compliance profiles override strategies for stricter privacy
redacted, key = redact(text, profile="pipl")   # phone → remove (no mask leakage)
redacted, key = redact(text, profile="hipaa")  # phone → remove
```

### Profile Strategy Overrides

Compliance profiles (`pipl`, `gdpr`, `hipaa`) automatically override `mask` strategies to `remove` for types where partial information leakage is a risk:

| Type | Default strategy | Profile override | Why |
|------|:---:|:---:|-----|
| phone | mask (`138****5678`) | remove (`PHON-XXXXX`) | 3+4 visible digits narrow to ~10K numbers |
| email | mask (`z***@example.com`) | remove | Domain + partial local part reveals identity |
| bank_card | mask | remove | BIN prefix + last 4 digits identify issuer + card |
| credit_card | mask | remove | Same as bank_card |

User config overrides profile config: `redact(text, profile="pipl", config={"phone": {"strategy": "mask"}})` uses mask despite PIPL profile.

**Caveat:** these are strategy-override presets, not coverage guarantees. A
profile changes *how* already-detected types are redacted — it does not widen
or narrow *which* types get detected. Selecting a profile does not by itself
make a pipeline compliant: compliance depends on what the detectors actually
find, your review process, and legal review, not on the profile name.

---

## Full Configuration Schema

The `config` argument is a mapping of `{entity_type: {options}}`. Pass it inline
(`redact(config={...})`) or as a file path (`redact(config="redact_config.yaml")`,
also the CLI `-c/--config`; JSON is accepted too). Only the per-type option keys below
are read — anything else in the file is ignored.

```yaml
# redact_config.yaml — {entity_type: {options}}. Every key below is read by the engine.

person:
  strategy: pseudonym    # pseudonym | realistic | mask | remove | category | name_mask | landline_mask | keep
  prefix: "P"            # pseudonym code prefix (per-type default: "P" person, "O" org, else TYPE[:4])

location:
  strategy: category
  label: "[LOCATION]"    # category: the label to substitute (per-type default: "[LOCATION]")

phone:
  strategy: mask         # 138****5678 — see the security note below
  visible_prefix: 3      # mask: leading chars kept visible
  visible_suffix: 4      # mask: trailing chars kept visible
  # ⚠️ mask retains prefix+suffix digits. For phone: 3+4 visible = ~10,000 possible
  # numbers. Use strategy: pseudonym or profile="pipl" for strict privacy.

id_number:
  strategy: remove
  replacement: "[ID number removed]"   # remove: the substitution label
```

The engine reads exactly these per-type keys: `strategy`, `prefix` (pseudonym),
`replacement` (remove), `label` (category), and `visible_prefix` / `visible_suffix`
(mask). There is **no** `global:` or `layers:` section, and no `rotation`,
`code_range`, `mask_char`, or `preserve_domain` key — those were never wired. What
those names implied is controlled elsewhere:

- **Which layers run** → the `mode=` argument (`"fast"` / `"ner"` / `"auto"`).
- **NER / semantic model** → `mode=` plus the `OLLAMA_MODEL` / `OLLAMA_HOST` env vars.
- **Confidence floor** → the top-level `min_confidence=` argument to `redact()`.
- **Unified prefix / language / salt** → the `unified_prefix=`, `lang=`, `salt=` args.
- **Fixed vs per-session pseudonyms** → persist and reuse `key=`; a reused key gives the
  same code for the same value. There is no `rotation` key.
- **Mask character** is always `*`.

---

## Strategy Reference

### pseudonym

Replace with a random code. Codes are stable within a call; reuse a persisted `key=` to keep them stable across calls, or start fresh for new codes.

```
Input:  "张三和李四在聊天"
Output: "P-037和P-012在聊天"     (fresh key)
Output: "P-003和P-071在聊天"     (a different fresh key)
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `prefix` | `str` | `"P"` (person), `"O"` (org), else `TYPE[:4]` | Pseudonym code prefix |

**Stable codes across calls:** persist and reuse the `key=` dict — there is no `rotation` option. Only do this for purely local pipelines where data never leaves your device: a reused key makes pseudonyms linkable across requests, so the cloud can build a profile.

### category

Replace with a category label. The original is mapped to its semantic category.

```
Input:  "在星巴克中关村店讨论"
Output: "在[LOCATION]讨论"
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `label` | `str` | `"[LOCATION]"` (location) | The single category label substituted for the value. |

`category` substitutes one fixed per-type label — there is no sub-category (`cafe` / `hospital`) resolution. Override it per type, e.g. `config={"location": {"label": "[place]"}}`.

### mask

Partially hide the value, keeping some characters visible.

```
Input:  "13812345678"
Output: "138****5678"
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `visible_prefix` | `int` | per-type (phone 3, bank_card 6, id_number 0) | Number of leading characters to keep visible. |
| `visible_suffix` | `int` | per-type (phone 4, bank_card 4, id_number 4) | Number of trailing characters to keep visible. |

The mask character is always `*`. Email uses a built-in shape (`local[0]` + `***` + `@domain`), so its domain stays visible without a config key.

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

---

## Built-in Defaults

When no config file is provided, these defaults are used:

| Entity Type | Strategy | Details |
|------------|----------|---------|
| `person` | `pseudonym` | prefix `P` |
| `location` | `category` | label `"[LOCATION]"` |
| `organization` | `pseudonym` | prefix `O` |
| `phone` | `mask` | Show first 3 + last 4 |
| `id_number` | `remove` | `"[身份证号已脱敏]"` |
| `email` | `mask` | Preserve domain |
| `bank_card` | `mask` | Show first 4 + last 4 |
| `address` | `remove` | `"[地址已脱敏]"` |
| `date_of_birth` | `remove` | `"[出生日期已脱敏]"` |
| *(other)* | `remove` | `"[REDACTED]"` |

---

## Validation

Invalid configuration raises `ValueError` at call time:

```python
redacted, key = redact(text, config={"person": {"strategy": "invalid"}})
# ValueError: Unknown strategy 'invalid' for entity type 'person'.
#   Valid: pseudonym, realistic, mask, remove, category, name_mask, landline_mask, keep
```

Missing fields fall back to defaults — you only need to specify what you want to override:

```yaml
# Only override person's prefix; everything else uses defaults
person:
  prefix: "USER"
```

---

## Reducing False Positives

Regex patterns match format, not semantics. argus-redact includes a context heuristic that checks text immediately before and after a match for non-PII indicators (e.g. "version", "order #", arithmetic operators).

For specific use cases where false positives are a problem, you can:

1. **Disable specific PII types** via config:
```python
# Don't detect bank cards in financial calculation documents
redact(text, config={"bank_card": {"strategy": "remove", "replacement": ""}}, mode="fast")
```

2. **Use NER mode** for context-aware detection:
```python
# NER understands context — won't flag "version 123-45-6789"
redact(text, mode="ner")
```

3. **Use `mode="auto"`** for maximum accuracy (regex + NER + semantic LLM).
