# Python API Reference

## redact()

```python
from argus_redact import redact

redact(
    text: str,
    *,
    key: dict | str | None = None,
    lang: str | list[str] = "zh",
    mode: str = "auto",
    seed: int | None = None,
    config: dict | None = None,
    names: list[str] | None = None,
    detailed: bool = False,
    report: bool = False,
    profile: str | None = None,
    types: list[str] | None = None,
    types_exclude: list[str] | None = None,
) -> tuple[str, dict] | tuple[str, dict, dict]
```

Detect and replace PII in the input text. Returns `(redacted_text, key)`, or `(redacted_text, key, details)` when `detailed=True`.

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `text` | `str` | *(required)* | Input text to redact. |
| `key` | `dict \| str \| None` | `None` | `None` = generate fresh key. `dict` = reuse this mapping (new entities are added, existing preserved). `str` = **file path** — if file exists, load and reuse; after redaction, file is updated with new entries. Behaves like CLI `-k`. |
| `lang` | `str \| list[str]` | `"zh"` | Language(s). `"zh"`, `"en"`, `"ja"`, `"ko"`, or list like `["zh", "en"]`. |
| `mode` | `str` | `"auto"` | `"auto"` = all installed layers. `"fast"` = regex only. `"ner"` = regex + NER. |
| `seed` | `int \| None` | `None` | Random seed for pseudonym generation.
| `config` | `dict \| str \| None` | `None` | Per-entity-type config. Dict, JSON file, or YAML file path. See [Configuration](configuration.md). |
| `names` | `list[str] \| None` | `None` | Known names to always redact (no NER needed). Combined with NER for best results. |
| `detailed` | `bool` | `False` | If `True`, return a 3-tuple with detection details (entities, stats). |
| `report` | `bool` | `False` | Return a `RedactReport` with risk assessment and compliance info. |
| `profile` | `str \| None` | `None` | Compliance profile: `"default"`, `"pipl"`, `"gdpr"`, `"hipaa"`. |
| `types` | `list[str] \| None` | `None` | Whitelist — only detect these PII types. |
| `types_exclude` | `list[str] \| None` | `None` | Blacklist — skip these PII types. Mutually exclusive with `types`. |

### Returns

`tuple[str, dict]` — `(redacted_text, key)`

- `redacted_text`: the input with all detected PII replaced
- `key`: mapping from replacement → original. Example: `{"P-037": "王五", "[咖啡店]": "星巴克"}`

**Key uniqueness:** Every replacement string is guaranteed unique within a key. `pseudonym` and `mask` strategies produce naturally unique outputs. `category`, `remove`, and `generalize` append a circled number (①②③) on collision:

```python
redacted, key = redact("他在星巴克和Costa都喝了咖啡")
# key = {"[咖啡店]": "星巴克", "[咖啡店①]": "Costa"}
# First occurrence: no suffix. Second: ①. Third: ②.
```

### Examples

```python
# Basic
redacted, key = redact("张三的手机号是13812345678")
# redacted = "P-042的手机号是[手机号已脱敏]"
# key = {"P-042": "张三", "[手机号已脱敏]": "13812345678"}

# Mixed language
redacted, key = redact("王五给John发邮件", lang=["zh", "en"])

# Reuse key (batch)
text1, key = redact("张三说了A")
text2, key = redact("张三说了B", key=key)  # same pseudonyms

# Fast mode
redacted, key = redact("张三 13812345678", mode="fast")
# Only phone is redacted; 张三 requires NER (skipped in fast mode)

# Save key to file (auto-read/write)
redacted, key = redact("张三在星巴克", key="key.json")
# key.json created (or updated if it existed)

# Batch via file: each call reads, updates, and writes back
redact("张三说了A", key="key.json")        # key.json doesn't exist → created
redact("张三和李四说了B", key="key.json")   # key.json exists → loaded, 李四 added, written back
redact("没有PII的文本", key="key.json")     # key.json exists → loaded, nothing added, NOT rewritten

# Detailed mode
redacted, key, details = redact("张三在星巴克", detailed=True)
```

### Purity Model

`redact()` is **not** a pure function. Understanding where purity breaks helps you write better tests:

| Aspect | Pure? | Why | How to control |
|--------|-------|-----|---------------|
| Pseudonym generation | No — random | Different codes each call | `seed=42` makes it deterministic |
| Pattern matching (Layer 1) | Yes | Same regex, same input → same matches | — |
| NER detection (Layer 2) | Mostly | Same model, same input → same output. But model loading is a side effect. | Mock or use real model |
| LLM detection (Layer 3) | No | LLM output may vary | Mock LLM response |
| `key=dict` | Yes | No I/O, no mutation of input dict | — |
| `key=str` (file path) | No — file I/O | Reads and writes the file system | Use `key=dict` in tests |
| `restore()` | **Yes** | Pure string replacement, fully deterministic | — |

**Rule for tests:** Use `seed` + `key=dict` + `mode="fast"` and your tests become fully deterministic with zero side effects:

```python
# Fully pure, fully testable
text, key = redact("张三 13812345678", seed=42, mode="fast")
assert text == "张三 [手机号已脱敏]"  # deterministic
assert key == {"[手机号已脱敏]": "13812345678"}  # deterministic

restored = restore(text, key)
assert restored == "张三 13812345678"  # pure
```

### Behavior

- **Same entity in one call → same pseudonym.** "张三...张三" → "P-012...P-012"
- **Different calls without key → different pseudonyms.** Fresh random codes each time.
- **With same seed → same pseudonyms.** `seed=42` always produces the same mapping.
- **Pseudonym codes are random, not sequential.** P-037 and P-012, not P-001 and P-002. The code numbers reveal nothing about entity count or order.
- **Layers run bottom-up.** Layer 1 (regex) first, then Layer 2 (NER), then Layer 3 (semantic). Later layers don't re-detect what earlier layers already caught.
- **Overlapping detections are deduplicated.** If regex and NER both catch the same span, the higher-confidence match wins.

### Edge Cases

```python
# Empty text → empty text, empty key
redacted, key = redact("")
# redacted = "", key = {}

# No PII detected → text unchanged, empty key
redacted, key = redact("今天天气不错")
# redacted = "今天天气不错", key = {}

# restore with empty key → text unchanged
restored = restore("any text", {})
# restored = "any text"

# Pseudonym appears as substring in a word — still matched
redacted, key = redact("王五说了话")
# redacted = "P-037说了话"
restored = restore("关于P-037的建议", key)
# "关于王五的建议"  ← P-037 matched even without whitespace boundaries

# Unknown pseudonyms left unchanged
restored = restore("P-999 is unknown", {"P-037": "王五"})
# "P-999 is unknown"  ← P-999 not in key, left as-is

# Multiple same-type entities (collision numbering)
redacted, key = redact("他的身份证110101199003071234，她的身份证220102198805061234")
# key has two entries: "[身份证号已脱敏]" and "[身份证号已脱敏①]"

# Reuse key with no matching entities — key returned unchanged
text, key = redact("今天天气不错", key={"P-037": "王五"})
# text = "今天天气不错", key = {"P-037": "王五"} (unchanged)
```

### Testable Invariants

These properties should hold in all cases. Tests use `seed` for determinism and `mode="fast"` to avoid model dependencies:

```python
import pytest
from argus_redact import redact, restore

# ── Pure properties (no models needed) ──

def test_roundtrip():
    """redact → restore recovers all PII."""
    original = "张三的手机号是13812345678"
    redacted, key = redact(original, seed=42, mode="fast")
    restored = restore(redacted, key)
    assert "13812345678" in restored

def test_pii_removed_from_output():
    """Original PII must not appear in redacted text."""
    redacted, key = redact("手机号13812345678", seed=42, mode="fast")
    for replacement, original in key.items():
        assert original in "手机号13812345678"    # was in input
        assert original not in redacted           # NOT in output
        assert replacement in redacted            # replacement IS in output

def test_empty_input():
    assert redact("", mode="fast") == ("", {})

def test_no_pii():
    text = "没有任何敏感信息的普通文本"
    assert redact(text, mode="fast")[0] == text

def test_key_uniqueness():
    """All replacement strings in key must be unique."""
    _, key = redact("身份证110101199003071234和220102198805061234", seed=42, mode="fast")
    assert len(key) == len(set(key.keys()))

def test_seed_determinism():
    """Same seed + same input = same output."""
    r1 = redact("张三 13812345678", seed=42, mode="fast")
    r2 = redact("张三 13812345678", seed=42, mode="fast")
    assert r1 == r2

def test_session_isolation():
    """Different seeds (or no seed) = different pseudonyms."""
    _, key1 = redact("张三", seed=42)
    _, key2 = redact("张三", seed=99)
    assert key1 != key2

def test_key_reuse():
    """Reusing key preserves existing pseudonyms and adds new ones."""
    _, key = redact("张三和李四", seed=42)
    original_key_size = len(key)
    text2, key = redact("张三和王五", key=key, seed=42)
    assert len(key) >= original_key_size  # only grows

def test_restore_is_pure():
    """restore() is deterministic — same input = same output."""
    key = {"P-037": "王五"}
    assert restore("P-037", key) == restore("P-037", key) == "王五"

def test_restore_no_match():
    """Unknown pseudonyms are left unchanged."""
    assert restore("P-999 is unknown", {"P-037": "王五"}) == "P-999 is unknown"

def test_restore_empty_key():
    assert restore("any text", {}) == "any text"

def test_detailed_returns_3tuple():
    result = redact("13812345678", detailed=True, seed=42, mode="fast")
    assert len(result) == 3
    text, key, details = result
    assert "entities" in details
    assert "stats" in details

# ── Error cases ──

def test_invalid_mode():
    with pytest.raises(ValueError):
        redact("text", mode="invalid")

def test_restore_bad_key_type():
    with pytest.raises(TypeError):
        restore("text", 123)
```

### Errors

| Error | When | Testable assertion |
|-------|------|-------------------|
| `ValueError` | `lang` specifies an uninstalled language pack | `pytest.raises(ValueError)` |
| `ValueError` | `mode` is not one of `"auto"`, `"fast"`, `"ner"` | `pytest.raises(ValueError)` |
| `FileNotFoundError` | `key` file path doesn't exist when used in `restore()` | `pytest.raises(FileNotFoundError)` |
| `TypeError` | `text` is not a string (e.g., `redact(123)`) | `pytest.raises(TypeError)` |
| `ValueError` | `types` and `types_exclude` both specified | `pytest.raises(ValueError)` |
| `ValueError` | Unknown `profile` name | `pytest.raises(ValueError)` |

---

## restore()

```python
from argus_redact import restore

restore(
    text: str,
    key: dict | str,
) -> str
```

Reverse redaction — replace pseudonyms with originals using the key.

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `text` | `str` | *(required)* | Text containing pseudonyms (typically LLM output). |
| `key` | `dict \| str` | *(required)* | The key from `redact()`. `dict` = use directly. `str` = load from JSON file path (**read-only** — unlike `redact()`, `restore()` never writes to the file). |

### Returns

`str` — text with pseudonyms replaced by originals.

### Examples

```python
redacted, key = redact("王五和张三在阿里面试")
# redacted = "P-037和P-012在[某公司]面试"

llm_output = "P-037 should help P-012 prepare for [某公司]"
restored = restore(llm_output, key)
# "王五 should help 张三 prepare for 阿里"

# From saved key file
restored = restore(llm_output, "key.json")
```

### Behavior

- **Exact string replacement.** `P-037` in text → looked up in key → replaced with original.
- **Longer replacements first.** `[某公司总部]` is matched before `[某公司]` to avoid partial replacement.
- **Unknown pseudonyms are left unchanged.** If the text contains `P-099` but the key has no `P-099`, it stays as `P-099`.
- **Works on any text.** The text doesn't have to come from an LLM — any string with pseudonyms can be restored.

### Edge Cases

```python
# Pseudonym at start of text
restore("P-037是好人", {"P-037": "王五"})  # "王五是好人"

# Pseudonym at end of text
restore("他是P-037", {"P-037": "王五"})  # "他是王五"

# Multiple occurrences of same pseudonym
restore("P-037和P-037", {"P-037": "王五"})  # "王五和王五"

# Replacement contains characters that look like another pseudonym
# key = {"P-037": "P先生"}  ← original contains "P"
restore("P-037说了话", {"P-037": "P先生"})  # "P先生说了话" (no re-matching)

# Nested-looking keys — longest match first
restore("[某公司总部]开会", {"[某公司]": "阿里", "[某公司总部]": "阿里西溪园区"})
# "阿里西溪园区开会"  ← [某公司总部] matched first (longer), [某公司] not triggered
```

### Errors

| Error | When | Testable assertion |
|-------|------|-------------------|
| `FileNotFoundError` | Key file path doesn't exist | `pytest.raises(FileNotFoundError)` |
| `TypeError` | Key is not dict or str | `pytest.raises(TypeError)` |

---

## check_restore_safety()

```python
from argus_redact import check_restore_safety

check_restore_safety(
    redacted: str,
    llm_output: str,
    key: dict[str, str],
) -> list[str]
```

Check if LLM output shows signs of prompt injection by detecting pseudonym amplification. Returns a list of warning strings (empty = safe).

```python
redacted, key = redact("张三在医院看病", names=["张三"])
llm_output = call_llm(redacted)

warnings = check_restore_safety(redacted, llm_output, key)
if warnings:
    print("Possible injection detected:", warnings)
else:
    restored = restore(llm_output, key)
```

Warns when a pseudonym code appears more times in the LLM output than in the original redacted text.

---

## wipe_key()

```python
from argus_redact import wipe_key

wipe_key(key: dict) -> None
```

Clear a key dict to minimize PII exposure in memory. Removes all entries so references can be garbage collected sooner.

```python
redacted, key = redact(text)
restored = restore(llm_output, key)
wipe_key(key)  # done with key, clear it
```

**Limitation:** Python strings are immutable and cannot be securely erased from memory. `wipe_key` removes dict references but string content may persist until GC. For high-security scenarios, run argus-redact in a short-lived process.

---

## Performance Telemetry

Opt-in timing logs for diagnosing performance.

### Environment Variables

```bash
ARGUS_PERF_LOG=perf.jsonl          # Enable file logging (JSONL)
ARGUS_PERF_SLOW_MS=50              # Slow call threshold in ms (default: 50)
ARGUS_PERF_SAMPLE=0.01             # Fast call sampling rate (default: 1%)
```

Slow calls (above threshold) are always logged. Fast calls are sampled at the configured rate.

### Custom Hook

```python
from argus_redact.telemetry import set_perf_hook, PerfRecord

def my_hook(record: PerfRecord):
    print(f"{record.text_len} chars, {record.total_ms}ms, {record.entities_found} entities")

set_perf_hook(my_hook)   # receives ALL calls (no sampling)
set_perf_hook(None)      # disable
```

### PerfRecord Fields

| Field | Type | Description |
|-------|------|-------------|
| `text_len` | int | Input character count |
| `text_ascii_ratio` | float | 0.0-1.0, indicates normalize cost |
| `lang` | list[str] | Languages used |
| `mode` | str | fast / ner / auto |
| `normalize_ms` | float | Unicode normalization time |
| `layer_1_ms` | float | Regex matching time |
| `layer_1b_person_ms` | float | Person name scoring time |
| `layer_2_ms` | float | NER time |
| `layer_3_ms` | float | Semantic LLM time |
| `merge_ms` | float | Merge + cross-layer + tier filter |
| `replace_ms` | float | Replacement + grammar normalization |
| `total_ms` | float | Sum of all above |
| `entities_found` | int | Entity count |
| `entity_types` | list[str] | Distinct types detected |
| `rust_core` | bool | Rust acceleration active |
| `slow` | bool | Above slow threshold |
| `sampled` | bool | Random sample (fast call) |

---

## Key Format

The key is a `dict[str, str]` mapping replacements to originals:

```python
{
    "P-037":         "王五",
    "P-012":         "张三",
    "[咖啡店]":       "星巴克",
    "[某公司]":       "阿里",
    "[手机号已脱敏]":  "13812345678",
}
```

### Serialized format (JSON file)

When saved via `key="path.json"` or `json.dump`:

```json
{
    "P-037": "王五",
    "P-012": "张三",
    "[咖啡店]": "星巴克",
    "[某公司]": "阿里"
}
```

Plain dict. No envelope, no metadata. Load with `json.load()`, pass to `restore()`.

### Key reuse

When passing `key` to `redact()`:
- **Existing mappings are preserved.** The function reverse-looks up the key (scans values) to find if an entity already has a pseudonym. If "王五" is already in the key's values mapped to "P-037", the same "P-037" is reused.
- **New entities get new random codes.** If "李四" appears but isn't in the key's values, a new code (e.g., P-058) is generated (collision-checked against existing keys).
- **The returned key is the updated version** containing both old and new mappings.

```python
text1, key = redact("王五和张三聊天")
# key = {"P-037": "王五", "P-012": "张三"}

text2, key = redact("王五和李四聊天", key=key)
# key = {"P-037": "王五", "P-012": "张三", "P-058": "李四"}
#        ↑ preserved                          ↑ new
```

**Key direction:** The key is always `{replacement → original}` (optimized for `restore()`). When reusing, `redact()` internally builds a reverse index `{original → replacement}` for O(1) lookup. This is transparent to the user.

---

## Inspecting Detection Details

For debugging or quality evaluation, pass `detailed=True`:

```python
redacted, key, details = redact("张三的手机号是13812345678", detailed=True)

details["entities"]
# [
#   {"original": "张三", "replacement": "P-042",
#    "type": "person", "layer": 2, "confidence": 0.95,
#    "start": 0, "end": 2},
#   {"original": "13812345678", "replacement": "[手机号已脱敏]",
#    "type": "phone", "layer": 1, "confidence": 1.0,
#    "start": 6, "end": 17},
# ]

details["stats"]
# {"total": 2}
```

Without `detailed=True`, `redact()` returns `(str, dict)` as usual. With it, returns `(str, dict, dict)`. The extra dict contains `entities` and `stats`.

**Testing note:** Code that always unpacks as `text, key = redact(...)` will break if `detailed=True` is accidentally set. Tests should verify both return shapes:

```python
# Normal mode
result = redact("test")
assert len(result) == 2

# Detailed mode
result = redact("test", detailed=True)
assert len(result) == 3
```

---

## Risk Assessment

### assess_risk()

```python
from argus_redact import assess_risk

result = assess_risk([
    {"type": "id_number", "sensitivity": 4},
    {"type": "phone", "sensitivity": 3},
])
result.score          # 0.85
result.level          # "critical"
result.reasons        # ("id_number (critical)", "phone (high)", "multiple high/critical entities detected")
result.pipl_articles  # ("PIPL Art.28", "PIPL Art.51")
```

### Report mode

```python
from argus_redact import redact

report = redact("身份证110101199003074610，手机13812345678", report=True, mode="fast")
report.redacted_text   # redacted text
report.key             # {replacement: original}
report.entities        # tuple of entity dicts
report.stats           # {"total": 2, "layer_1": 2, ...}
report.risk.score      # 0.85
report.risk.level      # "critical"
report.risk.pipl_articles  # ("PIPL Art.28", "PIPL Art.51")
```

### Compliance profiles

```python
# Use a preset profile
redact(text, profile="pipl")    # all types enabled
redact(text, profile="hipaa")   # HIPAA-relevant types only

# Fine-grained control
redact(text, types=["phone", "id_number"])          # only these types
redact(text, types_exclude=["address", "email"])     # everything except these
```

---

## Streaming Restore

For streaming LLM output, use `StreamingRestorer` to restore at sentence boundaries:

```python
from argus_redact.streaming import StreamingRestorer

restorer = StreamingRestorer(key)
for chunk in llm_stream:
    restored = restorer.feed(chunk)
    if restored:
        print(restored, end="")
final = restorer.flush()
if final:
    print(final, end="")
```

---

## Structured Data

Redact PII in JSON structures and CSV strings:

```python
from argus_redact.structured import redact_json, restore_json, redact_csv, restore_csv

# JSON — recursively walks all string values
data = {"user": {"name": "张三", "phone": "13812345678"}, "action": "login"}
redacted, key = redact_json(data, mode="fast")
restored = restore_json(redacted, key)

# CSV — header preserved, each cell redacted
csv_text = "name,phone\n张三,13812345678"
redacted_csv, key = redact_csv(csv_text, mode="fast")
restored_csv = restore_csv(redacted_csv, key)
```

---

## Limitations

| Limitation | Detail |
|-----------|--------|
| YAML config requires `pyyaml` | Pass dict or JSON file path if pyyaml not installed |
| Streaming restore is sentence-based | Pseudonyms split across chunks are buffered until a sentence boundary |
| `restore()` is global replacement | If LLM output naturally contains a pseudonym pattern, it gets replaced. Use a unique `prefix` in `config` to minimize risk |
| Pseudonym codes auto-expand | 5-digit codes (99,999 per prefix); automatically expands range on exhaustion |
