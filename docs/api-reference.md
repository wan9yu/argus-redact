# Python API Reference

## redact()

```python
from argus_redact import redact

redact(
    text: str,
    *,
    key: dict | str | None = None,
    lang: str | list[str] = "zh",
    mode: str = "fast",
    salt: int | bytes | None = None,
    config: dict | str | None = None,
    names: list[str] | None = None,
    detailed: bool = False,
    report: bool = False,
    with_types: bool = False,
    profile: str | None = None,
    types: list[str] | None = None,
    types_exclude: list[str] | None = None,
    unified_prefix: str | None = None,
    strict: bool = False,
) -> tuple[str, dict] | tuple[str, dict, dict]
```

Detect and replace PII in the input text. Returns `(redacted_text, key)`, or `(redacted_text, key, details)` when `detailed=True`.

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `text` | `str` | *(required)* | Input text to redact. |
| `key` | `dict \| str \| None` | `None` | `None` = generate fresh key. `dict` = reuse this mapping (new entities are added, existing preserved). `str` = **file path** — if file exists, load and reuse; after redaction, file is updated with new entries. Behaves like CLI `-k`. |
| `lang` | `str \| list[str]` | `"zh"` | Language(s). `"zh"`, `"en"`, `"ja"`, `"ko"`, or list like `["zh", "en"]`. Pass `"auto"` to let argus-redact pick language(s) from the text (script-based detection: Hiragana/Katakana → ja, Hangul → ko, CJK → zh, Latin letters → en; fallback `["zh"]`). |
| `mode` | `str` | `"fast"` | `"fast"` = regex only (zero deps, sub-ms). `"ner"` = regex + NER. `"auto"` = all installed layers (regex + NER + semantic LLM). |
| `salt` | `int \| bytes \| None` | `None` | Salt for deterministic pseudonym generation. Integers and short byte values are low-entropy; prefer `os.urandom(32)` in production.
| `config` | `dict \| str \| None` | `None` | Per-entity-type config. Dict, JSON file, or YAML file path. See [Configuration](configuration.md). |
| `names` | `list[str] \| None` | `None` | Known names to always redact (no NER needed). Combined with NER for best results. |
| `detailed` | `bool` | `False` | If `True`, return a 3-tuple with detection details (entities, stats). |
| `report` | `bool` | `False` | Return a `RedactReport` with risk assessment and compliance info. |
| `with_types` | `bool` | `False` | Return a 3-tuple `(redacted, key, types)` where `types` maps replacement → PII type. Ignored if `detailed` or `report` is also set — `detailed` wins. |
| `profile` | `str \| None` | `None` | Compliance profile: `"default"`, `"pipl"`, `"gdpr"`, `"hipaa"`. |
| `types` | `list[str] \| None` | `None` | Whitelist — only detect these PII types. |
| `types_exclude` | `list[str] \| None` | `None` | Blacklist — skip these PII types. Mutually exclusive with `types`. |
| `unified_prefix` | `str \| None` | `None` | Unify all reversible-strategy types under one prefix (e.g. `"R"` → `R-NNNNN`) instead of per-type prefixes. |
| `strict` | `bool` | `False` | With `mode="auto"`, raise `LayerUnavailableError` instead of warning + degrading when a requested layer (NER or semantic) isn't available. |

### Returns

`tuple[str, dict]` — `(redacted_text, key)`

- `redacted_text`: the input with all detected PII replaced
- `key`: mapping from replacement → original. Example: `{"P-037": "王五", "[咖啡店]": "星巴克"}`

**Key uniqueness:** Every replacement string is guaranteed unique within a key. `pseudonym` and `mask` strategies produce naturally unique outputs. `category` and `remove` append a circled number (①②③) on collision:

```python
redacted, key = redact("他在星巴克和Costa都喝了咖啡")
# key = {"[咖啡店]": "星巴克", "[咖啡店①]": "Costa"}
# First occurrence: no suffix. Second: ①. Third: ②.
```

**Available strategies** (`argus_redact.pure.replacer.VALID_STRATEGIES`):

| Strategy | Effect | Key entry? |
|----------|--------|------------|
| `pseudonym` | Replace with `P-NNNNN` (or per-type prefix) | yes |
| `realistic` | Replace with reserved-range fake (e.g., `19999...`); fakers run in Rust (built-in) or via a Rust per-entity callback (custom `faker_reserved`) | yes |
| `mask` | Replace with prefix + `***` + suffix (`138****5678`) | yes |
| `name_mask` | Chinese name mask (`张*`, `李**`) | yes |
| `landline_mask` | Area code + `***` + last 3 (`010****567`) | yes |
| `remove` | Replace with placeholder code (`MED-00123`) | yes |
| `category` | Replace with category label (`[LOCATION]`) | yes |
| `keep` *(v0.5.7+)* | **Preserve original text**; entity still emits hints / risk signal | **no** |

`keep` is useful for entities the LLM should see verbatim — for example, first-person pronouns (`我`, `我的`, `my`) where redacting them produces gibberish prompts. The `self_reference` type defaults to `keep` since v0.5.7.

> ℹ️ **Alias mappings:** `redact()` does NOT produce alias mappings. Cross-language alias generation (e.g., `张三` ↔ `Zhang San` for restoring after an LLM rewrites text into another language) is a `pseudonym-llm` profile feature; obtain it via `redact_pseudonym_llm()`'s result `.aliases` attribute, then pass it to `restore(text, key, aliases=...)`.

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

# Fast mode (default): regex + L1b person scoring
redacted, key = redact("张三说了话", mode="fast")
# No PII detected — bare name with no structural evidence; use mode="ner" for standalone names

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
| Pseudonym generation | No — random | Different codes each call | `salt=42` makes it deterministic |
| Pattern matching (Layer 1) | Yes | Same regex, same input → same matches | — |
| NER detection (Layer 2) | Mostly | Same model, same input → same output. But model loading is a side effect. | Mock or use real model |
| LLM detection (Layer 3) | No | LLM output may vary | Mock LLM response |
| `key=dict` | Yes | No I/O, no mutation of input dict | — |
| `key=str` (file path) | No — file I/O | Reads and writes the file system | Use `key=dict` in tests |
| `restore()` | **Yes** | Deterministic substitution; the v0.8.0+ provenance/scope guard is deterministic too | — |

**Rule for tests:** Use `salt` + `key=dict` + `mode="fast"` and your tests become fully deterministic with zero side effects:

```python
# Fully pure, fully testable
text, key = redact("张三 13812345678", salt=42, mode="fast")
assert text == "张三 [手机号已脱敏]"  # deterministic
assert key == {"[手机号已脱敏]": "13812345678"}  # deterministic

restored = restore(text, key, guard=False)  # local text, no LLM round-trip
assert restored == "张三 13812345678"  # pure
```

### Behavior

- **Same entity in one call → same pseudonym.** "张三...张三" → "P-012...P-012"
- **Different calls without key → different pseudonyms.** Fresh random codes each time.
- **With same salt → same pseudonyms.** `salt=42` always produces the same mapping.
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
redacted, key = redact("王五说了话", names=["王五"])
# redacted → "<P-code>说了话"; the P-code is random, e.g. "P-22560" (not sequential)
(code,) = key                        # exactly one entity was detected
restored = restore(f"关于{code}的建议", key, guard=False)  # local text, no LLM round-trip
# "关于王五的建议"  ← the pseudonym matched even without whitespace boundaries

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

These properties should hold in all cases. Tests use `salt` for determinism and `mode="fast"` to avoid model dependencies:

```python
import pytest
from argus_redact import redact, restore

# ── Pure properties (no models needed) ──

def test_roundtrip():
    """redact → restore recovers all PII."""
    original = "张三的手机号是13812345678"
    redacted, key = redact(original, salt=42, mode="fast")
    restored = restore(redacted, key, guard=False)  # local text, no LLM round-trip
    assert "13812345678" in restored

def test_pii_removed_from_output():
    """Original PII must not appear in redacted text."""
    redacted, key = redact("手机号13812345678", salt=42, mode="fast")
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
    _, key = redact("身份证110101199003071234和220102198805061234", salt=42, mode="fast")
    assert len(key) == len(set(key.keys()))

def test_salt_determinism():
    """Same salt + same input = same output."""
    r1 = redact("张三 13812345678", salt=42, mode="fast")
    r2 = redact("张三 13812345678", salt=42, mode="fast")
    assert r1 == r2

def test_session_isolation():
    """Different salts (or no salt) = different pseudonyms."""
    _, key1 = redact("张三", salt=42)
    _, key2 = redact("张三", salt=99)
    assert key1 != key2

def test_key_reuse():
    """Reusing key preserves existing pseudonyms and adds new ones."""
    _, key = redact("张三和李四", salt=42)
    original_key_size = len(key)
    text2, key = redact("张三和王五", key=key, salt=42)
    assert len(key) >= original_key_size  # only grows

# restore(..., guard=False) = the explicit legacy opt-out: no guard, no
# DeprecationWarning. These properties are about the substitution pass itself.

def test_restore_is_pure():
    """restore() is deterministic — same input = same output."""
    key = {"P-037": "王五"}
    assert restore("P-037", key, guard=False) == restore("P-037", key, guard=False) == "王五"

def test_restore_no_match():
    """Unknown pseudonyms are left unchanged."""
    assert restore("P-999 is unknown", {"P-037": "王五"}, guard=False) == "P-999 is unknown"

def test_restore_empty_key():
    assert restore("any text", {}, guard=False) == "any text"

def test_detailed_returns_3tuple():
    result = redact("13812345678", detailed=True, salt=42, mode="fast")
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
| `TypeError` | *(v0.8.0+)* `types` or `types_exclude` passed as a bare `str` (e.g. `types="phone"`) instead of a list — previously this silently treated the string as a character set and detected nothing | `pytest.raises(TypeError)` |
| `ValueError` | Unknown `profile` name | `pytest.raises(ValueError)` |

---

## redact_pseudonym_llm()

```python
from argus_redact import redact_pseudonym_llm

redact_pseudonym_llm(
    text: str,
    *,
    display_marker: str | None = None,
    salt: bytes | None = None,
    lang: str | list[str] = "zh",
    mode: str = "fast",
    names: list[str] | None = None,
    types: list[str] | None = None,
    types_exclude: list[str] | None = None,
    strict_input: bool = True,
    _polluted_input_ok: bool = False,
    existing_key: dict[str, str] | None = None,
    reserved_names: dict[str, tuple[str, ...]] | None = None,
    strategy_overrides: dict[str, str] | None = None,
) -> PseudonymLLMResult
```

Redact `text` with the `pseudonym-llm` profile, returning **three text forms** sharing one key dict. PII is replaced with realistic-looking but reserved-range fake values (e.g., `19999...` mobile, `999...` ID, `999999...` bank card) so downstream LLMs can reason about message structure. Reserved ranges are unassigned by the relevant authorities (CN MIIT for `199-99` mobile sub-segment, GB/T 2260 for `999` ID address codes, RFC 2606 for `example.com`, RFC 5737 for IP documentation blocks).

Detection runs **once**; the entity set feeds two replacement passes (realistic + audit). Cost is independent of mode for the dual-form output.

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `text` | `str` | *(required)* | Input text to redact. |
| `display_marker` | `str \| None` | `None` (= `ⓕ`) | Visible marker appended to fake values in `display_text`. Accepts a literal string (e.g., `"*"`, `"(假)"`) or a preset name (`"circled_f"`, `"superscript_s"`, `"asterisk"`, `"chinese"`, `"none"`). |
| `salt` | `bytes \| None` | `None` | Cross-process stable mapping. Same `salt` + same input → same fake values, suitable for cross-call joinability. Caller-explicit `salt` takes precedence over the `ARGUS_REDACT_PSEUDONYM_SALT` env var. |
| `lang`, `mode`, `names`, `types`, `types_exclude` | — | — | Same semantics as `redact()`. |
| `strict_input` | `bool` | `True` | If `True`, raises `PseudonymPollutionError` when the input already contains reserved-range values (i.e., the input was previously realistic-redacted). Set `False` to disable all input validation. |
| `_polluted_input_ok` | `bool` | `False` | Narrow opt-out: skip only the pollution check, keep other validation. Underscore prefix marks it as advanced usage. |
| `existing_key` | `dict[str, str] \| None` | `None` | Pre-existing `fake → original` mappings. Same original value present in both `text` and `existing_key.values()` reuses the same fake. Used by `StreamingRedactor` for cross-chunk consistency. |
| `reserved_names` | `dict[str, tuple[str, ...]] \| None` | `None` | Override canonical fake-name tables per type (e.g., `{"person_zh": ()}` to disable canonical-name pollution detection so a real user named 张三 / John Doe can be redacted). Pass a custom tuple to use a different list. |
| `strategy_overrides` | `dict[str, str] \| None` | `None` | Per-call override of the per-type strategy (e.g., `{"phone": "remove", "address": "realistic"}`). Affects the `downstream_text` (realistic) pass only — `audit_text` always emits placeholders. A type listed here that is not in the profile is added to both passes. Strategy names must be in `argus_redact.pure.replacer.VALID_STRATEGIES`. |

### Returns

A frozen `PseudonymLLMResult` dataclass with four fields:

| Field | Type | Purpose |
|-------|------|---------|
| `audit_text` | `str` | Placeholder labels (e.g., `[TEL-79329]`, `P-164`) — for compliance archive. |
| `downstream_text` | `str` | Realistic reserved-range fake — feed to LLMs. |
| `display_text` | `str` | Realistic + visible marker — safe to render to humans. |
| `key` | `dict[str, str]` | Unified `{fake → original}` mapping. `restore()` works on **any** of the three text forms. |

### Examples

The realistic strategy requires an explicit `salt`; `salt=42` below keeps the
output reproducible, production should pass a real secret.

<!-- pin -->
```python
from argus_redact import redact_pseudonym_llm, restore

result = redact_pseudonym_llm("请拨打 13912345678 联系王建国", salt=42)
result.audit_text       # "请拨打 PHON-68060 联系P-76865"
result.downstream_text  # "请拨打 19999946823 联系毕马温"
result.display_text     # "请拨打 19999946823ⓕ 联系毕马温ⓕ"

# Round-trip works on any of the three forms. guard=False here: this restores
# the library's own output, not an LLM reply — see guarded_restore() below
# for the guarded path a real LLM round-trip needs.
print(restore(result.downstream_text, result.key, guard=False))
# expected: 请拨打 13912345678 联系王建国
print(restore(result.audit_text, result.key, guard=False))
# expected: 请拨打 13912345678 联系王建国
print(restore(result.display_text, result.key, display_marker="ⓕ", guard=False))
# expected: 请拨打 13912345678 联系王建国

# Cross-process stable mapping
text = "请拨打 13912345678 联系王建国"
result1 = redact_pseudonym_llm(text, salt=b"shared-secret-32-bytes-min")
result2 = redact_pseudonym_llm(text, salt=b"shared-secret-32-bytes-min")
assert result1.downstream_text == result2.downstream_text

# English text
en = redact_pseudonym_llm(
    "Call John Smith at (415) 555-1234, email john@company.com",
    lang="en",
    salt=42,
)
en.downstream_text  # "Call Richard Roe at (555) 555-0123, email user64058@example.org"
print(restore(en.downstream_text, en.key, guard=False))
# expected: Call John Smith at (415) 555-1234, email john@company.com

# Mixed zh + en (auto-detect)
mx = redact_pseudonym_llm("客户Wang at user@company.com", lang="auto", salt=42)
print(restore(mx.downstream_text, mx.key, guard=False))
# expected: 客户Wang at user@company.com

# Per-call strategy override (v0.5.5+): force phone to a placeholder while the
# rest of the profile stands. audit_text is unchanged either way.
custom = redact_pseudonym_llm(
    "电话13912345678 地址北京市朝阳路100号",
    lang="zh",
    salt=42,
    strategy_overrides={"phone": "remove"},
)
custom.downstream_text  # "电话PHON-68060 地址LOCA-59624朝阳路100号"
```

### Reserved-range coverage

| Locale | Types | Reserved range |
|--------|-------|----------------|
| zh | phone, phone_landline, id_number, bank_card, license_plate, passport, address, person, age, date_of_birth | 199-99 mobile, 099 landline, 999XXX ID, 999999 BIN, 滨海市 city, 张三 names |
| en | phone, ssn, credit_card, address, person | (555) 555-01XX, 999-XX SSN, 999999 BIN, 1313 Mockingbird Lane, John Doe |
| shared (RFC) | email, ip_address, mac_address | example.{com,org,net} (RFC 2606), 192.0.2.0/24 etc. (RFC 5737), 2001:db8::/32 (RFC 3849), 00:00:5E:00:53:xx (RFC 7042) |

> ℹ️ **fast vs. ner for person**: Person detection (en and zh) runs in `mode="fast"` too — it's a Layer-1 pooled detector (surname / given-name pools) gated by corroborating evidence (a title, nearby PII, name-like shape, or a given-name lead). What `mode="fast"` does **not** run is the Layer-2 NER model (spaCy `en_core_web_sm`), so names with no structural or contextual evidence are missed in fast mode and recovered in `mode="ner"` or higher. Supplying `names=[...]` adds exact list matching on top of fast-mode detection.

### Errors

| Error | When |
|-------|------|
| `PseudonymPollutionError` | `strict_input=True` (default) and input contains reserved-range values (e.g., user passed already-realistic-redacted text for a second pass). Call `restore()` on the input first, or pass `_polluted_input_ok=True`. |
| `TypeError` | `text` is not a string. |
| `ValueError` | Input exceeds `MAX_INPUT_SIZE`; or invalid `mode`; or both `types` and `types_exclude` set. |

### When to use which form

| Use case | Form |
|----------|------|
| LLM prompt / completion input | `downstream_text` |
| UI render to a human | `display_text` |
| Compliance archive / audit log | `audit_text` |
| API response that may be shown OR consumed | `display_text` (safer default) |

> ⚠️ **Do not store `downstream_text` as business truth.** Realistic data looks real but is synthetic by design. Storing it in customer/business records causes data pollution.

---

## PseudonymLLMResult

```python
from argus_redact import PseudonymLLMResult

# Frozen result type returned by redact_pseudonym_llm().
# All five fields are plain attributes; mutating result.key / result.aliases
# directly mutates internal storage (the dataclass is frozen, but its dict
# fields are not). Copy first if you need to mutate.

result.audit_text       # placeholder labels — for compliance archive
result.downstream_text  # realistic reserved-range fake — for LLM input
result.display_text     # realistic + visible marker — for human display
result.key              # dict[str, str]: fake → original
result.aliases          # dict[str, tuple[str, ...]]: fake → cross-language aliases (v0.6.0+)
```

### result.aliases *(v0.6.0+)*

Maps a fake to alternate transliterations a downstream LLM might emit instead of the canonical fake — e.g. `result.key["王五"] == "王建国"` paired with `result.aliases["王五"] == ("Wang Jianguo",)`. Pass to `restore(text, key, aliases=...)` to recover originals from LLM output that rewrote names across languages. Fakes without aliases (phones, IDs, etc.) are absent from the dict — check with `result.aliases.get(fake, ())`.

---

## PseudonymPollutionError

```python
from argus_redact import PseudonymPollutionError
```

Subclass of `ValueError`. Raised by `redact_pseudonym_llm()` when input contains reserved-range values (i.e., the input is already realistic-redacted output). Re-redacting such input would silently corrupt the key dict, so the function refuses by default.

**Recovery**: call `restore(text, key)` to get back the original first, then re-redact if needed:

```python
from argus_redact import redact_pseudonym_llm, restore, PseudonymPollutionError

try:
    result = redact_pseudonym_llm(text)
except PseudonymPollutionError:
    original = restore(text, prior_key)
    result = redact_pseudonym_llm(original)
```

To disable the check (advanced usage), pass `strict_input=False` or `_polluted_input_ok=True`.

---

## restore()

```python
from argus_redact import restore

restore(
    text: str,
    key: dict[str, str] | str,
    *,
    aliases: dict[str, tuple[str, ...]] | None = None,
    display_marker: str | None = None,
    guard: bool | None = True,      # v0.7.18+; default flipped to True in v0.8.0
    anchor: object | None = None,   # v0.7.18+
    strict: bool = False,           # v0.7.18+
    detailed: bool = False,         # v0.7.18+
) -> str | tuple[str, dict]
```

Reverse redaction — replace pseudonyms with originals using the key.

> **If the text you are restoring came back from an LLM, prefer [`guarded_restore()`](#guarded_restore-v0720).**
> It is the same guard plus the injection heuristic, wired together correctly in one call.
> `restore()` is the lower-level primitive; use it directly for text that never left your process.

### `guard=True` is the default (v0.8.0+)

A bare `restore(text, key)` with no `anchor` now **fails closed**: it returns the text
**un-restored**, substitutes nothing, and (on `detailed=True`) reports a
`guard_no_anchor` security event. This is a change from pre-v0.8.0, where a bare call
ran a plain, unchecked substitution and only emitted a `DeprecationWarning`.

| You want | Pass | Result |
|----------|------|--------|
| The guard (recommended for LLM output) | `guard=True, anchor=anchor` | Provenance + scope checks run. |
| A plain legacy restore, no checks | `guard=False` | Unchecked restore, **no warning** — the explicit opt-out. |
| *(nothing)* | — | `guard=True` with no anchor → **fails closed**, `SecurityWarning`. |
| Legacy behavior with a migration nudge | `guard=None` | Unchecked restore (like `guard=False`) **plus** `DeprecationWarning`, and a `SecurityWarning` too if it actually substituted something (R4). |

`guard=None` is still accepted for callers migrating off the pre-v0.8.0 bare-call
default; it is not itself deprecated as a value, but relying on it silently is — pass
`guard=False` if you mean it.

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `text` | `str` | *(required)* | Text containing pseudonyms (typically LLM output). |
| `key` | `dict[str, str] \| str` | *(required)* | The key from `redact()` or `redact_pseudonym_llm()`. Accepts: (a) `dict[str, str]` (fake → original), or (b) `str` = path to a JSON file holding such a dict. |
| `aliases` | `dict[str, tuple[str, ...]] \| None` | `None` | *(v0.6.0+)* Per-fake alternate transliterations to also match. Pass `result.aliases` from `redact_pseudonym_llm()` to recover originals from LLM output that transliterated names across languages. |
| `display_marker` | `str \| None` | `None` | If set, strip the named display marker from `text` before key lookup. |
| `guard` | `bool \| None` | `True` *(v0.8.0+; was `None` in v0.7.18–v0.7.20)* | `True` (default) runs the deterministic provenance (P) + scope (S) checks — a bare call with no anchor fails closed. `False` runs the legacy unchecked restore, silently — the explicit opt-out. `None` runs the legacy restore and warns (`DeprecationWarning` always; `SecurityWarning` too if it substituted anything). |
| `anchor` | `object \| None` | `None` | *(v0.7.18+)* The `Anchor` from `make_anchor(key)`, carrying the nonce and the scope. Required for the guard to pass: with `guard=True` and no anchor, restore fails closed. |
| `strict` | `bool` | `False` | *(v0.7.18+)* With `guard=True`, raise `RestoreGuardError` on any security event instead of returning. Opt-in fail-closed. |
| `detailed` | `bool` | `False` | *(v0.7.18+)* Return `(text, {"security_events": [...]})` instead of a bare `str`. |

### Returns

- `str` by default — text with pseudonyms replaced by originals.
- `tuple[str, dict]` when `detailed=True` — `(text, {"security_events": [...]})`. The list is empty on a clean restore (including every `guard=False` / bare call, which runs no checks).

When the guard fails closed, the returned `str` is the text **un-restored** — shape-identical to a success, which is why the events channel exists.

### Guard semantics *(v0.7.18+)*

The guard has two deterministic parts. Both run inside `restore()` when `guard=True`:

- **P — provenance.** `prompt_anchor()` instructs the model to echo a per-call nonce; the anchor holds it. If no anchor was supplied (`guard_no_anchor`), or the nonce is absent from `text` (`provenance_failed`), restore **fails closed**: it returns the text un-restored, substituting nothing. On a pass, the echoed nonce is stripped from the output so it never reaches you as part of the plaintext.
- **S — scope binding.** Only pseudonyms listed in `anchor.scope` are restored. A pseudonym that appears in the reply but is outside the scope is withheld and reported as `out_of_scope_pseudonym`; the in-scope ones are still restored (a partial restore, not a fail-closed one).

The **H injection heuristic is not part of `restore()`.** It lives in [`check_restore_safety()`](#check_restore_safety) and is run for you by [`guarded_restore()`](#guarded_restore-v0720). H is **advisory by default** — it warns, it does not block — because it is a heuristic, and a heuristic is not promoted to the deterministic guarantee. `strict=True` is the opt-in that makes a security event fail closed.

A fail-closed or partial restore is **not silent**: it emits a `SecurityWarning` carrying reason codes and counts only, never the event's `detail` field. Prior to v0.7.19 a fail-closed restore returned un-restored text with no warning at all — a bug; it now always signals.

Guard checks are not a guarantee against a determined adversary — they raise the cost of replaying, forging or widening an LLM reply, and they surface what they catch. See `docs/security-model.md` for the threat model and its limits.

### Examples

```python
redacted, key = redact("王五和张三在阿里面试")
# redacted = "P-037和P-012在[某公司]面试"

# Text that never left your process — no guard is meaningful, so opt out explicitly.
restored = restore(redacted, key, guard=False)

# From saved key file
restored = restore(llm_output, "key.json", guard=False)
```

```python
# LLM output — run the guard. (guarded_restore() does this plus H in one call.)
from argus_redact import redact, restore, make_anchor
from argus_redact.compose import prompt_anchor

redacted, key = redact("王五和张三在阿里面试")
anchor = make_anchor(key)
llm_output = call_llm(redacted, system=prompt_anchor(key, anchor=anchor))

restored = restore(llm_output, key, guard=True, anchor=anchor)
# Guard passed  → "王五 should help 张三 prepare for 阿里" (nonce stripped)
# Guard tripped → llm_output, un-restored, plus a SecurityWarning
```

```python
# detailed=True — read the events instead of catching a warning.
restored, details = restore(llm_output, key, guard=True, anchor=anchor, detailed=True)
for event in details["security_events"]:
    log(event["reason_code"], event["count"])

# strict=True — raise instead of returning un-restored text.
from argus_redact import RestoreGuardError

try:
    restored = restore(llm_output, key, guard=True, anchor=anchor, strict=True)
except RestoreGuardError as e:
    handle(e.events)  # list of security event dicts
```

### Behavior

- **Exact substring match.** `P-037` in text → looked up in key → replaced with original (this substitution is what runs once the guard, above, lets the restore proceed).
- **Longer replacements first.** `[某公司总部]` is matched before `[某公司]` to avoid partial replacement.
- **Unknown pseudonyms are left unchanged.** If the text contains `P-099` but the key has no `P-099`, it stays as `P-099`.
- **Cross-language aliases** *(v0.6.0+, via `aliases=` kwarg)*: alternates in `aliases` are added to the alternation alongside the canonical fake. If an LLM transliterates `张三` into `Zhang San`, both forms map back to the original. Pass `result.aliases` from `redact_pseudonym_llm()` to enable.
- **Works on any text.** The text doesn't have to come from an LLM — any string with pseudonyms can be restored.

### Performance

The compiled alternation regex is cached on `frozenset(key.keys())` (since v0.5.4). Repeated `restore()` calls with the same key dict pay only one compile; subsequent calls are pure scan. This is the streaming hot path: `StreamingRestorer.feed()` flushes a sentence per call against an evolving but mostly-stable key, hitting the cache on every flush after the first. Cache is bounded at 128 entries via `lru_cache`.

### Edge Cases

These illustrate the substitution pass only, so each passes `guard=False` — the
explicit, silent, unguarded path — to isolate the string-matching behavior from the
guard. Since v0.8.0 a bare call with no `guard=` and no anchor fails closed and
returns the text un-restored, which would not demonstrate the substitution rule
being shown.

```python
# Pseudonym at start of text
restore("P-037是好人", {"P-037": "王五"}, guard=False)  # "王五是好人"

# Pseudonym at end of text
restore("他是P-037", {"P-037": "王五"}, guard=False)  # "他是王五"

# Multiple occurrences of same pseudonym
restore("P-037和P-037", {"P-037": "王五"}, guard=False)  # "王五和王五"

# Replacement contains characters that look like another pseudonym
# key = {"P-037": "P先生"}  ← original contains "P"
restore("P-037说了话", {"P-037": "P先生"}, guard=False)  # "P先生说了话" (no re-matching)

# Nested-looking keys — longest match first
restore("[某公司总部]开会", {"[某公司]": "阿里", "[某公司总部]": "阿里西溪园区"}, guard=False)
# "阿里西溪园区开会"  ← [某公司总部] matched first (longer), [某公司] not triggered
```

### Errors

| Error | When | Testable assertion |
|-------|------|-------------------|
| `FileNotFoundError` | Key file path doesn't exist | `pytest.raises(FileNotFoundError)` |
| `TypeError` | Key is not a mapping or str | `pytest.raises(TypeError)` |
| `RestoreGuardError` | `guard=True`, `strict=True`, and any security event fired | `pytest.raises(RestoreGuardError)` |

`RestoreGuardError.events` holds the security event dicts that caused the failure.

### Warnings

| Warning | When |
|---------|------|
| `DeprecationWarning` | `guard=None` was passed explicitly (the pre-v0.8.0 default). Pass `guard=False` for the silent legacy path, or `guard=True` (now the default — omitting `guard=` entirely also triggers the guard) with an `anchor` for the guard. |
| `SecurityWarning` | (a) `guard=True` (the default, explicit or implicit), `strict=False`, and a security event fired — a fail-closed (nothing substituted, e.g. a bare call with no anchor) or partial (out-of-scope pseudonyms withheld) restore. `restore()` warns whenever events fire, `detailed=True` or not. (`guarded_restore()` differs: it warns only when *not* `detailed`, unless you force it with `warn=`.) (b) *(R4, v0.8.0+)* `guard=None` (the deprecated legacy path) and the call actually substituted at least one pseudonym — names the consequence: originals were reinserted with no injection check. (`guard=False`, the informed opt-out, stays silent even when it substitutes.) |

---

## guarded_restore() *(v0.7.20+)*

```python
from argus_redact import guarded_restore

guarded_restore(
    text: str,
    key: dict[str, str] | str,
    *,
    redacted: str | None = None,
    anchor: object | None = None,
    guard: bool | None = True,
    strict: bool = False,
    detailed: bool = False,
    warn: bool | None = None,
) -> str | tuple[str, dict]
```

The correct-by-construction entry point for restoring an LLM reply. It runs the whole guarded-restore flow in one call: the supplementary injection heuristic (H) → fail closed on H first if `strict=True` (before any pseudonym is touched) → the deterministic provenance + scope guard (P + S), which lives inside `restore()` → merge every event from both stages into one `security_events` list → surface it.

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `text` | `str` | *(required)* | The model's reply, containing pseudonyms. |
| `key` | `dict[str, str] \| str` | *(required)* | The key from `redact()`, or a `str` path to a key file. A path is resolved once, here, so the same in-memory dict is used for both the H check and the restore call. |
| `redacted` | `str \| None` | `None` | The redacted prompt that was sent to the model. Supplying it is what *enables* the injection heuristic (H) — without it, no H check runs at all. |
| `anchor` | `object \| None` | `None` | The `Anchor` from `make_anchor(key)`. Required for the deterministic guard (P) to pass; without it, restore fails closed. |
| `guard` | `bool \| None` | `True` | Passed through to `restore()`: `True` runs the deterministic provenance (P) + scope (S) checks — the intended default here. `None` runs legacy restore with a `DeprecationWarning`. `False` is the explicit, silent opt-out. |
| `strict` | `bool` | `False` | Opt-in fail-closed, covering **both** stages. `True` raises `RestoreGuardError` on a suspected injection (H) *or* a failed deterministic guard (P/S) — for H specifically, this happens before any original is substituted, not after. `False` (the default) keeps H advisory: it warns, it does not block. |
| `detailed` | `bool` | `False` | `True` returns `(text, {"security_events": [...]})` instead of a bare `str`, and (by default) does not warn — inspecting the events is then the caller's job. `False` surfaces the merged H + P/S events as a single `SecurityWarning`. |
| `warn` | `bool \| None` | `None` | Whether to emit the `SecurityWarning`. `None` means *warn iff not `detailed`* — a `detailed` caller reads the structured events; a plain caller would otherwise get no signal at all. Force it either way with `True` / `False`: pass `warn=True` alongside `detailed=True` when you need **both** (argus-redact's own MCP `restore` tool does exactly this — it serialises the events into its JSON payload *and* wants the human-facing warning). |

### Returns

`str` by default. `tuple[str, dict]` when `detailed=True` — the dict is `{"security_events": [...]}`, the union of the H event (if any) and whatever the P/S guard produced. An empty list means nothing fired.

Each event is a dict: `{"type": "security", "reason_code": str, "count": int, "detail": str | None}`. Reason codes are `guard_no_anchor` / `provenance_failed` (P — nothing was substituted), `out_of_scope_pseudonym` (S — those pseudonyms were withheld, the rest were restored), and `injection_suspected` (H — advisory; the restore **proceeded** and originals *were* substituted). `detail` is designed to carry only counts and entity type names — never a pseudonym, an original value, or an excerpt of the model's reply — so it is safe for the same log stream as the `SecurityWarning`, which carries reason codes and counts. Entity type names are a closed vocabulary on every detector argus ships: layer-1 patterns and the layer-2 NER adapters declare theirs, and since v0.8.8 the layer-3 semantic adapter filters the model's choice through `_ALLOWED_SEMANTIC_TYPES`, retyping anything outside it as `semantic_other`. The one exception is the Presidio bridge, where an unmapped type from a caller-supplied recognizer passes through as-is (see `docs/known-issues.md`, Unresolved) — that vocabulary is the caller's own. Separately, `injection_suspected` no longer names *what* tripped the heuristic; call `check_restore_safety(redacted, llm_output, key)` for the specific hints when you are investigating one.

### Why it exists

Hand-assembling H → fail-closed-if-strict → the P+S guard → merged events → surfaced warning is exactly the kind of multi-step flow that goes subtly wrong under copy-paste: three of argus-redact's own five shipped integrations got it wrong before this function existed — one dropped the events it had just computed, one could not reach `strict` at all, and one ran no injection check whatsoever. Every integration this project ships now routes through `guarded_restore`; if you're wiring your own framework, use this instead of composing `restore()` by hand.

### Examples

```python
from argus_redact import redact, guarded_restore, make_anchor
from argus_redact.compose import prompt_anchor

redacted, key = redact("张三的电话是13912345678")
anchor = make_anchor(key)
system = prompt_anchor(key, anchor=anchor)
llm_output = call_llm(redacted, system=system)

# H runs because `redacted=` is supplied; P+S run because `anchor=` is supplied.
restored = guarded_restore(llm_output, key, redacted=redacted, anchor=anchor)
```

```python
# strict=True: raise before substituting anything, on EITHER a suspected
# injection or a failed deterministic guard.
from argus_redact import RestoreGuardError

try:
    restored = guarded_restore(llm_output, key, redacted=redacted, anchor=anchor, strict=True)
except RestoreGuardError as e:
    handle_guard_failure(e.events)  # e.events is a list of security event dicts
```

```python
# detailed=True: inspect events yourself instead of relying on the warning.
restored, details = guarded_restore(
    llm_output, key, redacted=redacted, anchor=anchor, detailed=True
)
for event in details["security_events"]:
    log(event["reason_code"], event["count"], event["detail"])
```

```python
# key may also be a path to a saved key file.
restored = guarded_restore(llm_output, "key.json", anchor=anchor)
```

### Behavior

- **H is advisory by default.** A suspected injection warns (and shows up in `security_events`) but does not block the restore — the deterministic guarantee is P + S, and a heuristic is never promoted to it. Pass `strict=True` to also fail closed on H.
- **One warning, accurately worded.** On the default (non-`detailed`) path, `guarded_restore` merges the H event and the P/S events into a single `SecurityWarning`, so a mixed outcome — some pseudonyms withheld, others advisory — is described as a mix, never as a plain "the restore proceeded" when it didn't (or the reverse).
- **No H check without `redacted=`.** Omit it and `guarded_restore` silently skips the heuristic; it needs the redacted prompt to compare against the model's reply.

### Errors

| Error | When | Testable assertion |
|-------|------|-------------------|
| `RestoreGuardError` | `strict=True` and any security event fired (H or P/S) | `pytest.raises(RestoreGuardError)` |

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

Check if LLM output shows signs of prompt injection by detecting pseudonym amplification. Returns a list of warning strings (empty = no suspicion).

**This function *is* the H heuristic.** It is exactly what [`guarded_restore()`](#guarded_restore-v0720) runs for you when you pass `redacted=`; a non-empty result there becomes an `injection_suspected` security event. Call it directly only when you want the raw hints without a restore — otherwise let `guarded_restore()` run it, so the H result and the deterministic P/S guard are merged, surfaced and (optionally) failed-closed in one place.

```python
redacted, key = redact("张三在医院看病")
llm_output = call_llm(redacted)

hints = check_restore_safety(redacted, llm_output, key)
if hints:
    print("Possible injection detected:", hints)
else:
    restored = restore(llm_output, key, guard=False)
```

It flags a pseudonym code appearing more times in the LLM output than in the redacted prompt, pseudonyms sitting next to exfiltration-shaped context (emails, URLs), and amplified reserved-range values from realistic mode.

Being a heuristic, it is advisory: expect both false positives (a model that legitimately repeats a code) and false negatives (an injection that never amplifies). The deterministic guarantee is the P + S guard, not this check — do not gate your pipeline on H alone.

Input is capped at the same 1 MiB `MAX_INPUT_SIZE` as the detection entry points. Over the cap the function does not scan; it returns a single `"input too large to scan ({} bytes; limit {}) — restore safety was NOT checked"` warning. That is a non-empty result, so `guarded_restore()` treats oversized model output as suspicious rather than silently unchecked — chunk the reply if you need it inspected.

---

## SecurityWarning

```python
from argus_redact import SecurityWarning
```

A `UserWarning` subclass, emitted when something would silently weaken redaction or when a restore did not go cleanly. It is the human-facing backstop for callers who are not reading `security_events`; the restore paths raise it for a fail-closed guard, a partial (out-of-scope) restore, an advisory H hit, and — since v0.8.0 (R4) — an unguarded (`guard=None`) restore that actually reinserted an original with no injection check.

The message carries **reason codes and counts only** — never the event `detail` — so it is safe to route into an ordinary log stream. The warning is attributed to your call site, not to argus-redact's internals.

```python
import warnings
from argus_redact import guarded_restore, SecurityWarning

# Promote to an exception in tests / CI
warnings.simplefilter("error", SecurityWarning)

# Or catch and inspect
with warnings.catch_warnings(record=True) as caught:
    warnings.simplefilter("always", SecurityWarning)
    restored = guarded_restore(llm_output, key, redacted=redacted, anchor=anchor)
if any(issubclass(w.category, SecurityWarning) for w in caught):
    ...
```

Import it from the top level (`argus_redact.SecurityWarning`); it lives in `argus_redact.exceptions` and is still re-exported from its historical home, `argus_redact.pure.replacer`, for backward compatibility.

For programmatic handling, prefer the structured channel — `detailed=True` (events) or `strict=True` (`RestoreGuardError`) — over parsing warning text.

---

## wipe_key()

```python
from argus_redact import wipe_key

wipe_key(key: dict) -> None
```

Clear a key dict to minimize PII exposure in memory. Removes all entries so references can be garbage collected sooner.

```python
redacted, key = redact(text)
anchor = make_anchor(key)
# ... send `redacted` to the LLM with prompt_anchor(key, anchor=anchor) ...
restored = guarded_restore(llm_output, key, redacted=redacted, anchor=anchor)
wipe_key(key)  # done with key, clear it
```

**Limitation:** Python strings are immutable and cannot be securely erased from memory. `wipe_key` removes dict references but string content may persist until GC. For high-security scenarios, run argus-redact in a short-lived process.

---

## is_strategy_reversible() *(v0.5.9+)*

Public helper for callers that need to know whether a redaction strategy's
surrogate is **safe to restore from an LLM round-trip** — a narrower question than
"can the key dict map it back". Every strategy is key-recoverable: `redact()` always
writes `surrogate -> original` into the returned `key` (or, for `keep`, leaves the
original verbatim with no key entry needed), so that broader question is always
`True` and is not what this function answers *(clarified v0.8.0, H2 — the docstring
previously implied the broader question; see `RedactReport.residual_personal_data`
in [security-model.md](security-model.md#redactreportresidual_personal_data) for
that one)*. `is_strategy_reversible` instead flags whether the surrogate is
*content-derived* from the original (`mask`-family surrogates like `138****5678`
carry a disambiguator that can be mangled by LLM normalization) versus
shape-independent (`pseudonym` / `realistic` / `remove` / `keep`, which survive an
LLM reply reliably).

```python
from argus_redact import is_strategy_reversible
from argus_redact.specs import get

is_strategy_reversible("pseudonym")   # True
is_strategy_reversible("mask")        # False — fragile under LLM round-trip
is_strategy_reversible("nonexistent") # raises ValueError

# PIITypeDef exposes the same answer for the type's *default* strategy:
get("zh", "phone").is_reversible      # False (default = mask)
get("zh", "person").is_reversible     # True  (default = pseudonym)
```

| Strategy | LLM round-trip safe? | Why |
|---|:---:|---|
| `pseudonym` | ✓ | random code, shape-independent of the original |
| `realistic` | ✓ | reserved-range fake, shape-independent of the original |
| `remove` | ✓ | per-type `[ID-NNNNN]` code, shape-independent of the original |
| `keep` | ✓ | original text untouched |
| `mask` | ✗ | content-derived (`138****5678`); collision disambiguator is fragile under LLM normalization |
| `name_mask` | ✗ | content-derived (`张*` style); same fragility |
| `landline_mask` | ✗ | content-derived, masked middle digits; same fragility |
| `category` | ✗ | many-to-one mapping (`[LOCATION]`); ambiguous on restore |

All eight strategies are key-recoverable regardless of this table — the ✗ rows are
about surviving an *LLM* round-trip specifically, not about whether `restore()` can
look the value up in the key.

When two originals actually collide on the same mask/category/remove surrogate,
argus-redact emits a `SecurityWarning` naming the collision (count and types only,
never the raw values) — see [Masked-value collisions](security-model.md#masked-value-collisions-are-not-guaranteed-llm-round-trip-reversible)
in the security model. Treat the collided entries as non-restorable across an LLM
round-trip rather than relying on the `①`-style disambiguator surviving a rewrite.

### When to use

Multi-turn dialog flows where the LLM may echo redacted values back: prefer
reversible strategies so the assistant can quote real PII to the user. Audit
flows where partial visibility is preferred can stay on `mask` / `category`.

To force-override a single type to a reversible strategy:

```python
from argus_redact import redact

redact(text, config={"phone": {"strategy": "remove"}})  # PHONE-NNNNN, reversible
```

> ⚠️ **Error contract:** Raises `ValueError` for any input not in the valid strategy list (including `None`, empty string, and unknown names). The exception message lists all valid strategies. This is intentional fail-loud behavior — the function is meant as a safety predicate before a destructive `restore()`, where silently returning `False` for an unknown input would be unsafe. Callers should validate strategy names at config-load time, not at restore time.

---

## Layer Constants *(v0.5.9+)*

`argus_redact.layers` exposes the canonical layer names used throughout the
detection pipeline and `PatternMatch.layer` field. Downstream consumers
should import from this module rather than defining their own constants.

```python
from argus_redact.layers import (
    LAYER_REGEX,            # 1
    LAYER_REGEX_EVIDENCE,   # "1b"
    LAYER_NER,              # 2
    LAYER_SEMANTIC,         # 3
    LAYER_NAMES,            # dict[int | str, str] with descriptions
)
```

| Constant | Value | Description |
|---|---|---|
| `LAYER_REGEX` | `1` | L1: regex pattern matching with prefix/suffix context |
| `LAYER_REGEX_EVIDENCE` | `"1b"` | L1b: evidence scoring on regex candidates (PII proximity, honorifics, kinship) |
| `LAYER_NER` | `2` | L2: NER model (HanLP / spaCy) for open-vocabulary entities |
| `LAYER_SEMANTIC` | `3` | L3: semantic LLM judgment (Ollama-backed) |

### Notes

- `PatternMatch.layer` is `int`-typed. L1b is a sub-stage of L1 — its
  candidates carry `layer=1`, not `"1b"`. The `"1b"` sentinel is for
  documentation and `LAYER_NAMES` lookup only.
- `LAYER_NAMES` is a `dict[int | str, str]`. Iterate it for tables and
  generated docs; do not hardcode descriptions.
- Adding a new layer index is a coordinated change: `_types.PatternMatch.layer`,
  the relevant glue stage in `glue/redact.py`, and this constant set.

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
result.score                   # 0.85
result.level                   # "critical"
result.reasons                 # ("id_number (critical)", "phone (high)", ...)
result.pipl_articles           # ("PIPL Art.13", "PIPL Art.28", "PIPL Art.51", ...)
result.gdpr_special_category   # False (id_number/phone not GDPR Art.9)        ← v0.5.9+
result.hipaa_categories        # ("phone_numbers",)                            ← v0.5.9+
```

**v0.5.9+**: `pipl_articles`, `gdpr_special_category`, and `hipaa_categories`
are read from `PIITypeDef` metadata via `argus_redact.specs.get(lang, name)`.
Gateway DPIA generators can read the same data statically:

```python
from argus_redact.specs import get
get("zh", "medical").pipl_articles
# → ("PIPL Art.13", "PIPL Art.28", "PIPL Art.51", "PIPL Art.29", "PIPL Art.55", "PIPL Art.56")
get("zh", "medical").gdpr_special_category   # True (GDPR Art.9 health data)
get("zh", "medical").hipaa_phi_category      # "medical_record"
```

The full mapping is documented in [`docs/pii-types.md`](pii-types.md). Rules
live in `src/argus_redact/specs/_compliance.py` — change them once and every
typedef + risk report picks up the change.

### Report mode

```python
from argus_redact import redact

report = redact("身份证110101199003074610，手机13812345678", report=True, mode="fast")
report.redacted_text                # redacted text
report.key                          # {replacement: original}
report.entities                     # tuple of entity dicts
report.stats                        # {"total": 2, "layer_1": 2, ...}
report.risk.score                   # 0.85
report.risk.level                   # "critical"
report.risk.pipl_articles           # ("PIPL Art.13", "PIPL Art.28", "PIPL Art.51", ...)
report.risk.gdpr_special_category   # False                                    ← v0.5.9+
report.risk.hipaa_categories        # ("phone_numbers",)                       ← v0.5.9+
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

## Compliance metadata exports *(v0.6.5+)*

Three top-level `dict` exports project per-PII-type compliance metadata from the registry. Downstream audit-report and compliance tooling can consume the canonical mapping from upstream instead of hand-coding a copy.

```python
from argus_redact import (
    PIPL_REFERENCES,           # dict[str, tuple[str, ...]]
    GDPR_SPECIAL_CATEGORIES,   # dict[str, bool]
    HIPAA_PHI_CATEGORIES,      # dict[str, str | None]
)

PIPL_REFERENCES["phone"]
# ('PIPL Art.13', 'PIPL Art.51')

GDPR_SPECIAL_CATEGORIES["medical"]
# True

HIPAA_PHI_CATEGORIES["phone"]
# 'phone_numbers'

HIPAA_PHI_CATEGORIES["self_reference"]
# None  (self_reference is not a HIPAA Safe Harbor identifier)
```

| Export | Shape | Notes |
|---|---|---|
| `PIPL_REFERENCES` | `dict[str, tuple[str, ...]]` | Empty tuple is treated as a defect (every registered type cites at least one article — enforced by `tests/architecture/test_compliance_metadata_export.py`). |
| `GDPR_SPECIAL_CATEGORIES` | `dict[str, bool]` | `True` for Article 9 special-category data (health, biometric, religion, political opinion, sexual orientation, etc.). To derive specific article numbers, callers may use ``["GDPR Art.9"] if flag else ["GDPR Art.6"]`` — argus-redact does not embed these article codes itself because the lawful-basis selection is controller-context-dependent. |
| `HIPAA_PHI_CATEGORIES` | `dict[str, str \| None]` | Safe Harbor identifier category string when the type IS a HIPAA identifier; `None` when not. |

Keys are the **canonical PII type names** (e.g., `"phone"`, `"id_number"`, `"medical"`). Aliases used by downstream consumers (e.g., `"phone_number"`, `"cn_id_card"`) must be mapped to canonical names on the consumer side.

When the same canonical name appears across multiple language variants (the registry has both a `zh` and `en` `phone`, etc.), variants are merged: `PIPL_REFERENCES` unions articles preserving order, `GDPR_SPECIAL_CATEGORIES` ORs flags, `HIPAA_PHI_CATEGORIES` takes the first non-`None` value (registry order is `zh` → `en` → `shared`, deterministic for a given argus-redact version).

The dicts are computed once at module import. Custom types registered via `argus_redact.specs.register()` after import are not reflected — by design.

---

## AuditLedger *(v0.7.18+)*

```python
from argus_redact import AuditLedger, AuditEntry, collect_security_events

AuditLedger(
    *,
    hmac_key: bytes | None = None,
    clock: Callable[[], str] | None = None,
)
```

A caller-owned, append-only, **PII-free**, hash-chained ledger that is simultaneously
the audit trail and the tamper-evident record. It carries no built-in I/O — like the
redaction key, persistence is the caller's responsibility.

```python
from argus_redact import redact, restore, AuditLedger

led = AuditLedger()

# Record a redact operation
redact_result = redact("姓名张伟，手机13812345678", lang="zh", mode="fast", detailed=True)
text, key = redact_result[0], redact_result[1]
led.record_redact(redact_result)

# ... send text to LLM, receive response ...

# Record a restore operation. guard=False here opts out of the guarded round-trip
# for this local illustration; production callers restoring LLM output should use
# the guarded flow (make_anchor / prompt_anchor / restore(guard=True, anchor=...)
# or guarded_restore()).
restore_result = restore(text, key, guard=False, detailed=True)
led.record_restore(restore_result)

assert led.verify() is True
print(led.head_digest)  # 64-char hex SHA-256 string

# Persist across sessions
import json
saved = json.dumps(led.to_dict())
led2 = AuditLedger.from_dict(json.loads(saved))
assert led2.verify() is True
```

### PII-free invariant

The ledger stores only: PII type names and counts (`type_counts`, e.g.
`{"person": 2, "phone": 1}`), sanitized security events (`reason_code` + `count`
only — the free-form `detail` field is stripped at append time), and one-way SHA-256
digests. It never stores original text, the pseudonym → original key, or an event's
raw `detail`. *(v0.8.0, H5)* `AuditEntry.from_dict` re-sanitizes events on load too,
so loading a hand-crafted or tampered on-disk ledger cannot smuggle PII into memory
even if the stored `detail` was never sanitized to begin with.

### Methods

| Method | Signature | Notes |
|---|---|---|
| `append` | `append(kind, *, type_counts, security_events=(), content_digest=None) -> AuditEntry` | Low-level primitive both sugar methods below call. |
| `record_redact` | `record_redact(detailed_result, *, content_digest=None) -> AuditEntry` | Accepts the 3-tuple from `redact(detailed=True)`. Counts detected entity types; `content_digest` defaults to a SHA-256 of the **redacted** text (never the original). |
| `record_restore` | `record_restore(detailed_result, *, content_digest=None) -> AuditEntry` | Accepts the 2-tuple from `restore(detailed=True)`. Records any security events; does **not** auto-digest the restored text (recovered plaintext should not be fingerprinted into the ledger by default) — pass `content_digest=` explicitly if your threat model needs it. |
| `verify` | `verify() -> bool` | Recomputes every entry hash and the `prev_hash` chain. `True` if intact, `False` on any interior modification, reorder, or deletion. |
| `head_digest` | *(property)* `str` | The current chain-head hash, or `""` if empty. Persist this externally to detect tail-truncation (see below). |
| `entries` | *(property)* `tuple[AuditEntry, ...]` | Read-only view of the recorded entries. |
| `to_dict` | `to_dict() -> dict` | `{"schema_version": 1, "hmac": bool, "entries": [...]}`. Never includes `hmac_key` itself. |
| `from_dict` | `AuditLedger.from_dict(d, *, hmac_key=None) -> AuditLedger` | Reloads a persisted ledger. Raises `ValueError` if `d["hmac"]` is `True` and no `hmac_key` is supplied — a clear error instead of a silent `verify() == False`. |

`collect_security_events(result)` is a standalone helper: given a `RedactReport`, a
`redact(detailed=True)` 3-tuple, or a `restore(detailed=True)` 2-tuple, it extracts
the `security_events` list uniformly (`[]` for anything else). `record_redact` /
`record_restore` use it internally; call it directly if you're building a custom
ledger entry.

### Keyless vs. HMAC — the forge boundary

The default constructor (`AuditLedger()`) chains entries with plain SHA-256:
**append-only integrity** — `verify()` reliably detects interior modification,
reordering, and deletion of entries. It does **not** detect:

- **Tail-truncation** — dropping the most recent entries leaves a valid shorter
  chain. Persist `head_digest` externally (a separate log, a notary service, a
  signed receipt) and compare after reload.
- **Full-chain forgery** — an adversary who controls the ledger store can recompute
  a self-consistent chain from scratch; `verify()` returns `True` on it. This is the
  keyless default's honest boundary, stated explicitly in `verify()`'s and the
  class's docstrings *(v0.8.0, H5)*.

Pass `hmac_key=secrets.token_bytes(32)` (kept separate from the ledger store, never
persisted by `to_dict()`) for forge-resistance: entry hashes become HMAC-SHA-256, and
an adversary who cannot reproduce the key cannot forge a chain that passes
`verify()`.

See [security-model.md § AuditLedger](security-model.md#auditledger) for the full
threat-model writeup, and `docs/known-issues.md` for the caller-persisted /
keyless-by-default design constraint.

---

## Streaming Redact (chunked input)

For chunked input where entities don't cross chunk boundaries, use `StreamingRedactor`. Cross-chunk consistency: same original value in different chunks maps to the same realistic fake (via shared `salt` + accumulated key).

```python
from argus_redact.streaming import StreamingRedactor

redactor = StreamingRedactor(salt=b"my-secret-salt", lang="zh")
for chunk in input_stream:                  # complete sentences/paragraphs/turns
    result = redactor.feed(chunk)
    send_to_llm(result.downstream_text)

# After all chunks fed, the unified key for cross-chunk restore
full_key = redactor.aggregate_key()
```

### Constructor

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `salt` | `bytes` | *(required)* | Required for cross-chunk stable mapping. Same `salt` + same input → same fake. |
| `display_marker` | `str \| None` | `None` (= `ⓕ`) | Marker for `display_text`. |
| `lang`, `mode`, `names`, `types`, `types_exclude` | — | — | Same semantics as `redact_pseudonym_llm()`. |
| `strict_input` | `bool` | `True` | Raises `PseudonymPollutionError` if a chunk contains reserved-range values. Set `False` to disable per-chunk pollution check. |

Sentence-bounded incremental detection runs unconditionally: chunks may split entities mid-value; the redactor accumulates until a sentence boundary, then redacts the buffered prefix. Use `flush()` at end-of-stream to drain the tail. *(The `incremental=False` opt-out, deprecated in v0.5.8, was removed in v0.6.0.)*

### Methods

- `feed(chunk: str) -> PseudonymLLMResult` — redact one chunk. Cross-chunk consistency preserved via internal accumulated key.
- `flush() -> PseudonymLLMResult` *(v0.5.7+)* — drain any text accumulated past the last sentence boundary.
- `aggregate_key() -> dict[str, str]` — copy of the unified key across all fed chunks (for batched restore).
- `export_state(*, include_salt: bool = False) -> dict` *(v0.5.5+; v0.6.2 default no longer includes salt)* — serialize redactor state (accumulated key, all constructor options) to a JSON-friendly dict. Persist to Redis / disk to survive process restarts. The salt is the cryptographic root and is held out-of-band by the caller; pass `include_salt=True` only for trusted-channel handoff (deprecated; will be removed in a future release).
- `from_state(state: dict, *, salt: bytes | None = None) -> StreamingRedactor` *(classmethod, v0.5.5+; v0.6.2 added `salt=` kwarg)* — rebuild an instance from a previously exported state. Pass `salt=` explicitly. Legacy v0.6.0/0.6.1 dumps with embedded salt still load (with `DeprecationWarning`). Subsequent `feed()` calls reuse the same fake values for already-seen originals.

### Incremental mode (v0.5.7 opt-in → v0.5.8 default → v0.6.0 only mode)

The redactor accumulates input until a sentence boundary (`。.！!？?；;\n`), then runs detection + replacement on the buffered prefix. Output for a chunk that has not yet completed a sentence is an empty `PseudonymLLMResult` (caller should accumulate and emit nothing yet). Cross-chunk entity boundaries are handled transparently.

```python
r = StreamingRedactor(salt=b"...", lang="zh", mode="fast")
for chunk in token_stream:
    out = r.feed(chunk)
    if out.downstream_text:
        send_to_llm(out.downstream_text)
final = r.flush()  # drain whatever is past the last boundary
if final.downstream_text:
    send_to_llm(final.downstream_text)
```

Limitations: detection runs per emit-segment (full L1+L2+L3 pipeline on each completed prefix); chunks without sentence punctuation grow the buffer up to 4096 chars before a forced flush. See `docs/design-streaming-incremental.md` for the full design.

### Cross-process resume (v0.5.5+)

```python
import json, redis
from argus_redact.streaming import StreamingRedactor

# Process A — start a session
SALT = b"session-secret-32-bytes-padding!"   # held out-of-band (vault / KMS / env)
r = StreamingRedactor(salt=SALT, lang="zh")
r.feed("张明今天打了13912345678。")
redis_client.set("session:42", json.dumps(r.export_state()))   # state has no salt

# Process B (later, different host) — resume
state = json.loads(redis_client.get("session:42"))
r = StreamingRedactor.from_state(state, salt=SALT)             # salt passed explicitly
result = r.feed("张明又来电话了13912345678确认。")
# Same original phone reuses the same fake from process A
```

State is a plain dict: `version` (integer schema version, decoupled from the package version), `accumulated_key`, plus all constructor options. **The salt is not in `state`** (v0.6.2+); the caller holds it out-of-band and passes it to `from_state(state, salt=...)`. `from_state()` raises `ValueError` for payloads with an unsupported `version` or when no salt is available.

### Constraints

- Caller MUST feed complete logical units; entities split across chunk boundaries are not detected.
- Strict input check applies per-chunk: realistic-faked output from one chunk fed back as input to another raises `PseudonymPollutionError`.
- Detection mode (`mode="ner"` / `"auto"`) runs full pipeline per chunk; cost scales linearly with chunk count.

> ℹ️ True byte-level streaming with realistic mode requires complete entity boundaries and is roadmapped for a later release.

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

`StreamingRestorer` works with **any** replacement strategy (placeholder, pseudonym, mask, realistic). For `pseudonym-llm` profile output it correctly handles all three text forms — pass `audit_text`, `downstream_text`, or `display_text` as input. Pseudonym values that span chunk boundaries are held back until the following text disambiguates them, then restored atomically — on **both** strategies, so streaming output matches what a batch `restore()` of the whole reply would produce no matter where the chunk boundaries fall.

Two strategies:

| `strategy` | Flushes | Holds back |
|---|---|---|
| `"sentence"` (default) | at sentence boundaries (`。.！!？?；;\n`), or at `max_buffer` if none arrives | the straddle tail |
| `"none"` | on every chunk — no sentence buffering | the straddle tail |

The held-back tail is bounded by the longest fake (or alias) in the key. It covers a partial token *and* a token that is complete but not yet followed by anything: a following character can turn a valid match into a non-token — for a numeric fake, into a longer digit run that batch restore deliberately refuses to touch. `flush()` drains whatever is still held.

Pass `aliases=` to restore the alternate transliterations `redact_pseudonym_llm()` returns in its `aliases` field, exactly as batch `restore(text, key, aliases=...)` does — without it, a model that rewrites 张伟 as "Cai Yun" leaves that mention unrestored:

```python
result = redact_pseudonym_llm(text, salt=salt, lang="zh")
restorer = StreamingRestorer(dict(result.key), aliases=dict(result.aliases))
```

> ℹ️ For `display_text` containing visible markers (`ⓕ`), the markers stay in the streamed output (the underlying `key` doesn't include them). To strip markers, call `strip_display_markers(text, marker="ⓕ")` from `argus_redact.pure.display_marker` on the streamed output, or feed `downstream_text` instead.

**Unguarded by design.** Every `feed()` / `flush()` substitution runs `restore(..., guard=False)` — there is no per-call anchor to check mid-stream, so `StreamingRestorer` cannot fail closed the way `guarded_restore()` does. The first time an instance actually reinserts a pseudonym, it emits a one-time `SecurityWarning`; it does not warn again for the rest of that instance's lifetime. If you need the provenance/scope guard, buffer the full reply and call `guarded_restore()` once instead of streaming the restore.

`StreamingRestorer(key, max_buffer=4096)` bounds the "sentence" strategy's buffer the same way `StreamingRedactor` does: a reply that never emits a sentence terminator is force-flushed once the buffer exceeds `max_buffer`, instead of accumulating without limit. The straddle tail sits on top of that as fixed headroom, so the real bound is `max(max_buffer, longest fake)` — a token is never split just to satisfy the buffer bound.

**Single-session, not thread-safe.** Construct one `StreamingRestorer` per thread / per session, same as `StreamingRedactor` above; do not share one instance across threads. `feed()`/`flush()` borrow the underlying Rust restore session's state on every call, so a concurrent call on a shared instance from another thread raises `Already borrowed` instead of corrupting output.

---

## Structured Data

Redact PII in JSON structures and CSV strings:

```python
from argus_redact.structured import redact_json, restore_json, redact_csv, restore_csv

# JSON — recursively walks all scalar leaf values
data = {"user": {"name": "张三", "phone": "13812345678"}, "action": "login"}
redacted, key = redact_json(data, mode="fast")
restored = restore_json(redacted, key)

# CSV — header preserved, each cell redacted
csv_text = "name,phone\n张三,13812345678"
redacted_csv, key = redact_csv(csv_text, mode="fast")
restored_csv = restore_csv(redacted_csv, key)
```

**Scalar leaves, not just strings.** `redact_json` scans every scalar leaf VALUE — strings, `int`/`float`, `Decimal`, `UUID`, and utf-8 `bytes`/`bytearray` (a national ID stored as a JSON number, a SQL `NUMERIC`, or a msgpack byte string all get redacted); a non-string leaf with no detectable PII passes through byte-for-byte with its original type. Dict KEYS are preserved verbatim (structural identifiers, like a CSV header). A leaf whose type cannot be coerced to text — a non-utf-8 byte string, an arbitrary object — is forwarded unchanged and emits a PII-free `SecurityWarning` (path + type name). Pass `on_unscannable="raise"` to fail CLOSED instead: `redact_json` then raises `TypeError` naming those leaves before any document or key is returned, so a security-conscious pipeline never forwards an un-scanned value (mirrors `redact_body(on_missing_field="raise")`).

**Unguarded by design.** `restore_json` / `restore_csv` apply `key` (+ optional `aliases=`) mechanically over every leaf/cell, with no per-call anchor — unlike the scalar `restore()` / `restore_guarded()` faces, which guard by default since v0.8.0 (see [`guard=True` is the default](#guardtrue-is-the-default-v080)). Threading that same provenance/scope guard through structured restore is a cross-layer redesign, not a parameter add, so it stays out of scope here; if a document came back from an LLM reply you don't fully trust, restore the plain text through `guarded_restore()` yourself instead. A benign leaf/cell that happens to equal one of `key`'s pseudonym codes is also restored — see each function's docstring for the same collision hazard `restore()` documents.

---

## Limitations

| Limitation | Detail |
|-----------|--------|
| YAML config requires `pyyaml` | Pass dict or JSON file path if pyyaml not installed |
| Streaming restore is sentence-based | Pseudonyms split across chunks are buffered until a sentence boundary |
| `StreamingRestorer` is unguarded | No per-call anchor mid-stream; a one-time `SecurityWarning` fires on the first real substitution, and the buffer is capped (`max_buffer`, default 4096) |
| `restore_json` / `restore_csv` are unguarded | Same reasoning as `StreamingRestorer` above — a stored key applied over a whole document with no per-call anchor. A benign leaf/cell that coincidentally equals a pseudonym code is also restored (see [Structured Data](#structured-data)) |
| `restore()` is global replacement | If LLM output naturally contains a pseudonym pattern, it gets replaced. Use a unique `prefix` in `config` to minimize risk |
| Pseudonym codes auto-expand | 5-digit codes (99,999 per prefix); automatically expands range on exhaustion |
