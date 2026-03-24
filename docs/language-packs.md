# Language Packs

A language pack teaches argus-redact how to detect PII in a specific language. Each pack provides three things:

1. **Regex patterns** — deterministic patterns for that country/language (phone numbers, ID cards, etc.)
2. **NER adapter** — connects a NER model for entity recognition (person, location, organization)
3. **Semantic prompts** — instructions for Layer 3 LLM to understand language-specific PII context

You can contribute any one of these independently. A pack with only regex patterns is still useful.

---

## Built-in Packs

### Chinese (`zh`)

Installed with `pip install argus-redact[zh]`.

**Layer 1 — Regex patterns:**

| PII type | Pattern | Example | Validation |
|----------|---------|---------|------------|
| Phone (mobile) | `1[3-9]\d{9}` | 13812345678 | 11 digits, starts with 1[3-9] |
| Phone (landline) | `0\d{2,3}-?\d{7,8}` | 010-12345678 | Area code + number |
| National ID | `[1-9]\d{5}(19\|20)\d{2}(0[1-9]\|1[0-2])...` | 110101199003071234 | 18 digits, MOD 11-2 checksum |
| Bank card | `[3-6]\d{15,18}` | 6222021234567890123 | 16-19 digits, Luhn checksum |
| Email | Standard RFC 5322 | zhang@example.com | Shared across languages |
| Passport | `[A-Z]\d{8}` or `[A-Z]{2}\d{7}` | E12345678 | Chinese passport format |

**Layer 1 — Test cases (should match / should NOT match):**

| Input | Should match? | Type | Why |
|-------|--------------|------|-----|
| `13812345678` | Yes | phone | Standard mobile |
| `+8613812345678` | Yes | phone | With country code |
| `1381234567` | No | — | Only 10 digits |
| `12345678901` | No | — | Starts with 1 but second digit is 2 (invalid) |
| `010-12345678` | Yes | phone | Beijing landline |
| `110101199003071234` | Yes | id_number | Valid checksum |
| `110101199003071235` | No | — | Invalid checksum (last digit wrong) |
| `6222021234567890123` | Yes | bank_card | Valid Luhn |
| `zhang@example.com` | Yes | email | Standard email |
| `E12345678` | Yes | passport | Chinese passport |
| `电话号码格式是1xx` | No | — | Descriptive text, not an actual number |

**Layer 2 — NER adapter:**

| Backend | Entity types | Model |
|---------|-------------|-------|
| HanLP 2.x | PERSON, LOCATION, ORGANIZATION, DATE | hanlp.pretrained.ner.MSRA_NER_ELECTRA |

**Layer 3 — Semantic prompts:**

The LLM receives instructions in Chinese to detect:
- Nicknames and informal references (老王, 小李)
- Implicit locations ("那个地方", "我们公司")
- Contextual PII ("那件事" referring to a sensitive topic)
- Occupation + name combinations that identify someone

### English (`en`)

Installed with `pip install argus-redact[en]`.

**Layer 1 — Regex patterns:**

| PII type | Pattern | Example | Validation |
|----------|---------|---------|------------|
| SSN | `\d{3}-\d{2}-\d{4}` | 123-45-6789 | Format check |
| Phone | `(\+1)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}` | (555) 123-4567 | North American format |
| Credit card | `[3-6]\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}` | 4111-1111-1111-1111 | Luhn checksum |
| Email | Standard RFC 5322 | john@example.com | Shared |
| Date of birth | `\d{2}/\d{2}/\d{4}` and variants | 03/07/1990 | Format check |

**Layer 2 — NER adapter:**

| Backend | Entity types | Model |
|---------|-------------|-------|
| spaCy | PERSON, GPE, ORG, DATE | en_core_web_sm |

---

## Creating a Language Pack

A language pack is a Python package under `argus_redact/lang/<code>/`. Minimum structure:

```
argus_redact/lang/ja/
├── __init__.py          # Pack metadata
├── patterns.py          # Layer 1 regex patterns
├── ner_adapter.py       # Layer 2 NER adapter (optional)
└── semantic_prompts.py  # Layer 3 prompts (optional)
```

### Step 1: patterns.py (Layer 1)

Define regex patterns for country-specific PII:

```python
# argus_redact/lang/ja/patterns.py

PATTERNS = [
    {
        "type": "my_number",                    # Entity type name
        "label": "[マイナンバー]",                # Replacement text (for "remove" strategy)
        "pattern": r"\d{4}\s?\d{4}\s?\d{4}",   # Regex
        "validate": validate_my_number,          # Optional validation function
        "description": "Japanese My Number (個人番号)",
    },
    {
        "type": "phone",
        "label": "[電話番号]",
        "pattern": r"0[1-9]\d{0,3}-?\d{1,4}-?\d{4}",
        "description": "Japanese phone number",
    },
    {
        "type": "phone_mobile",
        "label": "[携帯番号]",
        "pattern": r"0[789]0-?\d{4}-?\d{4}",
        "description": "Japanese mobile number",
    },
]

def validate_my_number(value: str) -> bool:
    """Check digit validation for My Number."""
    digits = value.replace(" ", "")
    if len(digits) != 12:
        return False
    # Check digit algorithm
    weights = [6, 5, 4, 3, 2, 7, 6, 5, 4, 3, 2]
    total = sum(int(d) * w for d, w in zip(digits[:11], weights))
    remainder = total % 11
    check = 0 if remainder <= 1 else 11 - remainder
    return int(digits[11]) == check
```

**Pattern schema:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | `str` | Yes | Entity type identifier (used in config and output) |
| `label` | `str` | Yes | Default replacement text for `remove` strategy |
| `pattern` | `str` | Yes | Python regex pattern |
| `validate` | `callable` | No | Function that takes the matched string and returns `bool`. Reduces false positives. |
| `description` | `str` | No | Human-readable description |
| `priority` | `int` | No | Higher priority patterns are checked first (default: 0) |

### Step 2: ner_adapter.py (Layer 2)

Connect a NER model. Implement the `NERAdapter` interface:

```python
# argus_redact/lang/ja/ner_adapter.py

from argus_redact.layers.ner import NERAdapter, NEREntity

class JapaneseNER(NERAdapter):
    """Japanese NER using GiNZA (spaCy-based)."""

    def __init__(self):
        self._nlp = None

    def load(self):
        import spacy
        self._nlp = spacy.load("ja_ginza")

    def detect(self, text: str) -> list[NEREntity]:
        if self._nlp is None:
            self.load()

        doc = self._nlp(text)
        entities = []
        for ent in doc.ents:
            if ent.label_ in ("Person", "City", "Country", "Company"):
                entities.append(NEREntity(
                    text=ent.text,
                    type=self._map_type(ent.label_),
                    start=ent.start_char,
                    end=ent.end_char,
                    confidence=0.85,  # spaCy doesn't provide per-entity confidence
                ))
        return entities

    def _map_type(self, label: str) -> str:
        return {
            "Person": "person",
            "City": "location",
            "Country": "location",
            "Company": "organization",
        }.get(label, "other")
```

**NEREntity schema:**

| Field | Type | Description |
|-------|------|-------------|
| `text` | `str` | The entity text as found in input |
| `type` | `str` | Mapped entity type (person, location, organization, etc.) |
| `start` | `int` | Character offset start |
| `end` | `int` | Character offset end |
| `confidence` | `float` | 0.0-1.0. Entities below `min_confidence` (config) are dropped. |

### Step 3: semantic_prompts.py (Layer 3)

Provide prompts for the local LLM to detect implicit PII:

```python
# argus_redact/lang/ja/semantic_prompts.py

SYSTEM_PROMPT = """
あなたは日本語テキストのプライバシー分析者です。
テキスト中の暗黙的な個人情報を検出してください：
- 愛称やニックネーム（たろちゃん、先輩）
- 暗示的な場所（「あそこ」「いつもの場所」）
- 文脈から特定可能な情報
- 職業 + 名前の組み合わせ

JSON形式で回答してください：
[{"text": "検出テキスト", "type": "person|location|organization", "reason": "理由"}]

個人情報が検出されない場合は空配列[]を返してください。
"""
```

### Step 4: __init__.py

Register the pack:

```python
# argus_redact/lang/ja/__init__.py

LANG_CODE = "ja"
LANG_NAME = "Japanese"
INSTALL_REQUIRES = ["ginza>=5.0", "ja_ginza>=5.0"]  # pip extras

from .patterns import PATTERNS
from .ner_adapter import JapaneseNER
from .semantic_prompts import SYSTEM_PROMPT
```

### Step 5: Register in setup

Add to `pyproject.toml`:

```toml
[project.optional-dependencies]
ja = ["ginza>=5.0", "ja_ginza>=5.0"]
```

---

## Testing a Language Pack

```python
from argus_redact import redact

# Test regex patterns
text = "山田太郎の電話番号は090-1234-5678、マイナンバーは1234 5678 9012"
redacted, key = redact(text, lang="ja")
print(redacted)
# Expected: "P-037の電話番号は[携帯番号]、マイナンバーは[マイナンバー]"

# Verify key
assert "山田太郎" in key.values() or any("090" in v for v in key.values())

# Test false positive resistance
text2 = "電話番号のフォーマットは090-XXXX-XXXXです"
redacted2, key2 = redact(text2, lang="ja")
# Should NOT redact "090-XXXX-XXXX" — it's a format description, not a real number

# Test NER
text3 = "田中さんが東京タワーの近くの三菱商事で働いている"
redacted3, key3 = redact(text3, lang="ja", mode="ner")
assert "田中" not in redacted3
assert "三菱商事" not in redacted3
```

### Benchmark format

If you have benchmark data, put it in `tests/benchmarks/ja/`:

```json
[
    {
        "input": "山田太郎の携帯は090-1234-5678",
        "entities": [
            {"text": "山田太郎", "type": "person", "start": 0, "end": 4},
            {"text": "090-1234-5678", "type": "phone_mobile", "start": 8, "end": 21}
        ]
    }
]
```

**No real PII in test data.** Use synthetic names, numbers, and addresses only.

---

## Contributing a Language Pack

1. Fork the repository
2. Create `argus_redact/lang/<code>/` with at minimum `patterns.py`
3. Add tests in `tests/lang/test_<code>.py`
4. Add to `pyproject.toml` optional dependencies
5. Submit PR with:
   - Which PII types are covered
   - Which NER backend is used (if any)
   - Whether validation functions are included
   - Known limitations (e.g., "address detection is weak")

Partial packs are welcome — regex-only is useful. NER and semantic can be added later.
