# Language Packs

A language pack teaches argus-redact how to detect PII in a specific language. Each pack provides three things:

1. **Regex patterns** — deterministic patterns for that country/language (phone numbers, ID cards, etc.)
2. **NER adapter** — connects a NER model for entity recognition (person, location, organization)
3. **Semantic prompts** — instructions for Layer 3 LLM to understand language-specific PII context

You can contribute any one of these independently. A pack with only regex patterns is still useful.

### Current Status

| Language | Regex (Layer 1) | NER (Layer 2) | Install |
|----------|:---------------:|:-------------:|---------|
| **Shared** (all langs) | email, IP, age, gender, MAC, IMEI, URL token | — | core |
| Chinese (zh) | 20+ types (phone, ID, bank card, passport, address, medical, ...) | HanLP | `[zh]` |
| English (en) | SSN, phone, credit card, DOB, passport, medical, ... | spaCy | `[en]` |
| Japanese (ja) | phone, My Number | spaCy | `[ja]` |
| Korean (ko) | phone, RRN | spaCy | `[ko]` |
| German (de) | tax ID, IBAN, phone | spaCy | `[de]` |
| UK (uk) | postcode, NINO, NHS number, phone | spaCy | `[uk]` |
| Indian (in) | Aadhaar, PAN, phone | spaCy | `[in]` |
| Brazilian (br) | CPF, CNPJ, phone | — | `[br]` |

For per-language pattern details, validation rules, and test cases:
- **Patterns:** `src/argus_redact/lang/<code>/patterns.py`
- **Test fixtures:** `tests/fixtures/<code>_*.json` (executable examples with descriptions)
- **Run tests:** `pytest tests/lang/test_<code>.py -v`

---

## Creating a Language Pack

A language pack is a Python package under `argus_redact/lang/<code>/`. Minimum structure:

```
argus_redact/lang/ja/
├── __init__.py          # Pack metadata (LANG_CODE, LANG_NAME)
├── patterns.py          # Layer 1 regex patterns
└── ner_adapter.py       # Layer 2 NER adapter (optional)
```

### Step 1: patterns.py (Layer 1)

Define regex patterns for country-specific PII:

```python
PATTERNS = [
    {
        "type": "my_number",                    # Entity type name
        "label": "[マイナンバー]",                # Replacement text
        "pattern": r"\d{4}\s?\d{4}\s?\d{4}",   # Regex
        "validate": validate_my_number,          # Optional: reduces false positives
        "description": "Japanese My Number",
    },
]
```

**Pattern fields:**

| Field | Required | Description |
|-------|----------|-------------|
| `type` | Yes | Entity type identifier |
| `label` | Yes | Default replacement text for `remove` strategy |
| `pattern` | Yes | Python regex |
| `validate` | No | `callable(str) -> bool` — post-match validation (e.g., checksum) |
| `check_context` | No | `bool` — enable arithmetic/context false positive filter |
| `group` | No | Named group to extract (keyword-triggered patterns) |
| `description` | No | Human-readable description |

### Step 2: ner_adapter.py (Layer 2)

Implement the `NERAdapter` interface:

```python
from argus_redact._types import NEREntity
from argus_redact.impure.ner import NERAdapter

_TYPE_MAP = {"PERSON": "person", "GPE": "location", "ORG": "organization"}

class JapaneseNERAdapter(NERAdapter):
    def load(self) -> None:
        import spacy
        self._nlp = spacy.load("ja_core_news_sm")

    def detect(self, text: str) -> list[NEREntity]:
        doc = self._nlp(text)
        return [
            NEREntity(text=ent.text, type=_TYPE_MAP[ent.label_],
                      start=ent.start_char, end=ent.end_char, confidence=0.80)
            for ent in doc.ents if ent.label_ in _TYPE_MAP
        ]

def create_adapter() -> JapaneseNERAdapter:
    return JapaneseNERAdapter()
```

### Step 3: Register

Add to `pyproject.toml`:

```toml
[project.optional-dependencies]
ja = ["spacy>=3.0"]
```

### Step 4: Test fixtures

Create `tests/fixtures/ja_*.json` with test cases:

```json
[
  {"id": "phone_mobile", "input": "電話090-1234-5678", "should_match": true,
   "type": "phone", "expected_text": "090-1234-5678", "description": "Mobile number"},
  {"id": "plain_text", "input": "今日はいい天気", "should_match": false,
   "type": "phone", "description": "No PII"}
]
```

Test fixtures are the specification. If the test passes, the pattern works. **No real PII in test data.**

---

## Contributing

1. Fork the repository
2. Create `argus_redact/lang/<code>/` with at minimum `patterns.py`
3. Add test fixtures in `tests/fixtures/<code>_*.json`
4. Add test class in `tests/lang/test_<code>.py`
5. Submit PR

Partial packs are welcome — regex-only is useful. NER and semantic can be added later.
