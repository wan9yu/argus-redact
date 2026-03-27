# Sensitive Information Taxonomy

## Vision

argus-redact aims to detect **all sensitive information**, not just direct PII identifiers. The three-layer architecture (regex → NER → semantic LLM) naturally maps to different sensitivity levels — from phone numbers with fixed formats to medical diagnoses that require language understanding.

Detection is configurable per type. Users enable what their compliance scenario requires.

---

## Four Levels of Sensitivity

### Level 1 — Direct Identifiers

One piece of data directly identifies a specific person. This is the current focus.

| Type | Status | Layer | Format examples |
|------|:------:|:-----:|-----------------|
| Phone number | ✓ 7 langs | 1 | `13812345678`, `+55 (11) 99876-5432` |
| National ID | ✓ 7 langs | 1 | `110101199003071234` (zh), `123-45-6789` (en SSN) |
| Bank card | ✓ zh/en | 1 | `6222021234567890123` |
| Email | ✓ shared | 1 | `zhang@example.com` |
| Passport | ✓ zh | 1 | `E12345678` |
| License plate | ✓ zh | 1 | `京A12345` |
| Address | ✓ zh | 1 | `北京市朝阳区建国路100号` |
| Person name | ✓ zh | 1b | `张三`, `何秀珍` (candidate + scoring) |
| Person name | ✓ en/ja/ko/de/uk/in | 2 | NER-based |
| Date of birth | planned | 1 | `1990年3月7日`, `03/07/1990`, `1990-03-07` |
| IP address | planned | 1 | `192.168.1.1`, `2001:db8::1` |
| Social account | planned | 1 | WeChat ID, QQ number |
| Military ID | planned | 1 | 军官证号 |
| Social security | planned | 1 | 社保号 |
| Business license | planned | 1 | 统一社会信用代码 |

### Level 2 — Quasi-Identifiers

Cannot identify someone alone, but combinations can. Research shows birth date + gender + zip code identifies 87% of the US population.

| Type | Status | Layer | Notes |
|------|:------:|:-----:|-------|
| Date of birth | planned | 1 | Many formats: `90年3月`, `三月七号`, `March 7th`, `07/03/1990` |
| Age | planned | 1/3 | `今年35岁`, `35-year-old` |
| Gender | planned | 3 | Contextual |
| Workplace | planned | 1b/2 | Similar ambiguity to person names |
| Job title | planned | 3 | `他是骨科主任` |
| School name | planned | 1b/2 | `北大`, `清华附中` |
| Ethnicity | planned | 3 | Contextual |

### Level 3 — Sensitive Attributes

Not identifiers, but high-harm if leaked. Protected by PIPL, GDPR, HIPAA.

| Type | Status | Layer | Notes |
|------|:------:|:-----:|-------|
| Medical / health | planned | 3 | Diagnosis, medication, symptoms, test results |
| Financial | planned | 3 | Salary, debt, credit score, transaction details |
| Religious belief | planned | 3 | Requires semantic understanding |
| Political opinion | planned | 3 | Requires semantic understanding |
| Sexual orientation | planned | 3 | Requires semantic understanding |
| Criminal record | planned | 3 | Requires semantic understanding |
| Biometric description | planned | 3 | Fingerprint, DNA references in text |

### Level 4 — Digital Identifiers

Machine-readable identifiers that can be traced to individuals or devices.

| Type | Status | Layer | Format examples |
|------|:------:|:-----:|-----------------|
| IP address | planned | 1 | `192.168.1.1`, `::ffff:127.0.0.1` |
| MAC address | planned | 1 | `AA:BB:CC:DD:EE:FF` |
| IMEI | planned | 1 | 15-digit device identifier |
| URL with token | planned | 1 | `example.com/verify?token=abc123` |
| Social media handle | planned | 1 | `@username`, WeChat ID |

---

## Layer Mapping

Each type naturally fits one or more detection layers:

```
Layer 1  (regex)          Format-driven. Fixed structure, detectable by pattern.
                          Phone, ID, email, IP, date of birth, card numbers.

Layer 1b (candidate+score) Has structure but is ambiguous. Needs evidence signals.
                          Person names (zh), organization names, school names.

Layer 2  (NER)            Named entities. Model-detected.
                          Person, location, organization (non-zh languages).

Layer 3  (semantic LLM)   Meaning-dependent. No surface pattern.
                          Medical info, financial details, beliefs, opinions.
```

---

## Compliance Profiles (Planned)

Different regulations care about different types. Profiles are pre-configured type sets:

| Profile | Focus | Types enabled | Completion |
|---------|-------|---------------|:----------:|
| `default` | Common PII | All Level 1 direct identifiers (current behavior) | ~70% — missing: date, IP, social |
| `pipl` | China PIPL | All Level 1 + biometric + financial + medical + religious + political | ~20% — Level 1 partial, Level 2-3 not started |
| `gdpr` | EU GDPR | All Level 1 + Level 2 quasi-identifiers + Level 3 special categories | ~15% — Level 1 partial, no quasi-identifiers |
| `hipaa` | US HIPAA | Direct identifiers + medical + 18 PHI types | ~10% — no medical/PHI types |

```python
# Future API
redact(text, profile="hipaa")
redact(text, types=["phone", "id_number", "date_of_birth"])
redact(text, types_exclude=["address"])
```

---

## Design Principles

1. **Structure first, types later.** Get the registry and configuration right before adding 50 types.
2. **Each type earns its place.** Must have test fixtures, false positive analysis, and at least one real-world use case.
3. **Spaces and noise.** Real-world PII often has spaces (`138 1234 5678`), dashes, mixed formatting. Every type must handle noisy input.
4. **Date formats are a minefield.** `1990年3月7日`, `90年3月`, `三月七号`, `1990-03-07`, `03/07/1990`, `March 7, 1990`, `7th March 1990` — date detection requires comprehensive format coverage and context awareness to avoid false positives on plain numbers.
5. **False positive cost varies.** Redacting a non-PII word is annoying; missing real PII is dangerous. But over-redacting destroys LLM utility. Each type needs its own precision/recall tradeoff.
6. **Community-driven languages.** New language packs should be contributed by native speakers who understand local PII formats and regulations.

---

## Roadmap

**Phase 1 — Foundation (current)**
- ✓ 8 PII types for Chinese
- ✓ Person name scoring (candidate + evidence)
- ✓ 7 language packs
- ✓ Spec registry with examples and fakers

**Phase 2 — Expand Level 1**
- Date of birth (multi-format, multi-language)
- IP address (v4, v6)
- Social accounts (WeChat ID, QQ)
- Chinese-specific: social security, military ID, business license
- Spec registry: add `sensitivity` and `compliance` fields

**Phase 3 — Generalize scoring**
- Extend candidate + scoring to organization names, school names
- Compliance profiles (`profile="pipl"`)
- Per-type enable/disable API

**Phase 4 — Semantic detection**
- Layer 3 prompts for medical, financial, political, religious content
- Configurable sensitivity levels
- Multi-language semantic prompts
