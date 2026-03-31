# Sensitive Information Taxonomy

## Vision

argus-redact is the **privacy layer between you and AI**. Our goal is not just regulatory compliance — it's ensuring every person can use AI without exposing their identity.

We evaluate privacy from **your perspective**, not a regulator's:

```
🟢 Safe      — nothing about you is exposed
🟡 Caution   — contains personal info, not dangerous alone
🟠 Danger    — can narrow down to you specifically
🔴 Exposed   — directly identifies you
```

Three promises guide everything we build:

| Promise | Question | Measure |
|---------|----------|---------|
| **Protected** | Is your PII detected and encrypted? | Detection coverage, false negatives (PRvL P=100%) |
| **Usable** | Can AI still understand and help you? | LLM output quality after redaction (PRvL U=95%) |
| **Reversible** | Can you get everything back? | Pseudonym survival rate, restore completeness (PRvL R-LLM=86%) |

Compliance with PIPL, GDPR, and HIPAA is a **byproduct** of this design, not the goal.

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
| Date of birth | ✓ zh/en | 1 | `1990年3月7日`, `03/07/1990`, `1990-03-07` |
| IP address | ✓ shared | 1 | `192.168.1.1`, `2001:db8::1` |
| Social account | ✓ zh | 1 | WeChat ID, QQ number |
| Military ID | ✓ zh | 1 | 军官证号 |
| Social security | ✓ zh | 1 | 社保号 |
| Business license | ✓ zh | 1 | 统一社会信用代码 (credit_code) |
| US Passport | ✓ en | 1 | `123456789` |

### Level 2 — Quasi-Identifiers

Cannot identify someone alone, but combinations can. Research shows birth date + gender + zip code identifies 87% of the US population.

| Type | Status | Layer | Notes |
|------|:------:|:-----:|-------|
| Date of birth | ✓ zh/en (Level 1) | 1 | Many formats: `90年3月`, `三月七号`, `March 7th`, `07/03/1990` |
| Age | ✓ shared | 1 | `今年35岁`, `35-year-old`, `aged 72` |
| Gender | ✓ shared | 1 | `男`, `female`, contextual patterns |
| Workplace | ✓ zh | 1b/2 | Similar ambiguity to person names |
| Job title | ✓ zh | 1b/2 | `他是骨科主任` |
| School name | ✓ zh | 1b/2 | `北大`, `清华附中` |
| Ethnicity | ✓ zh | 1b/2 | Contextual |

### Level 3 — Sensitive Attributes

Not identifiers, but high-harm if leaked. Protected by PIPL, GDPR, HIPAA.

| Type | Status | Layer | Notes |
|------|:------:|:-----:|-------|
| Medical / health | ✓ zh (explicit) | 1 | Keyword/regex; trigger words preserved (e.g. 确诊 stays, 糖尿病 → MED-code); implicit → Layer 3 LLM |
| Financial | ✓ zh (explicit) | 1 | Keyword/regex; trigger words preserved (e.g. 贷款 stays, amount → FIN-code); implicit → Layer 3 LLM |
| Religious belief | ✓ zh (explicit) | 1 | Keyword/regex detection; implicit → Layer 3 LLM |
| Political opinion | ✓ zh (explicit) | 1 | Keyword/regex detection; implicit → Layer 3 LLM |
| Sexual orientation | ✓ zh (explicit) | 1 | Keyword/regex detection; implicit → Layer 3 LLM |
| Criminal record | ✓ zh (explicit) | 1 | Keyword/regex detection; implicit → Layer 3 LLM |
| Biometric description | ✓ zh (explicit) | 1 | Keyword/regex detection; implicit → Layer 3 LLM |

### Level 4 — Digital Identifiers

Machine-readable identifiers that can be traced to individuals or devices.

| Type | Status | Layer | Format examples |
|------|:------:|:-----:|-----------------|
| IP address | ✓ shared | 1 | `192.168.1.1`, `::ffff:127.0.0.1` |
| MAC address | ✓ shared | 1 | `AA:BB:CC:DD:EE:FF` |
| IMEI | ✓ shared | 1 | 15-digit device identifier (keyword-triggered) |
| URL with token | ✓ shared | 1 | `example.com/verify?token=abc123` |
| Social media handle | ✓ zh | 1 | `@username`, WeChat ID (partial: QQ, WeChat) |

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

## Compliance Profiles

Different regulations care about different types. Profiles are pre-configured type sets:

| Profile | Focus | Types enabled | Completion |
|---------|-------|---------------|:----------:|
| `default` | Common PII | All Level 1 direct identifiers (current behavior) | ~100% — Level 1 complete |
| `pipl` | China PIPL | All Level 1 + biometric + financial + medical + religious + political | ~75% — Level 1 + Level 2 + Level 3 explicit complete; implicit needs Layer 3 LLM |
| `gdpr` | EU GDPR | All Level 1 + Level 2 quasi-identifiers + Level 3 special categories | ~40% — Level 1 + Level 2 complete, Level 3 not started |
| `hipaa` | US HIPAA | Direct identifiers + medical + 18 PHI types | ~20% — Level 1 + Level 2 improved |

```python
# Available now
redact(text, profile="hipaa")
redact(text, types=["phone", "id_number", "date_of_birth"])
redact(text, types_exclude=["address"])

# Risk assessment
from argus_redact import assess_risk, RedactReport
report = redact(text, report=True)  # returns RedactReport
report.risk.score    # 0.0-1.0
report.risk.level    # "low" / "medium" / "high" / "critical"
report.risk.pipl_articles  # ["PIPL Art.28", "PIPL Art.51"]
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
- ✓ 14 PII types for Chinese
- ✓ Person name scoring (candidate + evidence)
- ✓ 8 language packs
- ✓ Spec registry with examples and fakers
- ✓ Date of birth (multi-format, zh/en)
- ✓ IP address (v4, v6)
- ✓ Social accounts (WeChat ID, QQ)
- ✓ Chinese-specific: social security, military ID, business license (credit_code)
- ✓ US Passport

**Phase 2 — Risk Assessment & Compliance Infrastructure (complete)**
- ✓ PIITypeDef: `sensitivity` field (1=low, 2=medium, 3=high, 4=critical)
- ✓ Risk assessment: `assess_risk(entities)` → RiskResult (score + level + reasons + PIPL articles)
- ✓ Audit report: `redact(text, report=True)` → RedactReport
- ✓ Compliance profiles: `redact(text, profile="pipl")`
- ✓ Per-type filtering: `types=["phone"]` / `types_exclude=["address"]`

**Phase 3 — Level 2 Quasi-Identifiers & Scoring Extension (complete)**
- ✓ Age detection: `今年35岁`, `35-year-old` (shared regex)
- ✓ Gender detection: `男`, `female` (shared regex)
- ✓ Job title detection (zh): `骨科主任`, `总经理`
- ✓ Organization names (zh): candidate+scoring
- ✓ School names (zh): `北大`, `清华附中` (candidate+scoring)
- ✓ Workplace detection (zh): contextual
- ✓ Ethnicity detection (zh): contextual
- National LLM framework adapters: Dify plugin, FastGPT plugin (community-driven)

**Phase 4 — Semantic Detection (Layer 3)**

Unlocks Level 3 sensitive attributes. Largest investment, highest compliance impact.

- ✓ Explicit keyword/regex detection for all 7 Level 3 types (criminal_record, financial, biometric, medical, religion, political, sexual_orientation)
- Layer 3 LLM prompts for implicit/contextual detection (medical context, financial inference, political sentiment)
- Industry-specific terminology (medical diagnosis, legal documents, financial products)
- Configurable sensitivity levels per domain
- Multi-language semantic prompts
- Target: PIPL profile from ~75% → 90%+ (implicit detection via LLM)
