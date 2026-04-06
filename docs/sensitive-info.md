# Sensitive Information Taxonomy

## Vision

argus-redact is the **privacy layer between you and AI**. Our goal is not just regulatory compliance — it's ensuring every person can use AI without exposing their identity.

We evaluate privacy from **your perspective**, not a regulator's:

```
Safe      — nothing about you is exposed
Caution   — contains personal info, not dangerous alone
Danger    — can narrow down to you specifically
Exposed   — directly identifies you
```

Three promises guide everything we build:

| Promise | Question | Measure |
|---------|----------|---------|
| **Protected** | Is your PII detected and encrypted? | PRvL P=100%. PII leak 0% across GPT-4o, Claude, Gemini |
| **Usable** | Can AI still understand and help you? | PRvL U=100%. Trigger words preserved, only PII content redacted |
| **Reversible** | Can you get everything back? | PRvL R by task type: reference 100%, extract 50%, creative 0% (by design) |

Compliance with PIPL, GDPR, and HIPAA is a **byproduct** of this design, not the goal.

---

## Four Levels of Sensitivity

| Level | What | Examples | Layer |
|-------|------|---------|-------|
| **1. Direct Identifiers** | Directly identifies a person | phone, ID, bank card, email, passport, person name | L1 regex + L1b scoring |
| **2. Quasi-Identifiers** | Combinations narrow identity | age, gender, date of birth, workplace, school, ethnicity | L1 regex + L2 NER |
| **3. Sensitive Attributes** | High-harm if leaked | medical, financial, religion, political, sexual orientation, criminal record, biometric | L1 keyword + L3 LLM |
| **4. Digital Identifiers** | Machine-traceable | IP address, MAC address, IMEI, URL with token | L1 regex |

For the complete list of supported PII types, formats, and validation rules:
- **Spec registry:** `src/argus_redact/specs/zh.py` (single source of truth)
- **Test fixtures:** `tests/fixtures/zh_*.json`, `en_*.json`, etc. (executable examples)
- **Run `argus-redact info`** to see all supported types and languages

---

## Layer Mapping

```
Layer 1  (regex)          Format-driven. Fixed structure, detectable by pattern.
                          Phone, ID, email, IP, date of birth, card numbers.

Layer 1b (candidate+score) Has structure but is ambiguous. Needs evidence signals.
                          Person names (zh), organization names, school names.
                          Requires at least one structural signal (prefix/suffix/PII proximity).

Layer 2  (NER)            Named entities. Model-detected.
                          Person, location, organization (all languages).
                          Hint-gated: skipped for instruction text, confidence tuned by PII density.

Layer 3  (semantic LLM)   Meaning-dependent. No surface pattern.
                          Implicit medical, financial, beliefs, opinions.
```

---

## Design Principles

1. **Structure first, types later.** Get the registry and configuration right before adding 50 types.
2. **Each type earns its place.** Must have test fixtures, false positive analysis, and at least one real-world use case.
3. **Tests are the spec.** Supported types and their behavior are defined by test fixtures, not documentation. If the test passes, the type works.
4. **False positive cost varies.** Redacting a non-PII word is annoying; missing real PII is dangerous. But over-redacting destroys LLM utility. Each type needs its own precision/recall tradeoff.
5. **Cross-layer collaboration.** Earlier layers pass hints to later layers. L1 detects, L1b and L2 consume hints to adjust thresholds. No layer works in isolation.

---

## Compliance Profiles

```python
redact(text, profile="pipl")   # China PIPL
redact(text, profile="gdpr")   # EU GDPR
redact(text, profile="hipaa")  # US HIPAA

redact(text, types=["phone", "id_number"])      # whitelist
redact(text, types_exclude=["address"])          # blacklist
```
