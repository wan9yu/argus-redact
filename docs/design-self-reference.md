# Design: Self-Reference & Cross-Layer Hints

## Problem

"我" is not PII. But "我" binds all co-occurring PII to the user's identity. It is the strongest privacy signal in any text — and current PII tools completely ignore it.

```
"确诊了糖尿病"     → about someone (low risk)
"我确诊了糖尿病"   → about the user themselves (critical)
"我妈确诊了糖尿病" → about user's family, locates user through kinship (critical)
```

Beyond identity binding, first-person language enables **cumulative profiling**:

```
Turn 1: "我觉得这个方案不错"     → preference
Turn 2: "我不喜欢加班"           → work attitude
Turn 3: "我最近在看房"           → life status
Turn 4: "我确诊了糖尿病"         → health
```

Each turn alone may be harmless. Together, they build a complete user profile.

## Three Tiers of Self-Reference

Not all "我" are equal. Treatment depends on context:

### Tier 1: Identity Binding (keep, since v0.5.7)

"我" co-occurs with explicit PII in the same text. The first-person reference is detected so it can feed downstream hints (PII density, command-mode), but the pronoun itself is **preserved verbatim** so the LLM gets an intelligible prompt.

```
"我确诊了糖尿病"       → "我确诊了MED-01532"      ← pronoun kept; medical redacted
"我住在望京西路"       → "我住在ADDR-05432"       ← pronoun kept; address redacted
"我妈在301医院住院"    → "我妈在[LOCATION]住院"   ← kinship + location both kept / redacted
```

**Trigger:** other PII entities detected in same text.

> Historical note: v0.5.0–v0.5.6 used `strategy="pseudonym"` for self_reference,
> producing `P-NNN` placeholders. v0.5.7 flipped the default to the new `keep`
> strategy after issue #12 (LLMs treated `P-NNN` chains as gibberish).
> To restore the old behavior, pass
> `strategy_overrides={"self_reference": "pseudonym"}`.

### Tier 2: Preference Leakage (assess, don't replace)

"我" carries personal preferences, opinions, or behavioral signals. Replacing degrades LLM usability without proportional privacy gain.

```
"我觉得这个方案不错"   → don't replace, but note in risk assessment
"我不喜欢加班"         → don't replace, but note
```

**Trigger:** "我" present but no explicit PII. Risk assessment flags `preference_leakage` potential.

### Tier 3: Interaction Command (ignore)

"我" is part of the prompt interaction pattern. It carries zero privacy information — it means "the person typing this", which the LLM already knows.

```
"我想问一下"           → ignore completely
"帮我看看这段代码"     → ignore completely
"请告诉我怎么用"       → ignore completely
```

**Trigger:** matches command patterns (我想问/帮我/请告诉我/我需要/can you help me/tell me how to).

## Implementation: Conditional Replacement

```python
# Detection: always detect self_reference
entities = detect_all(text)    # includes self_reference entities

# Classification (drives the Tier 1/2/3 hint passed to L2/L3)
has_real_pii = any(e.type != "self_reference" for e in entities)
is_command = _is_interaction_command(text)

# v0.5.7+: replacement uses strategy="keep" by default, so the entity
# flows through hints / risk but the original text is preserved at emit
# time. The conditional below classifies the *hint* tier, not whether to
# replace.
if is_command and not has_kinship and not has_real_pii:
    tier = 3   # interaction command — pure prompt noise
elif has_real_pii or has_kinship:
    tier = 1   # identity binding — pronoun keeps, surrounding PII redacts
else:
    tier = 2   # preference leakage — only risk assessment sees it
```

### Merger Priority

self_reference must not be swallowed by overlapping longer entities:

```
"我在协和医院" → "我"(self_reference) + "在协和医院"(org)
                 NOT "我在协和医院"(org) swallowing "我"
```

Merger splits overlapping entities instead of picking a winner.

### Grammar Normalization (English)

After replacing first-person pronouns, verb forms must be normalized:

```
Forward:  "I am sick"    → "P-83811 is sick"     (sent to LLM)
Reverse:  "P-83811 is sick" → "I am sick"        (after restore)
```

Rules: am→is, have→has, 'm→is, 've→has, don't→doesn't. Chinese has no verb conjugation — no action needed.

## Cross-Layer Hints Protocol

Currently the three layers run independently. Hints allow each layer to pass information forward, making the pipeline collaborative instead of parallel.

### Architecture

```
          L1 (Regex)
              │
              ├── entities: [PatternMatch, ...]
              ├── hints: [Hint, ...]          ← NEW
              │
              ▼
          L2 (NER)
              │  receives L1 entities + hints
              ├── entities: [PatternMatch, ...]
              ├── hints: [Hint, ...]          ← enriched
              │
              ▼
          L3 (LLM)
              │  receives L1+L2 entities + hints
              ├── entities: [PatternMatch, ...]
              │
              ▼
          Merger → Replacer → output
```

### Hint Schema

```python
@dataclass
class Hint:
    type: str           # hint category
    region: tuple[int, int]  # (start, end) in original text
    data: dict          # hint-specific payload
    source_layer: int   # which layer produced this hint
```

### Self-Reference Hints (first use case)

L1 always detects self_reference. Even when Tier 2/3 means no replacement, L1 passes hints to L2 and L3:

```python
# L1 detects "我" at position 0, no other PII
hints = [
    Hint(
        type="self_reference_present",
        region=(0, 1),
        data={"pronoun": "我", "tier": 2},
        source_layer=1,
    )
]
```

**How L2 uses it:**
- NER knows first-person text → adjusts entity confidence for nearby spans
- "协和医院" near "我" → higher confidence it's user-related, not a mention

**How L3 uses it:**
- LLM prompt includes self-reference context
- "This text is written in first person. Pay extra attention to implicit PII."

### Obfuscation Hints (second use case)

L1 detects suspicious digit sequences that don't match any pattern:

```python
# "1 3 8 1 2 3 4 5 6 7 8" — not a phone match, but suspicious
hints = [
    Hint(
        type="suspicious_digit_sequence",
        region=(0, 21),
        data={"normalized": "13812345678", "separator": " "},
        source_layer=1,
    )
]
```

**How L2 uses it:**
- NER receives the normalized form → matches phone number
- Maps back to original region (0, 21) for replacement

### Risk Assessment Hints

self_reference hints feed directly into risk assessment:

```python
# Tier 1: "我确诊了糖尿病" → self_reference + medical
risk.score += 0.15  # amplification
risk.reasons += ("self-reference: PII directly linked to user",)

# Tier 2: "我觉得不错" → self_reference only
risk.score += 0.0   # no amplification
risk.flags += ("preference_leakage_potential",)
# Added to report but does not trigger replacement
```

## Scope & Pronouns

### Chinese

| Pattern | Type | Tier |
|---------|------|------|
| 我/我的/我们/我们的 | pronoun | 1-3 (context-dependent) |
| 我妈/我爸/我老公/我儿子/... (28 kinship terms) | kinship | always Tier 1 |
| 我想问/帮我/请告诉我/我需要 | command | always Tier 3 |

### English

| Pattern | Type | Tier |
|---------|------|------|
| I/me/my/mine/myself/we/us/our/ours/ourselves | pronoun | 1-3 (context-dependent) |
| my mom/my husband/my daughter/... (16 kinship terms) | kinship | always Tier 1 |
| can you help me/tell me how/I need to know | command | always Tier 3 |

### Future: Second Person

"你" / "you" can also leak identity in dialogue:

```
"你帮我挂个号" → reveals user is speaking to someone who can access medical system
```

Out of scope for v1. Revisit when multi-turn context is supported.

## Reversibility

Self-reference replacement must be perfectly reversible:

```
Forward:  "我确诊了糖尿病"    → "P-83811确诊了MED-01532"
Reverse:  "P-83811确诊了MED-01532" → "我确诊了糖尿病"

Forward:  "I have diabetes"   → "P-83811 has MED-01532"
Reverse:  "P-83811 has MED-01532" → "I have diabetes"
```

Grammar normalization is reversed after restore (is→am, has→have).

## Testing Strategy

| Layer | Test |
|-------|------|
| Detection | Fixture-driven: zh_self_reference.json, en_self_reference.json |
| Tier classification | Unit: given entities, verify correct tier assignment |
| Conditional replacement | Integration: Tier 1 replaces, Tier 2 doesn't, Tier 3 ignores |
| Merger priority | Unit: self_reference wins overlaps, other entity trimmed |
| Grammar | Unit: forward normalization + reverse on restore |
| Risk amplification | Unit: self_reference + PII → higher score |
| Hints protocol | Unit: L1 produces hints, L2/L3 consume them |
| Roundtrip | E2E: redact → restore = original text |

## Rollout Plan

### Phase 1: Conditional Replacement (current)
- [x] Detection: self_reference patterns for zh + en
- [x] Merger priority: self_reference wins overlaps
- [x] Grammar normalization (en)
- [x] Risk amplification
- [ ] Tier classification (command detection, conditional trigger)
- [ ] Tier 2 risk flags (preference_leakage)

### Phase 2: Hints Protocol
- [ ] Define Hint dataclass
- [ ] L1 emits self_reference hints
- [ ] L1 emits obfuscation hints (suspicious digit sequences)
- [ ] L2 consumes hints (focused NER)
- [ ] Plumb hints through redact() pipeline

### Phase 3: L3 Integration
- [ ] L3 prompt includes self-reference context from hints
- [ ] L3 assesses cumulative profiling risk
- [ ] Cross-turn analysis (requires conversation context)
