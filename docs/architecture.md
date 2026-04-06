# Architecture

## Overview

argus-redact is two functions and a processing pipeline between them:

```
redact(text) → (redacted_text, key)
restore(text, key) → plaintext
```

Internally, `redact()` runs a three-layer detection pipeline where each layer passes **hints** to the next, enabling collaborative detection. `restore()` is pure string replacement using the key.

```
                          redact()
                            │
                            ▼
                     ┌─────────────┐
                     │ Layer 1a     │  Regex patterns (<1ms)
                     │ Structural   │  phone, ID, bank card, email, self_reference, ...
                     └──────┬──────┘
                            │
                     produce_hints()
                            │
                     ┌──────┴──────┐
                     │   Hints:     │  self_reference_tier, text_intent, pii_density
                     └──┬───┬───┬──┘
                        │   │   │
                        ▼   │   │
                 ┌──────────┐   │
                 │ Layer 1b  │   │  Person name detection (zh)
                 │ Names     │   │  ← consumes text_intent (threshold adjustment)
                 └─────┬────┘   │
                       │        │
                       │        ▼
                       │  ┌───────────┐
                       │  │ Layer 2    │  NER models (10-100ms)
                       │  │ NER        │  ← consumes text_intent (skip/run)
                       │  │            │  ← consumes pii_density (confidence tuning)
                       │  └─────┬─────┘
                       │        │
                       │        ▼
                       │  ┌───────────┐
                       │  │ Layer 3    │  Local LLM (~20s, optional)
                       │  │ Semantic   │
                       │  └─────┬─────┘
                       │        │
                       └───┬────┘
                           ▼
                    ┌──────────────┐
                    │ Entity Merger │  dedup + priority splitting
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │ Cross-Layer   │  L1+L2 agreement → confidence boost
                    │ Validation    │
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │ Tier Filter   │  ← consumes self_reference_tier
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │ Replacer      │  pseudonyms / masks / category labels
                    └──────┬───────┘
                           ▼
                    (redacted_text, key)
```

---

## Normalize (pre-processing)

Before any detection, `normalize_text()` prepares the text for matching while maintaining an offset map for reversible replacement.

```
Step 1  Strip invisible chars    ZWJ, ZWSP, soft hyphen, BOM, direction controls (16 types)
Step 2  Confusables              Cyrillic/Greek → Latin (~45 pairs, C-level str.translate)
Step 3  NFKC                     Fullwidth → halfwidth, superscript → normal
Step 4  Chinese digit sequences  7+ consecutive digit-equivalent chars → ASCII digits
```

Step 4 is contextual: `一三八零零一三八零零零` (11 Chinese digits) → `13800138000`, but `三月` (1 digit) is left unchanged.

All steps produce an `offset_map` so detected spans map back to original text positions. Replacement and key storage use original text — restore is lossless.

ASCII text skips all steps (`text.isascii()` fast-path).

---

## Layer 1: Pattern (Regex)

**Input:** normalized text (str)
**Output:** list of `(start, end, type, matched_text)`

Runs a set of regex patterns against the full text. Each pattern belongs to a language pack (see [Language Packs](language-packs.md)).

```
text = "张三的手机号是13812345678，身份证号是110101199003071234"
       │                │                      │
       ├─ person (1b)   ├─ match: phone         ├─ match: id_number
       │  score=0.8+     │  start=8, end=19      │  start=25, end=43
       │  (PII proximity)│                      │
```

Layer 1 has two sub-phases:
- **1a: Structural PII** — regex patterns for phone, ID, bank card, email, self-reference pronouns, medical, etc.
- **1b: Person names (zh)** — candidate generation (surname + CJK chars, filtered by negative dictionary) + evidence scoring. **Requires at least one structural evidence signal** (context prefix, honorific suffix, PII proximity) — bare names without evidence are left to Layer 2 NER.

After 1a runs, `produce_hints()` generates **cross-layer hints** that downstream layers consume:

| Hint | Producer | Consumers | Effect |
|------|----------|-----------|--------|
| `self_reference_tier` | L1a | Tier Filter | Tier 1 (replace), 2 (skip), 3 (ignore) |
| `text_intent` | L1a | L1b, L2 | instruction → raise threshold / skip NER |
| `pii_density` | L1a | L2 | high → lower NER confidence threshold |

**Characteristics:**
- 1a runs on the full text in one pass (compiled regex union), always confidence = 1.0
- 1b generates candidates, scores them against evidence signals, confirms above threshold (0.8). Threshold is hint-adjusted: instruction text → 1.2 (effectively suppressed)
- Optional `validate` function per pattern reduces false positives (e.g., Luhn checksum for cards, MOD 11-2 for Chinese ID)
- Language-independent patterns (email, URL) are shared across all packs
- O(n) time complexity, < 1ms for typical texts

**No model loading, no dependencies.** This layer works with `pip install argus-redact` (no extras).

---

## Layer 2: Entity (NER)

**Input:** raw text (str) + Layer 1 results (to avoid re-detecting)
**Output:** list of `(start, end, type, matched_text, confidence)`

Runs a Named Entity Recognition model to detect person names, locations, and organizations.

```
text = "他的同事在星巴克开会"
       │         │
       │         ├─ NER: "星巴克" → ORG, confidence=0.90
       │
       (no structural PII — Layer 1b person scoring has no signals)
```

**Processing steps:**

1. **Sentence splitting** — text is split into sentences (period, newline, etc.)
2. **Chunking** — sentences are grouped into chunks of ≤ 512 tokens
3. **NER inference** — each chunk is processed by the NER model
4. **Span mapping** — entity offsets are mapped back to original text positions
5. **Conflict resolution** — if NER detects an entity that overlaps with a Layer 1 match, Layer 1 wins (higher confidence for deterministic patterns)

**Backend selection:**

| Language | Default backend | Model | Install |
|----------|----------------|-------|---------|
| `zh` | HanLP 2.x | MSRA_NER_ELECTRA | `argus-redact[zh]` |
| `en` | spaCy | en_core_web_sm | `argus-redact[en]` |

**Mixed language:** When `lang=["zh", "en"]`, both NER backends run on the same text. Results are merged by span position. If both backends detect the same span, the higher-confidence result wins.

**First-call overhead:** Model loads into memory on first use (2-5s). Cached for subsequent calls within the same process.

---

## Layer 3: Semantic (LLM)

**Input:** raw text (str) + Layer 1+2 results (already-detected entities)
**Output:** list of `(start, end, type, matched_text, confidence, reason)`

Runs a local small LLM (1-3B parameters, quantized, CPU via llama.cpp) to detect PII that regex and NER miss.

```
text = "老王说他上周在那个地方见了老李，聊了聊那件事"
                        │                      │
       (Layer 1: nothing)                      │
       (Layer 2: 老王→PERSON, 老李→PERSON)       │
       (Layer 3: "那个地方"→implicit location,   │
                 "那件事"→sensitive topic reference)
```

**What Layer 3 catches that Layer 1+2 cannot:**

| Pattern | Example | Why NER misses it |
|---------|---------|-------------------|
| Indirect references | "那个地方", "那件事" | Not named entities |
| Nicknames | "老王", "小李" | Some NER catches these, some don't |
| Identifying descriptions | "住在 XX 小区的那个医生" | Not a name, but identifies someone |
| Context-dependent PII | "他的病" (in medical context = sensitive) | Requires context understanding |
| Compound identifiers | "三里屯的星巴克" (location + brand = precise) | NER sees them separately |

**Processing:**

1. Text is chunked (with overlap for cross-sentence context)
2. Each chunk is sent to the local LLM with a language-specific prompt
3. The LLM returns JSON: `[{"text": "...", "type": "...", "reason": "..."}]`
4. Results are validated against the text (must match actual spans)
5. Merged with Layer 1+2 results

**Model selection:**

| Model | Size | RAM | Quality | Speed |
|-------|------|-----|---------|-------|
| **qwen2.5:3b** (default) | ~2GB | 4GB | Good | ~700ms |
| qwen2.5:7b | ~4GB | 8GB | Better | ~2s |
| qwen2.5:32b | ~20GB | 24GB | Best | ~10-20s |

Inference via Ollama (CPU, no GPU required). Configure with `OLLAMA_MODEL` environment variable.

**This layer is optional.** Requires Ollama running locally. Without it, Layers 1+2 handle most PII.

---

## Entity Merger

After all layers run, results are merged:

```
Layer 1: [(8, 19, "phone", "13812345678", 1.0)]
Layer 2: [(0, 2, "person", "张三", 0.95)]
Layer 3: []
           │
           ▼
Merged:  [(0, 2, "person", "张三", 0.95, layer=2),
          (8, 19, "phone", "13812345678", 1.0, layer=1)]
```

**Rules:**

1. **Priority types (self_reference):** Always win overlaps. When self_reference overlaps with a longer entity (e.g., "我" inside "我在协和医院"), the merger **splits** the longer entity instead of swallowing the priority type.
2. **Exact overlap:** Higher-confidence entity wins. Ties: lower layer number wins (regex > NER > LLM).
3. **Partial overlap:** Longer span wins.
4. **Containment:** If entity A contains entity B, keep A only (e.g., "三里屯的星巴克" contains "星巴克").
5. **Dedup:** Same text at same position from multiple layers → keep one.

**Cross-layer agreement:** After merging, if the same span (or compatible types like address/location) was detected by both L1 and L2, confidence is boosted by 0.1. This rewards entities that multiple independent detectors agree on.

**Output:** sorted list of non-overlapping entities, ordered by position in text.

---

## Cross-Layer Hints

The three detection layers are not independent — earlier layers pass **hints** to later layers via `produce_hints()`. This enables collaborative detection without coupling the layers.

```
L1a (regex) → produce_hints() → hints
                                  │
                    ┌─────────────┼─────────────┐
                    ▼             ▼              ▼
              L1b (person)    L2 (NER)     Tier Filter
              threshold↑      skip/conf↓    keep/drop
```

**Hint types:**

| Hint | Data | Effect |
|------|------|--------|
| `self_reference_tier` | `{tier: 1\|2\|3}` | Tier 1: replace "我" with PII. Tier 2: skip (no PII). Tier 3: ignore (command text) |
| `text_intent` | `{intent: instruction\|narrative\|casual\|neutral}` | instruction → suppress person name detection, skip NER |
| `pii_density` | `{level: none\|medium\|high, count: N}` | high → lower NER confidence threshold (find more names near PII) |

**Design principle:** hints are **suggestions, not commands**. Each consumer decides how to use them. A new hint type can be added without modifying existing consumers.

See [design-self-reference.md](design-self-reference.md) for the self-reference three-tier model and future roadmap.

---

## Key Generator

Takes merged entities and produces the key (replacement mapping).

```
Entities: [("张三", person), ("13812345678", phone), ("星巴克", location)]
           │
           ▼ apply strategies from config
Key:     {"P-037": "张三", "[手机号已脱敏]": "13812345678", "[咖啡店]": "星巴克"}
```

**Strategy dispatch:**

| Strategy | Input | Output | Unique? |
|----------|-------|--------|---------|
| `pseudonym` | "张三" | "P-037" | Yes (random code) |
| `category` | "星巴克" | "[咖啡店①]" | Yes (numbered on collision) |
| `mask` | "13812345678" | "138****5678" | Yes (visible digits differ) |
| `remove` | "110101199003071234" | "[身份证号①]" | Yes (numbered on collision) |
| `generalize` | "北京市朝阳区三里屯" | "[北京市某地址①]" | Yes (numbered on collision) |

**Uniqueness guarantee:** Every replacement in the key must be unique — it's a dict key. `pseudonym` and `mask` produce unique outputs naturally. `category`, `remove`, and `generalize` append a circled number (①②③...) when a collision occurs. First occurrence has no suffix, second gets ①, third gets ②, etc.

**Pseudonym generation:**
- Code = prefix + random integer from `code_range` (default 1-999)
- Codes are **not sequential** — P-037 doesn't imply 37 entities
- Within one `redact()` call, same entity always gets same code
- Across calls (without reusing key), same entity gets different code

**Key reuse (`key=existing_key`):**
- Lookup entity in existing key: if found, reuse the pseudonym
- If not found, generate new random code (checking for collision with existing codes)
- Return the merged key (old + new entries)

---

## Replacer

Takes the original text, merged entities (sorted by position), and key. Produces the redacted text.

```
text:     "张三的手机号是13812345678"
entities: [(0,2,"张三"), (8,19,"13812345678")]
key:      {"P-037":"张三", "[手机号已脱敏]":"13812345678"}
           │
           ▼ replace right-to-left (preserves offsets)
output:   "P-037的手机号是[手机号已脱敏]"
```

**Right-to-left replacement:** Entities are replaced from end of text to start, so earlier offsets remain valid. This avoids the need to recalculate positions after each replacement.

**Edge cases:**

| Case | Behavior |
|------|----------|
| No entities detected | Returns original text unchanged, empty key |
| Entity at start/end of text | Normal replacement |
| Adjacent entities "张三李四" | Both replaced: "P-037P-012" |
| Entity spans punctuation | Replaced as one unit |
| Unicode (emoji, CJK) | Character offsets, not byte offsets |

---

## restore()

Pure string replacement. No layers, no models, no complexity.

```
text:    "P-037 should talk to P-012 about [某公司]"
key:     {"P-037": "王五", "P-012": "张三", "[某公司]": "阿里"}
          │
          ▼ replace longest-first
output:  "王五 should talk to 张三 about 阿里"
```

**Longest-first replacement:** Keys are sorted by length (descending) before replacement. This prevents `[某公司]` from being partially matched if a shorter key `[某]` existed.

**No false matches:** Pseudonym codes (P-037) are unlikely to appear in natural text. Category labels ([咖啡店]) use brackets for the same reason.

**Performance:** O(n × k) where n = text length, k = key size. For typical use (< 100 entities), this is < 1ms.

---

## Data Flow Summary

```
User code                    argus-redact internals
─────────                    ──────────────────────

text ──────────────────────→ Layer 1a (regex)
                                    │
                             produce_hints() → [tier, intent, density]
                                    │
                             Layer 1b (person names) ← hint: text_intent
                             Layer 2 (NER)           ← hint: intent + density
                             Layer 3 (semantic LLM)  ← optional
                                    │
                             Entity Merger (priority splitting)
                                    │
                             Cross-Layer Agreement (L1∩L2 → boost)
                                    │
                             Tier Filter ← hint: self_reference_tier
                                    │
                             Replacer + Grammar Normalization (en)
                                    │
(redacted_text, key) ←──────────────┘

     │
     ├──→ cloud LLM (only redacted_text leaves device)
     │
     ▼

llm_output ─────────────────→ restore(text, key)
                                    │
                              String replacement
                              + Grammar Restoration (en)
                                    │
restored_text ←─────────────────────┘
```

**Key invariant:** The key and original text never leave the user's device. Only the redacted text crosses the network boundary.

---

## Purity Architecture

Not all parts of argus-redact are equal. The codebase is structured into three layers by purity — this drives the testing strategy and the future Rust rewrite boundary.

```
┌─────────────────────────────────────────────────────────────┐
│  Pure Functions (deterministic, no side effects)            │
│  → Unit testable, exact assertions, sub-ms                  │
│  → Rust rewrite candidates                                  │
│                                                             │
│  match_patterns(text, patterns) → [(start, end, type)]      │
│  produce_hints(entities, text) → [Hint, ...]                │
│  filter_self_reference(entities, hints) → entities          │
│  boost_cross_layer(merged, pre_merge) → entities            │
│  replace(text, entities, strategy, seed) → (redacted, key)  │
│  restore(text, key) → plaintext                             │
│  merge_entities(layer_results) → deduplicated_entities      │
│  normalize_grammar_en / restore_grammar_en                  │
│  generate_pseudonym(prefix, range, seed) → code             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  Impure Functions (side effects, non-determinism)           │
│  → Integration testable, mock or real models, seconds       │
│                                                             │
│  detect_ner(text, lang) → entities       ← model loading   │
│  detect_semantic(text, prompt) → entities ← LLM inference   │
│  read_key_file(path) → dict              ← file I/O        │
│  write_key_file(path, key) → None        ← file I/O        │
│  generate_random_seed() → int            ← entropy source   │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  Glue (composes pure + impure)                              │
│  → End-to-end testable, property-based                      │
│                                                             │
│  redact(text, *, key, lang, mode, seed, ...)                │
│    1. seed = seed or generate_random_seed()    [impure]     │
│    2. entities = match_patterns(text)          [pure]       │
│    3. hints = produce_hints(entities, text)    [pure]       │
│    4. entities += detect_person_names(hints)   [pure]       │
│    5. entities += detect_ner(text, hints)      [impure]     │
│    6. entities += detect_semantic(text)        [impure]     │
│    7. entities = merge_entities(entities)      [pure]       │
│    8. entities = boost_cross_layer(entities)   [pure]       │
│    9. entities = filter_self_reference(hints)  [pure]       │
│    6. redacted, key = replace(text, ..., seed)  [pure]       │
│    7. write_key_file(path, key) if needed       [impure]     │
│    8. return (redacted, key)                                 │
└─────────────────────────────────────────────────────────────┘
```

### Testing strategy per layer

| Layer | Test type | Speed | Deterministic? | Example |
|-------|-----------|-------|---------------|---------|
| Pure | Unit test | < 1ms | Yes (with seed) | `assert replace("张三", [...], seed=42) == ("P-037", {...})` |
| Impure | Integration | 1-5s | Model-dependent | `assert len(detect_ner("张三在北京", "zh")) >= 1` |
| Glue | End-to-end | 1-5s | With seed + mode="fast" | `assert "张三" not in redact("张三 138...", seed=42)[0]` |

### Why this matters for Rust

The Pure layer has zero Python dependencies — it's string manipulation, regex, and deterministic RNG. This is the natural Rust boundary:

```
Python process
  │
  ├── Impure layer (Python) — model loading, file I/O
  │     │
  │     ▼
  ├── Pure layer (Rust via PyO3) — regex, replace, key generation, restore
  │     │
  │     ▼
  └── Glue (Python) — composes the above
```

The Pure layer handles all hot paths (regex matching, string replacement, key management). Moving it to Rust gives:
- **Performance:** 10-100x faster regex and string ops for bulk workloads
- **Memory safety:** Key data (sensitive PII mappings) managed by Rust — no GC residue, deterministic destruction
- **Portable CLI:** Standalone Rust binary, no Python runtime needed

The Impure layer stays in Python because model loading (HanLP, spaCy, llama.cpp bindings) is already Python-native, and Python startup overhead doesn't matter when model inference takes 10-2000ms.

### seed parameter flow

```
redact(text, seed=42)
  │
  ├── seed=42 passed to generate_pseudonym()
  │   └── RNG initialized with seed=42 → deterministic codes
  │
  ├── seed=42 does NOT affect:
  │   ├── Pattern matching (already deterministic)
  │   ├── NER detection (model-deterministic)
  │   └── File I/O (orthogonal)
  │
  └── Result: same text + same seed = same output
      (assuming same model version and same installed layers)
```

When `seed=None` (default, production):
- Pseudonym codes use `secrets.randbelow()` — cryptographically random
- Each `redact()` call is unique and unpredictable
- This is what makes per-message keys unlinkable

---

## PII Type Registry (`specs/`)

All PII types are defined in a central registry (`specs/`). Each `PIITypeDef` is the **single source of truth** for a PII type — structure, validation, context, replacement strategy, and evidence.

```
PIITypeDef (specs/zh.py)
    │
    ├── to_patterns()   → regex patterns for match_patterns()
    ├── to_fixtures()   → test case entries from examples/counterexamples
    ├── faker()         → generate fake values for smoke tests
    │
    ├── structure       — format, length, charset, segment descriptions
    ├── validation      — checksum algorithm + validator function
    ├── context         — prefix/suffix words, allowed separators
    ├── action          — replacement strategy, label, mask rules
    └── evidence        — examples, counterexamples, authoritative source
```

### Why this matters

Before the registry, knowledge about each PII type was scattered across patterns, generators, fixtures, and replacer config. Changing one required manually updating the others. Now:

- **Change a separator** → `to_patterns()` reflects it, faker generates it, fixtures test it
- **Add a context word** → the person name pattern picks it up
- **Add a new PII type** → one `register()` call, everything derives from it

### Consistency guarantees

The test suite verifies that specs stay in sync with the runtime:

| Test | What it checks |
|------|---------------|
| `test_every_pattern_type_has_a_spec` | No pattern type without a spec |
| `test_spec_label_matches_pattern_label` | Spec and pattern labels agree |
| `test_spec_strategy_matches_replacer_default` | Spec and replacer strategies agree |
| `test_examples_should_match_patterns` | Spec examples are detected by patterns |
| `test_counterexamples_should_not_match` | Spec counterexamples are rejected |
| `test_faker_output_should_match_own_patterns` | Faker output is detected by patterns |
| `test_build_patterns_replaces_hand_written` | `build_patterns()` is identical to hand-written `PATTERNS` |
