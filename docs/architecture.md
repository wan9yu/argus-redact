# Architecture

## Overview

argus-redact is two functions and a processing pipeline between them:

```
redact(text) → (redacted_text, key)
restore(text, key) → plaintext
```

Internally, `redact()` runs a three-layer detection pipeline, deduplicates results, and applies replacement strategies. `restore()` is pure string replacement using the key.

```
                          redact()
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
   ┌─────────┐        ┌─────────┐        ┌──────────┐
   │ Layer 1  │        │ Layer 2  │        │ Layer 3   │
   │ Regex    │        │ NER      │        │ Semantic  │
   │ <1ms     │        │ 10-100ms │        │ 200-2000ms│
   └────┬─────┘        └────┬─────┘        └────┬──────┘
        │                   │                    │
        └───────────┬───────┘────────────────────┘
                    ▼
           ┌──────────────┐
           │ Entity Merger │  ← dedup overlapping spans
           └──────┬───────┘
                  ▼
           ┌──────────────┐
           │ Key Generator │  ← random pseudonyms / category labels / masks
           └──────┬───────┘
                  ▼
           ┌──────────────┐
           │ Replacer      │  ← apply substitutions to text
           └──────┬───────┘
                  ▼
           (redacted_text, key)
```

---

## Layer 1: Pattern (Regex)

**Input:** raw text (str)
**Output:** list of `(start, end, type, matched_text)`

Runs a set of regex patterns against the full text. Each pattern belongs to a language pack (see [Language Packs](language-packs.md)).

```
text = "张三的手机号是13812345678，身份证号是110101199003071234"
       │                │                      │
       │                ├─ match: phone         ├─ match: id_number
       │                │  start=8, end=19      │  start=25, end=43
       │                │                      │
       (not matched by regex — needs NER)
```

**Characteristics:**
- Runs on the full text in one pass (compiled regex union)
- Always returns confidence = 1.0
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
text = "张三的手机号是13812345678"
       │
       ├─ NER: "张三" → PERSON, confidence=0.95
       │
       (phone already caught by Layer 1 — skipped)
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

1. **Exact overlap:** Higher-confidence entity wins. Ties: lower layer number wins (regex > NER > LLM).
2. **Partial overlap:** Both kept if non-overlapping portions are meaningful. Otherwise, longer span wins.
3. **Containment:** If entity A contains entity B, keep A only (e.g., "三里屯的星巴克" contains "星巴克").
4. **Confidence filter:** Entities below `min_confidence` (config, default 0.5) are dropped.
5. **Dedup:** Same text at same position from multiple layers → keep one.

**Output:** sorted list of non-overlapping entities, ordered by position in text.

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

text ──────────────────────→ Layer 1 (regex)
                             Layer 2 (NER)         ← optional
                             Layer 3 (semantic LLM) ← optional
                                    │
                             Entity Merger
                                    │
                             Key Generator ←── config (strategies)
                                    │
                             Replacer
                                    │
(redacted_text, key) ←──────────────┘

     │
     ├──→ cloud LLM (only redacted_text leaves device)
     │
     ▼

llm_output ─────────────────→ restore(text, key)
                                    │
                              String replacement
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
│  replace(text, entities, strategy, seed) → (redacted, key)  │
│  restore(text, key) → plaintext                             │
│  merge_entities(layer_results) → deduplicated_entities      │
│  generate_pseudonym(prefix, range, seed) → code             │
│  resolve_collisions(key, label) → unique_label              │
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
│    3. entities += detect_ner(text, lang)       [impure]     │
│    4. entities += detect_semantic(text)         [impure]     │
│    5. entities = merge_entities(entities)       [pure]       │
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
