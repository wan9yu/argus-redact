# Recipe: writing a detector adapter

> v0.6.11+ · part of `argus_redact.compose`

## 30-second pitch

You have PII detection logic outside argus_redact — Presidio, a custom
spaCy NER model, an ML classifier for domain entities, or a list of
regexes for internal codes. You want its output to flow through
argus_redact's `redact() → restore()` round-trip with stable pseudonyms,
full pipeline guarantees, and per-message keys.

The three Layer 2 primitives — `register_pii_type`, `PIITypeDef`,
`PatternMatch` — plus the `_pre_detected=` private kwarg on `redact()`
give you an adapter surface. The in-tree reference is
`src/argus_redact/integrations/presidio.py:PresidioBridge`.

## When to use

- You use Presidio (`PresidioBridge` is the in-tree reference)
- You have a custom spaCy NER model
- You run an ML classifier for domain-specific entities (employee IDs,
  SKUs, internal product codes)
- You have a regex list that argus_redact's built-in types don't cover

## When NOT to use

- **Detect-only without restoring** — build a gateway-side validator
  instead; this layer is for round-trip flows.
- **Full plugin framework** (discovery, lifecycle, hot reload) — out of
  scope for argus_redact; build that in your application layer.
- **A few missing built-in types** — file an upstream issue rather than
  writing a runtime adapter, so it benefits everyone.

## The three Layer 2 primitives

### `register_pii_type(typedef)`

Adds a custom PII type to the runtime registry so `redact()` / `restore()`
treat it like a built-in. argus_redact looks up the type's `strategy`
(e.g. `"pseudonym"`) and `sensitivity` from the registry; the rest comes
from the matches you feed via `_pre_detected=`.

```python
from argus_redact.compose import register_pii_type, PIITypeDef

register_pii_type(PIITypeDef(
    name="employee_id",
    lang="en",
    format="EMP-NNNNNN",        # human-readable, docs only
    strategy="pseudonym",
    sensitivity=2,              # int 1-4 (1=low, 2=medium, 3=high, 4=critical)
))
```

After registration, an entity with `type="employee_id"` passed via
`_pre_detected=` flows through the normal pipeline.

### `PIITypeDef`

The frozen dataclass for type definitions. Fields adapter authors
commonly touch:

| Field | Required | Purpose |
|---|---|---|
| `name` | yes | Type identifier (used in `PatternMatch.type` and CLI `types` filter) |
| `lang` | yes | `"zh"`, `"en"`, or `"shared"` |
| `format` | yes (`""` OK) | Human-readable format string for docs |
| `strategy` | no (defaults `"remove"`) | One of `"mask"`, `"pseudonym"`, `"remove"`, `"category"` |
| `sensitivity` | no (defaults `2`) | Int 1-4 |
| `label` | no | Placeholder label override |
| `description` | no | Free-form |
| `faker_reserved` | no | Custom `realistic`-strategy faker: `(value: str, rng: _core.ShakeRng) -> tuple[str, list[str]]`. Invoked mid-loop via the Rust orchestrator's `PyFakerFactory` callback — must be deterministic from the rng. Does **not** force a pure-Python fallback. |

Compliance fields (`pipl_articles`, `gdpr_special_category`,
`hipaa_phi_category`) are auto-derived from `name + sensitivity` via
`argus_redact.specs._compliance`. You can override them but usually
don't — the central rule book is the source of truth.

For the full field list see `src/argus_redact/specs/registry.py`
(`PIITypeDef`).

### `PatternMatch`

The frozen dataclass adapters produce to feed pre-detected entities into
the pipeline:

```python
from argus_redact.compose import PatternMatch

match = PatternMatch(
    type="employee_id",   # MUST match a registered type name
    text="EMP-123456",
    start=5,
    end=15,
    confidence=0.95,      # optional, defaults 1.0 — currently informational
    layer=2,              # optional, defaults 0 — annotates detection layer
)
```

`start` and `end` are character offsets into the original text (Python
`str` indices). `text` must equal `original_text[start:end]` —
argus_redact validates this.

## Putting it together — PresidioBridge-style adapter

Reference implementation: `src/argus_redact/integrations/presidio.py`.

```python
from argus_redact import redact
from argus_redact.compose import (
    register_pii_type, PIITypeDef, PatternMatch,
)
from your_detector import detect_entities  # your code

# Once at startup: declare any custom types
register_pii_type(PIITypeDef(
    name="employee_id", lang="en",
    format="EMP-NNNNNN",
    strategy="pseudonym",
    sensitivity=2,
))

# Per request
def redact_with_adapter(text: str, salt: bytes, lang: str = "en"):
    # 1. Run your detector
    your_entities = detect_entities(text)
    # 2. Convert to PatternMatch list
    matches = [
        PatternMatch(
            type=e.label,
            text=e.span,
            start=e.start,
            end=e.end,
        )
        for e in your_entities
    ]
    # 3. Feed into argus_redact's full pipeline
    return redact(text, lang=lang, salt=salt, _pre_detected=matches)
```

The full pipeline — `MAX_INPUT_SIZE` guard, type validation, profile
resolution, telemetry, normalization, `types` / `types_exclude` filter,
key persistence, restore round-trip — is applied automatically.
`PresidioBridge.redact()` is exactly this pattern.

## The `_pre_detected` hook — stability promise

`_pre_detected` is a private kwarg on `redact()` (underscore prefix).

**Stability promise**: it does not change in any v0.6.x or v1.0 release.
If a public `pre_detected` (no underscore) ships in v1.1+, it will land
with a deprecation cycle — migration is a one-line `sed`.

Until then, callers using `_pre_detected=` are taking on the explicit
risk that the kwarg name may change post-v1.0. For Gateway-style
downstream products this is acceptable because the migration is
mechanical.

## What NOT to do

- **Don't reach into `pure.merger` or `pure.replacer`.** Their internal
  shape may change between releases. The `_pre_detected=` hook gives you
  identical pipeline guarantees through a stable entry point.
- **Don't pre-merge entities yourself.** Pass them as a flat list with
  unresolved overlaps; `redact()` handles dedupe and conflict resolution
  via `pure.merger.merge_entities`.
- **Don't bypass the registry.** A `PatternMatch.type` that isn't in the
  registry will fall through default strategy logic — register first,
  then pass matches.
- **Don't try to auto-detect via `_patterns`** unless you've read the
  per-language specs (`specs/zh.py` / `specs/en.py`) for the pattern-dict
  shape. Most adapters should let their custom detector provide matches
  via `_pre_detected=` instead — simpler, fewer surprises.

## Auto-detected custom types (advanced)

If you need argus_redact's built-in matcher to find your custom type
without an external detector, populate `_patterns` on the `PIITypeDef`
with pre-built pattern dicts:

```python
register_pii_type(PIITypeDef(
    name="employee_id", lang="en",
    format="EMP-NNNNNN", strategy="pseudonym", sensitivity=2,
    _patterns=(
        # pattern-dict shape: see specs/en.py / specs/zh.py for examples
    ),
))
```

This path is more involved. Read `specs/en.py` and `pure/patterns.py`
for the exact dict shape and matcher behavior before using it. Most
adapter authors don't need this — feeding matches via `_pre_detected=`
is simpler and gives you the same pipeline guarantees.

## Combining with `prompt_anchor` / `expand_aliases`

The three Layer 2 helpers compose:

```python
from argus_redact import redact, restore
from argus_redact.compose import (
    register_pii_type, PIITypeDef, PatternMatch,
    prompt_anchor, expand_aliases,
)

# Once at startup
register_pii_type(PIITypeDef(
    name="employee_id", lang="en",
    format="EMP-NNNNNN", strategy="pseudonym", sensitivity=2,
))

def handle(text, salt, system_prompt):
    matches = your_detector.detect(text)
    redacted, key = redact(text, lang="en", salt=salt, _pre_detected=matches)
    anchor = prompt_anchor(key, lang="en")
    expanded = expand_aliases(key, lang="en")

    full_system = f"{system_prompt}\n\n{anchor}"
    llm_output = call_llm(full_system, redacted)
    return restore(llm_output, expanded)
```

The adapter provides detection; `prompt_anchor` anchors placeholders
input-side; `expand_aliases` catches surname+title variants output-side.

## Limitations

- **Synchronous only.** Async detector support is out of scope for
  v0.6.x.
- **No automatic dedupe across multiple adapter outputs.** If you run
  several detectors, dedupe their `PatternMatch` lists in your
  controller before passing to `_pre_detected=`.
- **No built-in confidence-score filtering.** Drop low-confidence
  entities in your controller before passing — `confidence` is currently
  informational, not a gate.
- **Round-trip correctness depends on registration.** Unregistered types
  still get redacted but fall through default strategy logic; the
  pseudonym format won't reflect your intended `format` / `label`.

## See also

- `src/argus_redact/integrations/presidio.py` — in-tree reference adapter
- `docs/architecture-layers.md` — layer model context
- `docs/recipes/compose-prompt-anchor.md` and
  `docs/recipes/compose-expand-aliases.md` — the other two Layer 2 helpers
