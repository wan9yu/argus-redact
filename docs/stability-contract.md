# Stability contract

> What a downstream consumer can build against and expect to keep working across
> a minor or patch release. Read this alongside
> [`docs/architecture-layers.md`](architecture-layers.md), which defines the
> Primitive / Compose / Downstream layers this contract scopes over.

This project is the string-level primitive that products such as Argus Gateway
sit on top of. Those products pin an argus-redact version and thread payloads
through it programmatically, so two things have to be predictable version to
version: **the shape of the calls** and **the shape of the JSON that comes
back**. This document states exactly which of those are frozen and which are a
default you may override.

## The canonical import path

There is **one** supported import path: the top-level `argus_redact` package.

```python
from argus_redact import (
    redact, restore,                 # Layer 1 primitive
    redact_json, restore_json,       # structured (JSON), promoted top-level in v0.8.10
    redact_csv, restore_csv,         # structured (CSV),  promoted top-level in v0.8.10
)
```

Submodule paths such as `argus_redact.structured` or `argus_redact.glue.redact`
still resolve and will not be broken gratuitously, but the top-level names are
the contract. New code should import from the top level; deep imports are an
implementation detail and may be reorganised.

## What is frozen

### 1. Public function signatures

The parameter names, order, keyword-only markers, and defaults of the public
functions are frozen. Additive optional **keyword-only** parameters are
backwards-compatible and may appear in a minor release; removing a parameter,
renaming one, reordering positionals, or adding a required parameter is a
breaking change.

- **Layer 1 primitive** — `redact`, `restore`, `assess_risk`,
  `check_restore_safety`, `wipe_key`, `is_strategy_reversible`,
  `max_pseudonym_length`. These are the v1.0 freeze candidates; a breaking
  change here needs a major version bump. Pinned by
  [`tests/architecture/test_frozen_api.py`](../tests/architecture/test_frozen_api.py).
- **Structured API** — `redact_json`, `restore_json`, `redact_csv`,
  `restore_csv`. Pinned by
  [`tests/architecture/test_structured_namespace.py`](../tests/architecture/test_structured_namespace.py).

### 2. Wire-face key sets

The three wire faces — the HTTP server, the CLI, and the MCP integration — each
build their own JSON envelope (their shapes differ on purpose; see
[`src/argus_redact/pure/wire.py`](../src/argus_redact/pure/wire.py)). The
**set of top-level keys** each face emits is frozen. A consumer that reads
`resp.json()["risk"]["pipl_articles"]` can rely on those keys existing.

The projection of a single report field is shared across faces via `wire.py`, so
the `risk` sub-object carries the same key set everywhere it appears:

```
risk: { score, level, reasons, pipl_articles,
        gdpr_special_category, gdpr_art10, hipaa_categories }
```

The per-face key sets and the reason each face withholds a field (the MCP face
withholds `entities` because `entities[].original` is raw plaintext read back
into a model's context) are pinned by
[`tests/architecture/test_face_contract.py`](../tests/architecture/test_face_contract.py).
Adding a key is a compatible change; removing or renaming one is breaking.

The `stats` block within the redact envelope carries the layer-status keys and
their value sets — those are documented in
[`docs/architecture-layers.md` § Boundary with Argus Gateway](architecture-layers.md#boundary-with-argus-gateway).

## What is NOT frozen — classification values are an overridable default

The **values** a type classifies to are a curated default, not part of the
contract:

- the PII **type** a span is labelled with,
- its risk **score** / **level**,
- its compliance metadata — `pipl_articles`, `gdpr_special_category`,
  `gdpr_art10`, `hipaa_categories`.

These reflect the current statute review and reference corpora and are expected
to move as the law, the corpora, and detection improve. They can be overridden
per call (`config=`, `profile=`, `register_pii_type`), so a downstream product
that needs a value pinned should pin it in its own configuration rather than
depend on the upstream default staying put. Value changes are recorded in the
[CHANGELOG](../CHANGELOG.md) but do **not** require a major version bump.

The distinction is the key set vs. the value: `risk.pipl_articles` will always
be present and always be a list of strings (frozen key + type), but *which*
articles it lists for a given type is the overridable default.

## Changing something that is frozen

A change to a frozen surface — a signature or a wire-face key set — is a
deliberate, announced event, not an incidental edit:

1. It lands with a **loud CHANGELOG entry** that names the exact signature or key
   that changed, old shape and new.
2. It carries a **notice to the Argus Gateway maintainers** (the canonical
   enterprise downstream) so they can adjust their pinned integration before
   upgrading.
3. A breaking change to a **Layer 1** signature additionally requires a major
   version bump per [`docs/architecture-layers.md`](architecture-layers.md).

The frozen-API and face-contract tests above are the mechanical guard: a change
to any frozen surface turns them red, which is the prompt to run this process
rather than update the snapshot silently.

## See also

- [`docs/architecture-layers.md`](architecture-layers.md) — the layer model and
  the Argus Gateway boundary
- [`docs/api-reference.md`](api-reference.md) — full call and return shapes
- [`CHANGELOG.md`](../CHANGELOG.md) — where value and contract changes are recorded
