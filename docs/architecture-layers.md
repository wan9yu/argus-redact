# Architecture Layers

> **Purpose**: declare argus-redact's identity in 3 layers, each with a distinct
> SLA. This document is for **all downstream consumers** — gateway products,
> integrators, library users, and future contributors. Read this first if
> you're trying to figure out what argus-redact promises and what it doesn't.

argus-redact is **a PII detection string-level primitive + PRvL evaluation
standard**. Everything beyond that — LLM round-trip UX, semantic coreference
restoration, multi-tenancy, audit, multimodal, tool_use state machines, customer
UX — is **not in this project**.

This split is intentional. It keeps the primitive small, audited, fast, and
trustworthy. UX/integration concerns live downstream.

---

> **Two layer taxonomies coexist in this codebase.** Don't be surprised:
>
> | Where | Taxonomy | Meaning |
> |---|---|---|
> | this doc | Primitive / Compose / Downstream | **public stability contract** for the API surface |
> | [`docs/architecture.md`](architecture.md) Purity Architecture | Pure / Impure / Glue | **internal mechanics** — which subdirectories under `src/argus_redact/` may do I/O |
> | [`src/argus_redact/layers.py`](../src/argus_redact/layers.py) `LAYER_REGEX/NER/SEMANTIC` | L1 / L1b / L2 / L3 | **detection pipeline stages** — orthogonal to the other two |
>
> Mapping: Layer 1 primitive ≈ `pure/` + the `redact / restore / assess_risk` entry points in `glue/`. Layer 2 compose ≈ in-tree `streaming.py` + the `compose/` subpackage (v0.6.7+). Layer 3 downstream is out-of-tree.

---

## The three layers

```
┌──────────────────────────────────────────────────────────────┐
│  Layer 1: Primitive (this project, frozen contract at 1.0)   │
│                                                              │
│  argus_redact.{redact, restore, assess_risk}                 │
│  argus_redact.specs (PII type registry, compliance metadata) │
│  PRvL evaluation standard                                    │
│                                                              │
│  SLA: deterministic, string-level, narrow, fast              │
└──────────────────────────────────────────────────────────────┘
                            ↑
                            │ depends on
                            │
┌──────────────────────────────────────────────────────────────┐
│  Layer 2: Compose (this project, in-tree, best-effort SLA)   │
│                                                              │
│  argus_redact.compose.* helpers (heuristic LLM round-trip)   │
│  argus_redact.streaming                                      │
│                                                              │
│  SLA: best-effort, heuristics, semver-stable but evolving    │
└──────────────────────────────────────────────────────────────┘
                            ↑
                            │ wraps / extends
                            │
┌──────────────────────────────────────────────────────────────┐
│  Layer 3: Downstream products (NOT in this project)          │
│                                                              │
│  • Argus Gateway (sibling, enterprise gateway)               │
│  • Recipes / cookbook patterns (this project's docs/recipes) │
│  • Caller-built integrations                                 │
│                                                              │
│  SLA: defined by each downstream product                     │
└──────────────────────────────────────────────────────────────┘
```

---

## Layer 1: Primitive — what we promise

The primitive layer is `argus_redact.{redact, restore, assess_risk}` and the
underlying `specs` registry plus the **PRvL evaluation standard**
(`docs/prvl-standard.md`).

### Contract

| Aspect | Promise |
|---|---|
| `redact()` signature | Frozen at 1.0. Same call, same params → same observable behavior (modulo `salt=` non-determinism). |
| `restore()` semantics | **Literal substring inverse** of `redact()`'s substitution. Pure function. Not coreference-aware. Not paraphrase-aware. |
| Key schema | `dict[str, str]` mapping fake → original. Stable across versions. |
| PII type registry | Names stable; new types added (additive). |
| Compliance metadata (`PIPL_REFERENCES` etc.) | Key set stable; values updated when laws/regulations change. |
| Pseudonym derivation chain | SHAKE-256 + HMAC, deterministic given salt + value. Chain frozen for replay across versions. |
| Performance | Sub-ms `mode="fast"` per 1KB on Apple M1 Max; perf budget CI gate at ±10% per release. |

### What the primitive does NOT promise

These are **out of scope** for the primitive — by design, forever:

- **NLP coreference resolution.** If an LLM rewrites "张三" as "张先生" / "老张" / "Mr. Zhang" in its output, `restore()` will not recognize those variants. Coref is a downstream concern.
- **Full-fidelity semantic round-trip.** Paraphrasing, translation, partial references, definite descriptions — none of these are reversed by `restore()`. PRvL R-by-task-type quantifies this honestly (reference task ≈ 100%, creative task ≈ 0% by design).
- **Multimodal redaction.** Vision, audio, file uploads — not supported. Text-only.
- **Token-by-token streaming.** Sentence-buffered streaming via `StreamingRedactor` is the upper bound. Byte-level partial regex / per-token restore is not in scope. See [`docs/design-streaming-incremental.md`](design-streaming-incremental.md) §"Why sentence boundaries".
- **Tool-use / function-calling cross-turn state.** Stateful redact/restore across LLM tool turns is downstream territory.
- **Multi-tenant isolation, audit log persistence, RBAC.** Operational concerns of a gateway product.
- **Customer-facing UX, installation, support.** Out of an OSS library's scope.

### How the primitive evolves after 1.0

**Contract stable ≠ capability frozen.** Post-1.0, the primitive will continue
to deepen on these axes (without breaking signatures):

- PII type registry expansion (current: 56 → planned: 80+ as new regions and
  threats are added)
- Language packs (current: 8 → planned: 12+)
- Cryptographic primitives (post-quantum readiness, KDF evolution as standards
  shift)
- Detection accuracy (Rust-core regex optimization, validator coverage, hint
  protocol refinement)
- PRvL standard (new task types, new evaluation dimensions)
- Adversarial robustness (Unicode obfuscation, format-spoofing defenses)
- Performance baselines (perpetual ratchet via CI perf gate)
- Public knowledge curation (reserved-range catalog, compliance metadata
  mappings, hint protocol design — research-grade artifacts)

These are **internal deepening**, not surface expansion. Callers see the same
API. The library gets better.

---

## Layer 2: Compose — best-effort LLM round-trip helpers

The compose layer lives in `argus_redact.compose.*` (formalization in progress
toward v0.7). It provides **opt-in helpers** that wrap the primitive to address
common LLM round-trip pain points the primitive cannot solve by design.

### Examples (v0.7 candidates)

- `compose.prompt_anchor(key, lang) -> str` — generate a system-prompt
  addendum that explicitly asks the LLM not to abbreviate, retitle, or
  pronoun-substitute pseudonyms. Intervenes at the **input** side, before
  variants are generated.
- `compose.expand_aliases(key, lang) -> dict` — generate surname+title
  composite aliases (e.g., `张先生` → `黄先生` when key has `张三` → `黄芳`).
  Conservative: only composite forms, no bare surname (to avoid false-positive
  restoration on common characters).
- `redact_pseudonym_llm(...)` — three-form output (audit / downstream /
  display) already in `argus_redact.streaming`-adjacent module; will move to
  `compose` namespace.
- `StreamingRedactor` / `StreamingRestorer` — sentence-buffered streaming,
  already shipped.

### Contract

| Aspect | Promise |
|---|---|
| API stability | Semver-stable, but evolving more freely than primitive. Adds may happen between minor versions; removes only with a deprecation cycle. |
| Behavior | **Best-effort**. Covers common patterns. Long tail of LLM variant behavior is not guaranteed. |
| Failure mode | A missed variant restoration is a **known limitation**, not a release blocker. Documented in PRvL standard. |
| Testing | Standard unit tests + benchmarks. Not held to the primitive's property/mutation-test bar. |

### Why this layer exists

LLM behavior is open-ended: prompts vary, models vary, outputs vary. The
primitive's deterministic substring inverse cannot cover the long tail of LLM
linguistic variation. But there's a middle ground — heuristic input-side
anchors and conservative output-side alias expansion catch the common 80%.

The compose layer is honest about being **heuristic**. Callers who want
guaranteed full-fidelity round-trip should either (a) use the `pseudonym`
strategy (`P-NNNNN`-style codes that LLMs treat opaquely) instead of
`realistic`, or (b) integrate a downstream coref-aware framework.

---

## Layer 3: Downstream products — NOT in this project

This layer is where the bulk of LLM-pipeline UX lives:

- **Argus Gateway** (`gateway.agilist.cn`) — enterprise gateway product:
  multi-tenant, audit log persistence, RBAC, customer UX, compliance materials,
  sales-legal channel.
- **Cookbook recipes** (this project's `docs/recipes/`) — single-machine OSS
  patterns for dev/hacker use cases (e.g.,
  [`local-cli-proxy`](recipes/local-cli-proxy.md) for putting a PII guard
  around CLI tools like `aider` / `llm` / cursor terminal). These are
  reference patterns, not maintained products.
- **Caller-built integrations** — anyone embedding argus-redact into their own
  service.

argus-redact upstream does **not** ship downstream products. Recipes are the
exception, and they're explicitly framed as cookbook code (copy, modify, run —
not pip-installable products).

### Boundary with Argus Gateway

Argus Gateway is the canonical enterprise downstream. The OSS↔Gateway boundary:

| OSS (this project) | Argus Gateway (sibling) |
|---|---|
| String-level primitive + PRvL standard | Multi-tenant gateway with RBAC + audit |
| Public knowledge curation (PII types, reserved ranges, hints, compliance metadata) | Customer-facing UX, install, support, sales-legal |
| `compose` helpers (best-effort LLM round-trip) | Coref-aware restoration, tool_use orchestration, multimodal (if/when), policy engine |
| Recipes (cookbook) | Productized SKUs |

These are **different layers, not an upsell funnel**. Both can exist
independently and serve different audiences.

---

## How to decide where a new feature belongs

If you're adding a feature and unsure which layer:

```
Is the behavior deterministic for given input?
  ├─ Yes → does it operate on string substitution semantics?
  │        ├─ Yes → primitive
  │        └─ No (heuristic, statistical, LLM-mediated) → compose
  └─ No (depends on LLM behavior, multi-turn state, etc.) → compose or downstream

Does it require persistent state across requests?
  └─ Yes → downstream (not in this project)

Does it require multi-tenant isolation?
  └─ Yes → downstream

Does it require coref resolution / NLP understanding?
  └─ Yes → downstream

Does it intervene at LLM input/output but is stateless?
  └─ compose
```

When in doubt, **default to compose** rather than primitive. The primitive's
contract is precious; we don't expand it lightly.

---

## See also

- [`docs/prvl-standard.md`](prvl-standard.md) — the open evaluation standard
- [`docs/known-issues.md`](known-issues.md) — out-of-scope items and known limitations
- [`docs/api-reference.md`](api-reference.md) — Python API
- [`docs/recipes/local-cli-proxy.md`](recipes/local-cli-proxy.md) — example downstream pattern
