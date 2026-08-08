# Security Model

## The Analogy

argus-redact works like encryption:

```
GPG:           encrypt(plaintext, pubkey) → ciphertext     decrypt(ciphertext, privkey) → plaintext
argus-redact:  redact(plaintext)          → (redacted, key) restore(redacted, key)       → plaintext
```

The critical difference:

| | Encryption | argus-redact |
|-|-----------|--------------|
| Output readable? | No (ciphertext) | **Yes** (redacted text has meaning) |
| LLM can process? | No | **Yes** — this is the whole point |
| Math guarantee? | Yes (provable security) | No (best-effort NLP) |
| Key leaked = ? | Plaintext exposed | **Identities exposed** |

argus-redact is **semantic encryption** — it hides identity while preserving meaning.

---

## What's Protected

### Primary threat: Cloud provider learns PII

```
Without argus-redact:
  "张三 went to 协和医院 for a checkup" → Cloud LLM logs → 张三's health info exposed

With argus-redact:
  "P-037 went to [hospital] for a checkup" → Cloud LLM logs → nothing identifiable
```

### Secondary threat: Cross-request profiling

Even with pseudonyms, a provider might correlate multiple requests:

```
Fixed pseudonyms (other tools):
  Request 1: "P-001 discussed an interview"
  Request 2: "P-001 went to hospital"
  → Provider knows: P-001 is job-seeking AND has health concerns

Per-message keys (argus-redact):
  Request 1: "P-037 discussed an interview"
  Request 2: "P-003 went to hospital"
  → Provider sees two unrelated people
```

Each `redact()` call generates a fresh random key. Compromising one key reveals nothing about other sessions — similar to the "forward secrecy" concept in cryptography, though without the mathematical proof.

### Why this matters now: LLM deanonymization attacks

Research from ETH Zurich ([arXiv:2602.16800](https://arxiv.org/abs/2602.16800), February 2026) demonstrates that LLM-based agents can deanonymize online users at a cost of $1-4 per person, achieving 67% recall at 90% precision.

The attack relies on correlating pseudonymous activity across multiple requests. Fixed pseudonym schemes — where the same person always maps to `PERSON_1` — are particularly vulnerable, as the attacker can build a profile across requests and cross-reference with public data.

**Per-message key rotation is the primary defense.** When each request uses a completely independent set of pseudonyms, cross-request correlation becomes impossible. This is why argus-redact generates a fresh random key for every `redact()` call by default. All other open-source PII tools we surveyed (Presidio, AVA Protocol, Bridge, anonLLM) use fixed or session-persistent pseudonyms.

---

## What's NOT Protected

| Threat | Why not | Mitigation |
|--------|---------|------------|
| **Context inference** | "the CEO of [company] in [city] discussed quarterly results" — identity might be guessable from context alone | Layer 3 (semantic) tries to detect these; detected quasi-identifiers default to `remove`. Removing explicit PII is not anonymization — residual cue *combinations* may still enable inference. No guarantee. |
| **Timing correlation** | Requests always at 9am from same IP | Outside scope. Use VPN, randomize timing. |
| **Device compromise** | Attacker has access to your filesystem | Encrypt disk. Delete key files after use. |
| **Traffic analysis** | Request size, frequency patterns | Outside scope. |
| **Model memorization** | Cloud LLM memorized your redacted text during training | Redacted text contains pseudonyms, not real PII. Low risk. |

---

## Data Flow

```
┌─── YOUR DEVICE (trusted boundary) ───────────────────────┐
│                                                            │
│   plaintext ──→ redact() ──→ redacted text                │
│                    │              │                         │
│                   key          goes to                     │
│                (in-memory)     NETWORK                     │
│                    │              │                         │
│               NEVER leaves       ▼                         │
│               your device    Cloud LLM                     │
│                    │              │                         │
│                    ▼              ▼                         │
│   restored ←── restore() ←── LLM response                 │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

### What crosses the network

| Data | Leaves device? | Contains PII? |
|------|---------------|--------------|
| Redacted text | Yes → LLM API | No |
| Key | **Never** | Yes — the key IS the sensitive data |
| Original text | Not in `fast`/`ner` mode; see note below for `auto` | Yes |
| Key file (if saved) | Only if user copies it | Yes (plaintext dict) |

> **Egress scope for `auto` mode (Layer 3).** In `fast` and `ner` modes — and in
> `auto` mode with a loopback Ollama host — the original text never leaves your
> device. A non-loopback `OLLAMA_HOST` sends the original (pre-redaction) text to
> that host for Layer-3 semantic detection. argus-redact default-denies this: a
> non-loopback host requires the explicit `ARGUS_ALLOW_REMOTE_OLLAMA=1` opt-in and
> emits a `SecurityWarning` (naming the host) before any text is sent.
>
> That loopback check validates the `OLLAMA_HOST` URL, not the request's transport:
> an `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` environment variable can still
> redirect a request to a validated-loopback host wherever the proxy points, since
> `requests` does not exempt loopback targets from a configured proxy. The outbound
> call pins `proxies={"http": None, "https": None}`, so a loopback `OLLAMA_HOST` is
> unaffected by any proxy variable in the process environment — only the explicit
> `ARGUS_ALLOW_REMOTE_OLLAMA=1` opt-in above (with its `SecurityWarning`) can send
> this text to a non-loopback destination.

---

## Key Security

The key is the most sensitive artifact. It maps pseudonyms to real identities.

### Lifecycle

```
redact() called  →  key generated (in-memory)
                     ↓
                 used by restore()
                     ↓
                 variable goes out of scope → garbage collected
```

Or if saved to file:

```
redact() called  →  key generated + written to file
                     ↓
                 used by restore()
                     ↓
                 user deletes file → gone
```

### Rules

1. **In-memory by default.** Key only exists as a Python dict until the variable is garbage collected.
2. **File only when you ask.** `key="key.json"` or CLI `-k key.json` explicitly writes to disk.
3. **Never logged.** Key contents are excluded from all log output, even at DEBUG level.
4. **Caution with `print`.** The key is a plain dict — `print(key)` will show full contents. Avoid logging or printing keys in production. Wrap in a helper if needed.
5. **Treat like a private key.** If you save it, protect the file. Delete after use.

### What if the key leaks?

The key maps pseudonyms to originals. Anyone with the key and the redacted text can restore all PII. But:
- They only get identities from **that specific session**.
- Other sessions used different keys — each session is isolated.
- Without the redacted text, the key alone reveals entity names but not context.

### Scope of cross-message isolation (pseudonymized vs. masked)

The salt isolates **pseudonymized** values across messages: a key from one
redaction cannot reconstruct a pseudonymized value (salt-derived `P-NNNNN`,
faker/realistic value) that was redacted under a different salt.

**Masked** values use deterministic, content-derived codes that are
salt-independent (and partially self-revealing by design — see *mask strategy
partial leakage* below), so they are **not** isolated across messages: a key can
reconstruct a masked value it shares with another message. The exposure is
narrow — this only re-exposes a value the key holder already possesses (a
cross-message *linkage* of an already-known value, not new PII). A
salt-independent code is also the only form that currently survives the LLM
round-trip (redact → LLM → restore the LLM's fresh reply). LLM-roundtrip-compatible
salt-keyed masking is planned for a future release.

---

## Per-Message Keys vs. Reused Keys

| | Per-message key (default) | Reused key (`key=key`) |
|-|--------------------------|----------------------|
| Cross-request linkability | **Unlinkable** | Linkable within batch |
| Use case | Independent LLM requests | Multiple texts sharing context |
| Security | Strongest | Acceptable — entire batch is one logical unit |

**Rule of thumb:** If you'd send the texts in a single LLM request, they can share a key. If they're independent requests, use separate keys.

---

## Recommendations

### Personal use
- Use default per-message keys
- Don't save keys unless you need deferred restoration
- Delete key files after restoring
- Enable full-disk encryption

### Enterprise
- Define a config that over-redacts (lower `min_confidence`)
- Audit redacted output before sending to cloud
- Use key file paths on encrypted volumes
- Automate key deletion (e.g., `&& rm key.json` in pipeline)

### Compliance (HIPAA, PIPL, GDPR)
- argus-redact is a **technical control**, not a certification
- Use as one layer in defense-in-depth
- Review redacted output — no system is 100%
- Document your pipeline for audit
- Consult legal counsel for your requirements

---

## Regulatory Context

### China PIPL — Cross-border LLM usage

China's Personal Information Protection Law (PIPL) cross-border data transfer rules (effective January 2026) require organizations to minimize personal data sent to overseas services. When using overseas LLM APIs (OpenAI, Anthropic, Google), user PII must be de-identified before transmission.

argus-redact provides the technical implementation:

1. `redact()` runs locally — PII is replaced before any network call
2. Only pseudonymized text crosses the border
3. `restore()` runs locally — original identities never leave the device
4. Per-message keys prevent cross-request profiling by the overseas provider

This does not replace a Data Protection Impact Assessment (DPIA) or legal review, but it provides the technical layer that such assessments typically require.

### EU AI Act / GDPR

The EU AI Act (effective August 2026) imposes data minimization requirements on AI systems. GDPR Article 25 requires data protection by design. argus-redact supports both by ensuring that only the minimum necessary data — semantically preserved but identity-removed — is processed by external AI services.

v0.7.18 adds machine-readable compliance artifacts that make the pseudonymization/anonymization boundary explicit: `RedactReport.residual_personal_data` (accessible via `redact(report=True)`) is `True` whenever any PII was detected — a retained recovery key makes masked/category output just as re-linkable as a pseudonym, and `keep` leaves the original verbatim — signalling that output remains personal data under GDPR Art.4(5). See [Compliance artifacts (v0.7.18)](#compliance-artifacts-v0718) below for the full artifact set.

### HIPAA

For healthcare applications in the US, argus-redact can serve as a de-identification step before sending clinical notes to LLM APIs. The key file should be treated as PHI and stored on encrypted, access-controlled volumes. Delete key files after restoration.

---

## Compliance artifacts (v0.7.18)

v0.7.18 ships three machine-readable compliance artifacts that pipeline code can
consume programmatically. They complement the human-readable `SecurityWarning`
emitted to Python's warnings system — which remains in place — with structured,
inspectable data suitable for logging, audit storage, and compliance dashboards.

### `keep_downgraded` security event

When a `keep` strategy is configured for a PII type that is not a self-reference
(pronoun / kinship phrase), argus-redact downgrades the entity to the type's
default strategy and emits a `SecurityWarning`. v0.7.18 also surfaces this as a
structured security event in `redact(detailed=True)["security_events"]` — the
reliable programmatic channel.

```python
from argus_redact import redact

text, key, details = redact(
    "卡号4111111111111111",
    lang="zh",
    mode="fast",
    detailed=True,
    config={"bank_card": {"strategy": "keep"}},
)

for event in details["security_events"]:
    print(event["reason_code"])  # "keep_downgraded"
    print(event["count"])        # 1 (number of affected entities)
    print(event["detail"])       # "types: bank_card"  — PII-free; types only
```

Event shape:

```python
{
    "type": "security",
    "reason_code": "keep_downgraded",
    "count": 1,          # number of unique entity texts that were downgraded
    "detail": "types: bank_card",  # sorted type names; never raw PII values
}
```

`security_events` is always present in the details dict (empty list when nothing
noteworthy occurred). The same list of event dicts is also available in
`RedactReport.security_events` when using `redact(report=True)`.

### `coverage_restored` security event (v0.8.6)

Detection ends with a priority-aware merge — when two detected spans overlap, one
wins and the loser is discarded, which is safe only because the winner's bytes
cover the loser's — followed by filters that drop entities by type: the
self-reference tier filter, and the `types=`/`types_exclude=` filter. If one of
those filters then drops a winner that had absorbed something else during the
merge, argus-redact re-admits what it absorbed so it stays redacted, and records
that it happened as a `coverage_restored` structured event plus a
`SecurityWarning`.

Event shape:

```python
{
    "type": "security",
    "reason_code": "coverage_restored",
    "count": 1,                # number of entities the invariant re-admitted
    "detail": "types: phone",  # sorted type names; never the raw value
}
```

Like `keep_downgraded`, `detail` names entity TYPES only — the values that were
re-admitted never appear in this channel, and the redaction itself never depended
on this signal reaching you: the invariant already re-admits the entity before this
event is built, so `coverage_restored` reports what was fixed, not something still
unredacted. It is expected on type-filtered calls — `types=`/`types_exclude=`
legitimately excluding a winner that had absorbed something else during the
merge — and rare on an unfiltered call, where a firing means an ordinary overlap
between two detectors happened to be split by a filter that was not aimed at
either of them.

Unlike `keep_downgraded`, this event is not reproducible from a one-line
`config=` toggle — it fires only when the merge actually absorbed one span into
another first, so no short standalone snippet here is guaranteed to trigger it.
Access it the same way as any other event, via
`redact(..., detailed=True)["security_events"]` or `RedactReport.security_events`.

### `RedactReport.residual_personal_data`

`redact(report=True)` returns a `RedactReport` dataclass. The
`residual_personal_data` field (`bool`) is a machine-readable signal that the
redacted output is still personal data under GDPR Art.4(5): pseudonymization
produces reversible output, so the pseudonymized text can be re-linked to the
original identity via the key.

`residual_personal_data` is `True` whenever **any** entity was detected. Every
substituting strategy — including the lossy-looking ones (`mask`, `name_mask`,
`landline_mask`, `category`) — writes `surrogate -> original` into the `key` dict
`redact()` returns, so the surrogate can be mapped back regardless of which
strategy produced it; `keep` needs no key at all because it leaves the original
verbatim in the output text. So a retained recovery key (or verbatim output) means
the result is still personal data under GDPR Art.4(5) no matter the strategy. It is
`False` only when nothing was detected (nothing to recover). This is deliberately
**not** derived from `is_strategy_reversible` — that helper answers a narrower,
LLM-specific question (does the surrogate survive an LLM round-trip), not the
broader "is the original recoverable at all" question this flag answers.

```python
from argus_redact import redact

# Default pseudonym strategy → output is pseudonymised → still personal data
report = redact("姓名张伟，手机13812345678", lang="zh", mode="fast", report=True)
assert report.residual_personal_data is True

# Forcing mask on every type → still recoverable via the retained key
report_masked = redact(
    "手机13812345678",
    lang="zh",
    mode="fast",
    report=True,
    config={"phone": {"strategy": "mask"}},
)
assert report_masked.residual_personal_data is True  # the key still maps 138****5678 -> 13812345678
```

`RedactReport` also carries `report.security_events` — a tuple of the same
structured event dicts described above — so a single `redact(report=True)` call
gives you both the residual-data flag and any security events.

### `RedactReport.coverage` and `.layers_used` (v0.8.7)

`residual_personal_data` tells you what happened to the PII this call *found*.
It says nothing about the PII this call could never have found in the first
place — an empty `key` looks identical whether the text was genuinely clean or
the configuration had no detector for what was in it. `report.coverage`
closes that gap: a `CoverageAdvisory` stating what this `(lang, mode)`
configuration could **not** have found.

```python
from argus_redact import redact

report = redact("Nothing identifying here.", lang="en", mode="fast", report=True)
assert report.key == {}
assert "occupation" in report.coverage.uncovered  # no English occupation detector at all
assert "sex" in report.coverage.narrow            # only the labelled form, see below
```

`CoverageAdvisory` has three fields:

- `uncovered: tuple[str, ...]` — categories with no detector at all under this
  configuration.
- `narrow: tuple[str, ...]` — categories detected only in some forms, or only
  as a different type.
- `exhaustive: bool` — always `False`. The 9 categories are the standard
  inference-attribute taxonomy (age, sex, location, occupation, education,
  relationship_status, income, place_of_birth, medical_condition) that the
  project's own re-identification fixtures are built from — not an exhaustive
  account of everything that can re-identify a person. It is a field rather
  than a sentence in this doc because consumers read fields, not prose.

It is derived from `(lang, mode)` alone: `coverage` never inspects the text and
makes no claim about this document, only about the configuration that ran.
That distinction is why the dataclass is named `CoverageAdvisory` and not
`ResidualAdvisory` — "residual" would imply a finding about what survived
this specific input, and that is not what this field measures.

`report.coverage` is `None` when the call went through `_pre_detected` (a
caller supplying its own already-detected entities, as the Presidio bridge
does internally) — argus ran no detection pass in that case, so a
`(lang, mode)` capability claim would falsely say this configuration looked
for a category and missed it, when in truth nothing was looked for at all.

The measured table (`src/argus_redact/pure/coverage_table.py`) is blunter than
you might expect, on purpose — softening it would defeat the reason it exists.
Read `have` precisely, too: it means the one probe pinned for that cell fired
under its exact phrasing, not that every phrasing of the category is caught.
`age` is a `have`-shaped cell that turned out not to be one: at `mode="fast"`
it fires on full prose ("... years old") but misses a labelled or reformatted
age ("Age: 42"; a Chinese-numeral or `周岁`-suffixed age) in both languages —
the same hit/miss shape that already makes `sex` `narrow` — so `age` is
`narrow`, not `have`, at every measured configuration. English has **no
detector at all** for `occupation`, `education`, `relationship_status`, or
`income`. English `sex` is `narrow`, not `have`: it matches the labelled form
(`"Gender: female."`) but not prose (`"She is a
woman."`) — and the project's own English re-identification fixture states sex
as prose ("I'm a woman"), so its own reference profiles fall on the missed
side of that line. `mode="ner"` adds English `location` (uncovered at fast)
and strengthens `place_of_birth` in both languages via a generic Layer-2
location entity that fires when a separator follows a place name — but not
identically: English `place_of_birth` becomes fully `have` (no documented
miss), while Chinese `place_of_birth` stays `narrow`, because the same entity
still misses the bare `X籍` construction (`籍贯` fixtures spell it, e.g.
`湖南籍`). Chinese `location` was already `have` at `fast`, so `ner` does not
add it there — only English gains it. None of this touches the English
`occupation` / `education` / `relationship_status` / `income` zeroes — those
detectors don't exist at any mode. `mode="auto"` reads the `ner` row rather
than getting a column of its own, because it would otherwise claim a Layer-3
coverage improvement a deployment without a served model does not actually
have.

Only two of the eight shipped language packs (`zh, en, ja, ko, de, uk, in,
br`) have measured rows in `_TABLE`. The other six fall back to the exact
same branch as a language this table has never heard of at all: every
category reported `uncovered`, sorted. That fallback is safe in direction —
it never overstates what the pack can do — but it does not distinguish
"measured and confirmed empty" from "never measured". Treat a coverage
advisory for `ja`/`ko`/`de`/`uk`/`in`/`br` as the latter; this is a visible
scope boundary of the current table, not a defect, and extending `_TABLE` to
those packs is future work.

A call that activates several language packs at once (`redact(lang=["zh",
"en"], ...)`) combines their coverage pessimistically rather than reading
only the first pack: a category is `have` in the combined advisory only if
every active pack has it as `have`; if any active pack has it as `none`, the
combined result is `none` no matter what another pack found (e.g.
`occupation` is `have` for zh and `none` for en, so `lang=["zh", "en"]`
reports `occupation` as not covered). Crediting one pack's coverage while
staying silent about another active pack having no detector at all would be
the same "silence read as safety" gap this feature exists to close,
reappearing at the multi-language seam.

`report.layers_used: tuple[int, ...]` is the companion signal for *this call*,
not the configuration — which detection layers actually contributed a
surviving entity. It is derived from the entities' own `.layer`, never from
`stats`: `stats["layer_1"]` and friends are hardcoded to zero on the
`_pre_detected` path even when real detection happened upstream, so deriving
`layers_used` from `stats` there would silently misreport it. Layer `0` is
kept rather than filtered out — a caller-supplied entity that never tagged a
layer (the Presidio bridge builds `PatternMatch` without one) reports
`layers_used == (0,)`, distinguishable from `()`, which means no entity
survived at all.

### `AuditLedger`

`AuditLedger` is a caller-owned, append-only, PII-free, hash-chained structure
that is simultaneously the audit trail and the tamper-evident record. It records
type counts, detail-stripped security events, and one-way SHA-256 digests of the
redacted text — never the original text, never a pseudonym map, never a key.

```python
from argus_redact import redact, restore, AuditLedger

led = AuditLedger()

# Record a redact operation
redact_result = redact("姓名张伟，手机13812345678", lang="zh", mode="fast", detailed=True)
text, key = redact_result[0], redact_result[1]
led.record_redact(redact_result)

# ... send text to LLM, receive response ...

# Record a restore operation
# guard=False opts out of the guarded round-trip for this illustration;
# production callers should use the guarded flow (see § Guarded restore).
restore_result = restore(text, key, guard=False, detailed=True)
led.record_restore(restore_result)

# Verify the chain has not been modified
assert led.verify() is True

# Inspect the current chain head (persist this to detect tail-truncation)
print(led.head_digest)  # 64-char hex SHA-256 string

# Persist across sessions
import json
saved = json.dumps(led.to_dict())

# Reload in a later session
led2 = AuditLedger.from_dict(json.loads(saved))
assert led2.verify() is True
assert led2.head_digest == led.head_digest
```

#### `record_redact` and `record_restore`

`record_redact(detailed_result)` accepts the 3-tuple returned by
`redact(detailed=True)`. It counts detected entity types, computes a one-way
SHA-256 digest of the **redacted** text (never the original), and appends a
`"redact"` entry.

`record_restore(detailed_result)` accepts the 2-tuple returned by
`restore(detailed=True)`. It records any security events from the restore
operation. It does **not** auto-digest the restored text (recovered plaintext
should not be stored in the ledger); pass `content_digest=` explicitly if your
threat model needs it.

#### `verify()`

`verify()` recomputes every entry hash and checks the `prev_hash` linkage. It
returns `True` if the chain is intact, `False` on any break. Entry inspection:

```python
for entry in led.entries:
    print(entry.seq, entry.kind, entry.type_counts, entry.security_events)
```

#### Honest integrity boundary

The keyless default (`AuditLedger()`) uses SHA-256 for chaining. This provides
**append-only integrity**: it detects interior modification, reordering, and
deletion of entries.

What it does **not** detect on its own:

- **Tail-truncation**: dropping the most-recent entries leaves a valid shorter
  chain. Detect this by persisting `led.head_digest` externally (e.g., in a
  separate log, a notary service, or a time-stamped receipt) before each session
  ends, then comparing the stored digest against `led.head_digest` after reload.
- **Full-chain forgery**: an adversary who controls the store can recompute the
  entire chain from scratch, producing a different valid chain. Prevent this with
  `hmac_key=`.

To add forge-resistance, pass a secret key:

```python
import secrets

led = AuditLedger(hmac_key=secrets.token_bytes(32))
```

With `hmac_key=`, each entry hash is HMAC-SHA-256 rather than plain SHA-256.
An adversary who cannot reproduce the key cannot forge a chain that passes
`verify()`. Keep the `hmac_key` secret and separate from the ledger storage
(same principle as keeping the redaction key separate from the redacted text).

argus-redact ships no notarization or timestamp integration. External anchoring
of `head_digest` — writing it to a trusted log, a blockchain, or a signed
receipt — is the caller's responsibility. The library gives you the digest; the
anchoring mechanism is yours to choose.

#### PII-free invariant

The ledger stores:

- PII type names and counts (`type_counts`, e.g. `{"person": 2, "phone": 1}`)
- Sanitized security events: `reason_code` and `count` only; the free-form
  `detail` field is stripped at append time so the ledger never depends on
  producer discipline about what ends up in `detail`
- One-way SHA-256 digests of redacted text (`content_digest`)
- Chain hashes (`prev_hash`, `entry_hash`)

It does **not** store: original text, redacted text, pseudonym-to-original
mappings, or any value that would allow recovery of PII from the ledger alone.

---

## Known Security Limitations

### Not real encryption

argus-redact is **semantic pseudonymization**, not cryptographic encryption. There is no mathematical proof of security. Detection is best-effort NLP. Always review redacted output before sending to external services.

### In-memory key residue

Python strings are immutable and cannot be securely erased. After `del key`, the key content may remain in process memory until garbage collected. This does not defend against memory forensics (core dumps, `/proc/pid/mem`, cold boot attacks). For HIPAA/high-security scenarios, run argus-redact in a short-lived process and rely on OS-level memory protections.

### restore() and LLM prompt injection

If an attacker controls the LLM output (via prompt injection), they can include pseudonym codes (e.g., `P-00037`) in the response. `restore()` defaults to `guard=True`, so a bare `restore(text, key)` with no anchor **fails closed** — it returns the text un-restored rather than substituting. But an explicit unguarded call (`guard=False`, the informed opt-out — or `guard=None`, the deprecated legacy path) will replace pseudonym codes with real PII: that call is a mechanical string replacement by design and does not check where the text came from. Mitigations:
- Prefer the guard: pass `guard=True` with an `anchor`, or use `guarded_restore()`, for any text that came back from an LLM.
- If you must call `restore(..., guard=False)`, validate LLM output structure before restoring.
- Use `report=True` to review what was redacted before sending.
- Consider the LLM's output trustworthiness in your threat model.
- Use guarded restore (described below) to add a deterministic provenance layer.

### Guarded restore

A guard layer sits between the LLM's reply and the substitution pass. It does not replace
careful output validation, but it closes the mechanical window where a pseudonym injected
into LLM output would silently restore.

Use **`guarded_restore()`** — it is the whole flow in one call, and the same function the
shipped integrations call internally.

**How it works:**

1. **Build an anchor** from the key before sending the prompt:

   ```python
   from argus_redact import redact, guarded_restore, make_anchor
   from argus_redact.compose import prompt_anchor

   redacted, key = redact(user_input)
   anchor = make_anchor(key)
   # anchor.nonce is a random 32-hex-char token; anchor.scope = frozenset of pseudonyms
   ```

2. **Embed the nonce in the LLM system prompt** so the LLM echoes it back:

   ```python
   system = prompt_anchor(key, lang="zh", anchor=anchor)
   llm_reply = call_llm(redacted, system=system)
   ```

3. **Restore through the guard**, passing back *both* the redacted prompt and the anchor:

   ```python
   restored = guarded_restore(
       llm_reply, key, redacted=redacted, anchor=anchor, strict=False
   )
   ```

   `redacted=` is what enables the injection heuristic. Hand-composing the flow as
   `restore(llm_reply, key, guard=True, anchor=anchor)` still runs the deterministic
   P + S checks, but with no redacted prompt to compare against it runs **no H check at
   all** — which is why `guarded_restore()` is the recommended path rather than a
   convenience wrapper.

**Three checks run, in this order:**

- **H (injection heuristic)** — compares the reply against the redacted prompt for
  suspicious pseudonym usage (frequency amplification, pseudonyms next to exfiltration
  patterns). It is **advisory by default: it warns, it does not block.** A hit emits an
  `injection_suspected` event and the restore still proceeds — originals *are*
  substituted. H runs only when `redacted=` is supplied.
- **P (provenance)** — the nonce must appear verbatim in the reply, as the trailing token
  or on a line of its own. Ordinary model formatting around it — a code span, bold,
  quotes, brackets, a trailing full stop — is tolerated; the nonce must still be the whole
  token, so `id=<nonce>xyz` does not qualify. If absent, the reply cannot be traced to this
  redaction session: restore fail-closes, returning pseudonyms unchanged, and emits a
  `provenance_failed` event. Once the check passes the token has done its job and
  **every** echoed copy of it is **stripped from the returned text** — it is not part of
  the model's answer and never reaches the caller.
- **S (scope-binding)** — only pseudonyms in `anchor.scope` (the set produced by *this*
  redaction call) are substituted. Out-of-scope codes appearing in the reply trigger an
  `out_of_scope_pseudonym` event and are left unreplaced.

**P + S are the deterministic guarantee. H is a heuristic and is never promoted to that
guarantee** — it can miss an injection, and it can fire on a benign reply. Treat an H
event as a signal to investigate, not as proof of either safety or attack.

**Fail-closed behaviour:** when P or S withholds a substitution, the call returns the text
with pseudonyms intact — no PII is substituted — **and emits a `SecurityWarning`** (a
`UserWarning` subclass). A fail-closed restore is therefore never silent, which matters
because the returned `str` is otherwise shape-identical to a successful one: without the
warning, a caller could read silence as success. The warning carries the reason code and
count only — never the offending text — so it is safe for a log stream. `SecurityWarning`
lives in `argus_redact.exceptions` (also importable from the top-level package; the
historical `argus_redact.pure.replacer` import still works).

**`strict=True`** is the opt-in that makes the advisory layer fail closed too: any event —
H, P, or S — raises `RestoreGuardError` instead of returning. Under `strict=True` the H
check raises **before any restore is attempted**, so on a suspected injection no original
value is ever substituted, not even transiently into a value that is then discarded.

```python
from argus_redact import RestoreGuardError, guarded_restore

try:
    restored = guarded_restore(
        llm_reply, key, redacted=redacted, anchor=anchor, strict=True
    )
except RestoreGuardError as e:
    # e.events is a list of security event dicts
    handle_guard_failure(e.events)

# Or inspect without raising:
restored, details = guarded_restore(
    llm_reply, key, redacted=redacted, anchor=anchor, detailed=True
)
for event in details["security_events"]:
    log(event["reason_code"], event["count"], event["detail"])
```

Security event `reason_code` values: `provenance_failed`, `out_of_scope_pseudonym`,
`injection_suspected`, `guard_no_anchor`.

**The integrations are thin wrappers over the same call.** All five shipped integrations
route through `guarded_restore()`, so all five run H → P → S and all five expose
`strict=`:

| Integration | How to pass `strict=` |
|---|---|
| `langchain` | constructor kwarg — `RestoreRunnable(redact_runnable, strict=True)` |
| `llamaindex` | constructor kwarg — `RestoreTransform(redact_transform, strict=True)` |
| `mcp` | tool argument — `restore(text, key_token, strict=True)` |
| `presidio` | call kwarg — `bridge.restore(..., strict=True)` |
| `fastapi` | call kwarg — `restore_body(..., strict=True)` |

The LangChain and LlamaIndex adapters hold the redacted prompt and anchor from their
paired redact step, so H runs there without you threading anything; the MCP server keeps
them alongside the key token for the same reason (see [security.md](security.md#mcp-token-store)).

**The guard is not Python-only.** The P + S checks are core logic (`restore_full_guarded`),
and the in-browser wasm build exposes them directly as `restore_guarded(text, key, anchor)`,
taking the same `{nonce, scope}` anchor shape and returning a structured `{restored,
outcome, events}` result — the browser-facing counterpart to the Python binding, with no
Python or server round-trip involved. The [in-repo demo](../demo/) — the same demo also
published as a [Hugging Face Space](https://huggingface.co/spaces/wan9yu/argus-redact) —
drives this path with a guarded-restore panel: it builds a real anchor and nonce, but the
"reply" is a **simulated echo typed into the page**, not a live LLM — so the panel
demonstrates the guard's provenance and scope checks, not an end-to-end LLM integration.

**Honest boundary:** the guard operates at the restore layer only. It verifies that a
response came from the expected session and contains only in-scope pseudonyms. It does
not inspect network transport, protect against key exfiltration, or prevent the LLM from
leaking context through paraphrase. Egress and transport security remain separate layers.

### mask strategy partial leakage

The `mask` strategy (e.g., `138****5678`) reveals prefix and suffix digits. For phone numbers, 3 prefix + 4 suffix digits may narrow the search space to ~10,000 numbers. For strict privacy, use `pseudonym` or `remove` strategy instead. PIPL/GDPR compliance profiles should prefer non-mask strategies.

### Masked-value collisions are not guaranteed LLM-round-trip reversible

When two different originals produce the same masked/category/remove surrogate (e.g., two phone numbers that mask to the same `138****5678`), argus-redact disambiguates them by appending a trailing circled digit (`①②③...`) to the second and later occurrences. That disambiguator is itself content — an LLM rewriting or normalizing the text can drop or alter it, which collapses the two surrogates back to the same string. `restore()` can then no longer tell the two originals apart.

argus-redact emits a `SecurityWarning` naming the collision whenever `resolve_collision` actually disambiguates two same-strategy surrogates; the message carries the count and affected types only, never the raw values. Treat any masked/category/remove entry involved in a reported collision as **not restorable with confidence** across an LLM round-trip — prefer `pseudonym` or `realistic` (shape-independent surrogates, see `is_strategy_reversible()` in [api-reference.md](api-reference.md#is_strategy_reversible-v059)) for values you need to restore reliably after the text has passed through an LLM.

### Seeded pseudonym codes are predictable, not random

When you supply a seed/salt, the `P-NNNNN` codes are drawn from a Mersenne-Twister (MT19937) stream (CPython's `random.Random`), which is deterministic and not cryptographic — so the codes are reproducible and, given enough outputs, predictable and linkable across redactions that share the same seed/salt. This is low severity: the code is an opaque sequence label, not derived from the original value, so it leaks no original-value information. It is a deterministic-but-predictable label, not a cryptographic commitment. Unseeded redactions use `secrets` instead and are not subject to this property.
