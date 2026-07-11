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

### HIPAA

For healthcare applications in the US, argus-redact can serve as a de-identification step before sending clinical notes to LLM APIs. The key file should be treated as PHI and stored on encrypted, access-controlled volumes. Delete key files after restoration.

---

## Known Security Limitations

### Not real encryption

argus-redact is **semantic pseudonymization**, not cryptographic encryption. There is no mathematical proof of security. Detection is best-effort NLP. Always review redacted output before sending to external services.

### In-memory key residue

Python strings are immutable and cannot be securely erased. After `del key`, the key content may remain in process memory until garbage collected. This does not defend against memory forensics (core dumps, `/proc/pid/mem`, cold boot attacks). For HIPAA/high-security scenarios, run argus-redact in a short-lived process and rely on OS-level memory protections.

### restore() and LLM prompt injection

If an attacker controls the LLM output (via prompt injection), they can include pseudonym codes (e.g., `P-00037`) in the response. `restore()` will replace these with real PII. This is by design — restore is a mechanical string replacement. Mitigations:
- Validate LLM output structure before restoring
- Use `report=True` to review what was redacted before sending
- Consider the LLM's output trustworthiness in your threat model
- Use guarded restore (v0.7.18, described below) to add a deterministic provenance layer

### Guarded restore (v0.7.18)

v0.7.18 adds a deterministic guard layer to `restore()`, enabled by passing `guard=True` alongside an `Anchor`. It does not replace careful output validation, but it closes the mechanical window where a pseudonym injected into LLM output would silently restore.

**How it works:**

1. **Build an anchor** from the key before sending the prompt:

   ```python
   from argus_redact import redact, restore, make_anchor
   from argus_redact.compose import prompt_anchor

   redacted, key = redact(user_input)
   anchor = make_anchor(key)
   # anchor.nonce is a random 32-hex-char token; anchor.scope = frozenset of pseudonyms
   ```

2. **Embed the nonce in the LLM system prompt** so the LLM echoes it back:

   ```python
   system = prompt_anchor(key, lang="zh", anchor=anchor)
   llm_output = call_llm(redacted, system=system)
   ```

3. **Restore with guard**:

   ```python
   restored = restore(llm_output, key, guard=True, anchor=anchor)
   ```

**Two checks run on every guarded restore:**

- **P (provenance)**: the nonce must appear verbatim in the LLM response. If absent, the
  response cannot be traced to this redaction session — restore returns pseudonyms
  unchanged (fail-closed) and emits a `provenance_failed` security event.
- **S (scope-binding)**: only pseudonyms within `anchor.scope` (the set produced by this
  redaction call) are substituted. Out-of-scope codes that appear in the response
  trigger an `out_of_scope_pseudonym` event and are left unreplaced.

**Fail-closed by default:** when a guard check fails, `restore()` returns the text with
pseudonyms intact — no PII is leaked — and emits a `UserWarning`. Pass `strict=True`
to raise `RestoreGuardError` instead. Pass `detailed=True` to receive
`(text, {"security_events": [...]})` for programmatic inspection.

```python
from argus_redact import RestoreGuardError

try:
    restored = restore(llm_output, key, guard=True, anchor=anchor, strict=True)
except RestoreGuardError as e:
    # e.events is a list of security event dicts
    handle_guard_failure(e.events)

# Or inspect without raising:
restored, details = restore(llm_output, key, guard=True, anchor=anchor, detailed=True)
for event in details["security_events"]:
    log(event["reason_code"], event["count"], event["detail"])
```

Security event `reason_code` values: `provenance_failed`, `out_of_scope_pseudonym`,
`injection_suspected`, `guard_no_anchor`.

**Honest boundary:** the guard operates at the restore layer only. It verifies that a
response came from the expected session and contains only in-scope pseudonyms. It does
not inspect network transport, protect against key exfiltration, or prevent the LLM from
leaking context through paraphrase. Egress and transport security remain separate layers.

### mask strategy partial leakage

The `mask` strategy (e.g., `138****5678`) reveals prefix and suffix digits. For phone numbers, 3 prefix + 4 suffix digits may narrow the search space to ~10,000 numbers. For strict privacy, use `pseudonym` or `remove` strategy instead. PIPL/GDPR compliance profiles should prefer non-mask strategies.

### Seeded pseudonym codes are predictable, not random

When you supply a seed/salt, the `P-NNNNN` codes are drawn from a Mersenne-Twister (MT19937) stream (CPython's `random.Random`), which is deterministic and not cryptographic — so the codes are reproducible and, given enough outputs, predictable and linkable across redactions that share the same seed/salt. This is low severity: the code is an opaque sequence label, not derived from the original value, so it leaks no original-value information. It is a deterministic-but-predictable label, not a cryptographic commitment. Unseeded redactions use `secrets` instead and are not subject to this property.
