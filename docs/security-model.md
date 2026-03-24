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
| **Context inference** | "the CEO of [company] in [city] discussed quarterly results" — identity might be guessable from context alone | Layer 3 (semantic) tries to detect these. Use `generalize` strategy. No guarantee. |
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
| Original text | **Never** | Yes |
| Key file (if saved) | Only if user copies it | Yes (plaintext dict) |

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
