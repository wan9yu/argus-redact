# Security model

argus-redact's threat model and the cryptographic guarantees it makes (and
those it deliberately does not).

## Threat model

argus-redact runs locally. The threats it defends against are:

1. **PII leakage to the LLM**: anything the library returns as `downstream_text`
   must contain no original PII the library detected.
2. **De-anonymization of redacted output**: an adversary who observes one or
   more `(fake, original)` pairs (e.g. recovered from a leaked log) must not
   be able to recover the rest of the originals from the redacted output.
3. **Cross-tenant linkage**: two tenants of a multi-tenant deployment using
   different salts must not have their fake values collide.
4. **Audit-trail integrity**: the `key` dict returned alongside redacted
   output is the canonical fake → original mapping; restoration via that
   dict must not require re-deriving fakes.

argus-redact does NOT defend against:

- A locally-rooted attacker with read access to the salt or in-process memory.
  The salt is the cryptographic root of trust; if it leaks, everything
  derivable from it leaks.
- Statistical re-identification from quasi-identifiers retained by design
  (e.g. `mask` strategy keeping 7 of 11 phone digits visible). Use compliance
  profiles (`profile="pipl"` / `"hipaa"`) to harden these defaults.
- Side channels (timing, memory, logs the caller writes themselves).

## Salt handling (v0.6.1+)

Realistic-strategy fake derivation uses **HMAC-SHA256** keyed by the salt the
caller provides, with the entity's `(type, value)` as the message:

```
master_key = HMAC-SHA256(salt, type + ":" + value)         (32 bytes)
fake_bytes = SHAKE-256(master_key)                         (extendable)
fake_value = faker_reserved(value, ShakeRng(fake_bytes))
```

Properties:

- **Full-salt entropy preserved**: the caller's full salt bytes flow into the
  HMAC. Pre-v0.6.1 truncated to 8 bytes (≈63-bit effective entropy); fixed.
- **Forward-secure mapping**: knowing a `(fake, original)` pair does not let
  an attacker recover the salt without brute-forcing HMAC-SHA256.
- **Process-stable**: identical `(salt, type, value)` produces an identical
  fake regardless of which process / Python interpreter runs the redaction.
  Pre-v0.6.1 used `hash(entity_type)` which was randomized per-process via
  PYTHONHASHSEED; fixed.

## Salt sources, in priority order

The realistic / pseudonym-llm path resolves the salt as follows:

1. **Explicit `salt=<bytes>`** kwarg: used verbatim. Recommended; preserves
   full entropy.
2. **Explicit `seed=<int>`** kwarg: encoded as 8-byte big-endian (back-compat;
   provides 64-bit entropy).
3. **`ARGUS_REDACT_PSEUDONYM_SALT` env var**: bytes of the UTF-8 encoded
   string. Convenient for deployments; document the value as an operator
   secret.

If none are set, the realistic path raises `ValueError`. Pre-v0.6.1 silently
fell back to `b""` which collapsed HMAC to a deterministic public hash.

## Faker output guarantees

- **Reserved range**: realistic fakers emit only values in officially-reserved
  ranges (RFC 5737 IP, NANP 555-01XX, SSA 999-XX SSN, etc.). Not a real
  person's PII alias.
- **Identity-pass guard** (v0.6.1+): a faker can never return the input
  itself — the wrapper rolls the RNG up to 10 times to find a fake distinct
  from `value`. Pre-v0.6.1 the small reserved-name pool (10 entries each for
  zh/en) could pick the input back with ~10% probability.
- **No real common names in EN reserved pool** (v0.6.1+): `James Smith` and
  `Bob Loblaw` removed; replaced with additional Doe/Roe legal placeholders.

## Strategy reversibility

`is_strategy_reversible(strategy)` returns whether `restore()` can map the
redacted form back to the original via the key dict.

| Strategy | Reversible | Default for |
|---|:---:|---|
| `pseudonym` | ✓ | person, organization |
| `realistic` | ✓ | (pseudonym-llm profile) |
| `remove` | ✓ | id_number, ssn, address, ... |
| `keep` | ✓ | self_reference (whitelisted text only — see H6 fix) |
| `mask` | ✗ | phone, email, bank_card |
| `name_mask` | ✗ | (opt-in) |
| `landline_mask` | ✗ | (opt-in) |
| `category` | ✗ | location |

Mask strategies are irreversible by design: they keep some plaintext digits
visible (`138****5678`). Use `profile="pipl"` / `"hipaa"` to override these
defaults to `remove` for stricter privacy.

## `keep` strategy whitelist (H6, v0.6.1+)

`strategy="keep"` preserves an entity's text verbatim. v0.6.1 restricts this
to a whitelist of self-reference forms — pronouns (`I` / `我` / `我们`) and
kinship phrases (`我妈` / `我老公` / ...). Any other use downgrades to the
type's default strategy with a `SecurityWarning`.

This guards against Layer-3 (LLM-driven semantic detection) misclassifying
a sensitive value (e.g. an SSN string) as `self_reference`. Pre-fix, the
keep path would emit the original verbatim into `downstream_text`.

## What is in `result.key` and `key` files

The `key` dict (returned alongside redacted text and persisted by the CLI to
`-k <path>`) maps every fake to its original. **It contains plaintext
originals.** Treat it as sensitive material:

- Never commit `key.json` to source control.
- Encrypt at rest if persisted.
- The CLI writes key files mode 0644 in v0.6.1; v0.6.2 hardens this to 0600.

## What is in `StreamingRedactor.export_state()`

v0.6.1 export_state still includes the salt and `accumulated_key` (which
contains plaintext originals). v0.6.2 changes the default to omit the salt
and require `salt=` kwarg on `from_state`. Even after that change, the
`accumulated_key` field still carries originals — encrypt at rest.

## Reporting issues

Email: wangyu@go2imagination.com. Please do not file public GitHub issues
for security-sensitive findings.
