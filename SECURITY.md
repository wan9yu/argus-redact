# Security Policy

argus-redact is a privacy library — bug-class issues that affect PII redaction,
key restoration, or cryptographic derivation are treated as high priority.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.6.x   | ✅ |
| < 0.6   | ❌ (please upgrade) |

## Reporting a Vulnerability

**Preferred**: open a [private vulnerability advisory](https://github.com/wan9yu/argus-redact/security/advisories/new)
on this repository. This keeps the report private until a fix is published.

**Alternative**: email `wangyu@go2imagination.com` with subject prefix `[argus-redact security]`.
PGP encryption available on request.

### What to include
- Affected version(s)
- Reproduction steps or proof-of-concept
- Impact assessment (data confidentiality / integrity / availability)
- Optional: a proposed fix or mitigation

### Response SLA
- Acknowledgement within 7 days.
- Triage and severity assessment within 14 days.
- Fix timeline depends on severity:
  - **HIGH** (PII leak, crypto break): patch release within 30 days.
  - **MEDIUM**: next minor release.
  - **LOW**: bundled with planned work.

## Threat Model

The full threat model lives at [docs/security.md](docs/security.md).
Headline guarantees:
- Salt is the cryptographic root of trust; if it leaks, derivable mappings
  leak too. Treat as operational secret.
- Realistic-strategy fakes derive via HMAC-SHA256 keying + SHAKE-256 stream.
- All third-party GitHub Actions are pinned to commit SHAs.

## Recognition

Researchers who report a verified vulnerability are credited in the release
notes (opt-in; reply to the advisory if you'd like attribution).
