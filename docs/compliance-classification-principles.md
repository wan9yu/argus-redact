# Compliance classification — principles and reasoning

This document states *how* argus-redact decides which statutory obligations each PII type carries,
and *why* the debatable calls were decided the way they were. The per-type result is published in
[`compliance-mappings.md`](compliance-mappings.md); this is the reasoning behind it. Its purpose is
to keep future classifications consistent — a new PII type should be classifiable by re-applying the
rules here, not by re-litigating first principles.

## Stance: a transparent, conservative, overridable default

argus-redact is base infrastructure. It does **not** hand down a definitive legal verdict — that would
be brittle and a liability. It offers a **default** classification that is:

- **Transparent** — every mapping is published next to its statute citation and a one-line rationale, so
  a user or auditor can see the basis and disagree with it specifically.
- **Conservative (fail-safe)** — where authorities genuinely diverge, we **over-flag**: treat the type as
  more protected, never silently downgrade it. An over-classification costs a little extra ceremony; a
  silent under-classification is a compliance hole.
- **Designed to be overridden** — the mapping is data (per-type article sets + membership sets), so a
  future compliance-profile layer can select or override it per jurisdiction and risk posture. The
  default is a starting point, not a ceiling or a floor imposed on the user.
- **Convenient** — the default needs no configuration for the common case.

## The framework

**PIPL (China).** Every personal-information type carries a **universal floor**: Art.13 (a lawful basis
is required) and Art.51 (the processor's security-measures obligation — both apply to *all* PI
processing). A type that is **sensitive personal information** additionally carries Art.28 (definition),
Art.29 (separate consent), Art.55 (PIA), and Art.56 (PIA content + retention). There is no
sensitivity-score gate: membership in the sensitive-PI set is what triggers the four sensitive articles.

**Membership test (Art.28).** A type is sensitive PI if it falls in an enumerated Art.28 category
(biometric, religious belief, specific identity, medical/health, financial accounts, whereabouts,
minors < 14) **or** the Art.28 ¶1 general harm clause captures it (information whose leakage may harm
personal dignity or endanger personal or property safety — the enumerated list is non-exhaustive).

**GDPR (EU).** Art.9 special categories (racial/ethnic origin, political opinions, religious/
philosophical belief, trade-union membership, genetic, biometric-for-ID, health, sex life/orientation)
are marked. Criminal-conviction data is **Art.10**, a separate dimension — deliberately *not* Art.9.

**HIPAA (US).** The Safe Harbor identifiers (45 CFR 164.514(b)(2)(i), letters A–R) are mapped where a
type is one of them; the letter is recorded for traceability.

## How to classify a new type (the procedure)

1. Does it fall in a GDPR Art.9 category? Mark GDPR-special (or Art.10 for criminal-conviction data).
2. Is it a HIPAA Safe Harbor identifier? Record the letter.
3. For PIPL: is it in an enumerated Art.28 category, or does the harm clause capture it (leakage →
   impersonation / discrimination / property or dignity harm)? If yes → sensitive-PI member. If it is a
   high-sensitivity type you leave a **non-member**, record an explicit, cited downgrade reason.
4. When in doubt, **over-flag** (member). Cite the controlling article; add the type as data so a profile
   can later override it.

## The boundary calls, and why

These are the debatable decisions this framework resolved. Recorded so they are not silently reversed.

- **National-ID / identity-credential numbers** (resident ID, passport, SSN, Aadhaar, …) → **sensitive-PI
  members**, on the **Art.28 ¶1 harm clause**, *not* the "specific identity" (特定身份) enumerated
  category. Rationale: GB/T 45574-2025 reads 特定身份 as *status* (e.g. disability, sensitive occupation)
  and does not per-se enumerate ID numbers; GB/T 35273-2020 Annex B did list them as sensitive, and the
  harm (impersonation, fraud) is unambiguous. The harm clause captures them regardless of the
  standards' divergence — the conservative, divergence-proof basis.
- **`credit_code` (Unified Social Credit Code)** → **non-member**. It identifies a legal entity /
  organization, not a natural person (PIPL Art.4), so the sensitive-PI regime does not attach. Consistent
  with `cnpj` (Brazil's company registry number). The universal Art.13/51 floor still governs any
  natural-person PI processed alongside it.
- **Machine / API secrets** (API keys, access tokens, private keys) → **non-members**. They are machine
  credentials, not information about a natural person; handled as security secrets at the highest
  redaction priority for a different reason (secret leakage), not as sensitive PI.
- **`ethnicity`, `political`, `sexual_orientation`** → **sensitive-PI members via the general harm
  clause.** All three are GDPR Art.9 categories that PIPL does not enumerate; the harm clause
  (discrimination / dignity harm on disclosure) captures them. Classified identically for consistency —
  a GDPR-Art.9 category that PIPL does not enumerate is treated as a general-clause member by default.
- **`financial`** (free-text salary / income / credit-score mentions) → **sensitive-PI member via the
  general harm clause**, *not* the enumerated "financial accounts" (金融账户) category, and **not** a HIPAA
  account-number identifier — because it is not an account number. Structured account types
  (`bank_card`, `credit_card`, `housing_fund`) are the enumerated financial accounts (and HIPAA (J)).
- **`nhs_number`** → GDPR **Art.9** (a number assigned to identify an individual for health purposes is
  health data, GDPR Recital 35) and PIPL sensitive (health). This is a per-typedef GDPR override; the
  GDPR-special set is derived from the live registry so such overrides are never silently dropped.
- **`criminal_record`** → GDPR **Art.10** (criminal convictions/offences), removed from Art.9.

## Keeping drift low

- The published mappings are generated from a single frozen decision table, which is checked against the
  live registry (the "old" state) and against the harm-based rule (the "new" state) — a green test suite
  alone is not accepted as proof; the table is reviewed against the statute.
- Membership and article sets are **data**. New jurisdictions or risk postures are expressed as override
  profiles over this data, not as new branching logic.
- GDPR-special membership is derived from the live registry, so a per-type override cannot drift out of
  the published classification unnoticed.
- Selectable per-jurisdiction / per-type override profiles are on the roadmap; this default is their
  base layer.
