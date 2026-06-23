# English detection breadth: an explored-and-cut design

> **Status: cut.** The evidence-detector framework was generalized to support
> English (a word-boundary candidate scan), and an English re-identification eval
> fixture + harness were built. But the eval falsified the premise — detecting and
> removing English occupation / condition / hobby does **not** reduce
> re-identification — so the three English detectors were never built. The
> framework generalization and the eval harness were kept (they are reusable).
> This note records *why*, so the idea isn't silently re-attempted.

## The hypothesis

v0.7.12 shipped evidence-gated **Chinese** detectors for occupation / medical
condition / hobby — quasi-identifiers that survive explicit-PII removal. The
natural follow-up was to do the same for **English**. We applied the discipline
from [the generalize exploration](design-quasi-identifier-generalization.md): pin
**re-identification reduction** as the primary metric and validate each detector
against it *before* building (fixture + ablation first, ranked detectors second).

## What was built — and kept

- **A language-neutral generalization of the `evidence_detector` framework.**
  Candidate generation is now pluggable: `candidates_cjk` (Chinese char-substring
  matching, byte-identical to the original) and `candidates_word` (English
  word-boundary matching — `nurse` never matches inside `nursery`), selected by a
  fn-pointer on `DetectorConfig`; plus a multi-word lexicon-confidence proxy for
  English (`new_word` / `from_ron_word`). The shipped Chinese detectors are
  **byte-identical** (0 golden moves). *Kept* — reusable for any future
  word-delimited language, and adversarially reviewed (one inter-token
  over-capture bug was caught and fixed before it shipped).
- **A separate English closed-world re-identification eval.** An 18-persona
  fixture (`tests/benchmark/fixtures/reid_profiles_en.json`) + an English
  prompt/pool in `reid_eval.py` / `reid_ablation.py` (`--pool en`). The pool is
  single-language on purpose — mixing scripts lets a model re-identify trivially
  by language. *Kept* — reusable measurement infrastructure.

## What was NOT built

The three English detectors (occupation / condition / hobby). The eval cut them
before a line of detector code was written.

## The measurement

DeepSeek, the 18-persona closed-world fixture, `mode="fast"`. Re-id rate =
fraction of personas the model correctly matched to its candidate.

| redactor | re-id rate |
|---|---|
| raw | 100% (18/18) |
| `argus_fast` (names / phones / emails removed) | 100% (18/18) |

Single-signal ablation — strip one survivor from the `argus_fast`-redacted text,
re-ask:

| stripped | re-id | drop vs none |
|---|---|---|
| occupation | 100% | 0 |
| condition | 100% | 0 |
| hobby | 100% | 0 |

Combined ablation:

| stripped | re-id |
|---|---|
| occupation + condition + hobby | 100% |
| city only | 100% |
| occupation + condition + hobby + **city** | 100% |

## What this falsified

Even removing names, phones, emails, **all three** target quasi-identifiers,
**and** city, the model still re-identifies every persona — from the residual
(age + employer-type + prose) alone, in a closed candidate set. Detecting and
removing occupation / condition / hobby does **not** reduce English
re-identification.

This is the [generalize lesson](design-quasi-identifier-generalization.md) again:
re-identification is **combinatorial**. Removing a *subset* of quasi-identifiers
doesn't lower it while the rest remain; a per-document redactor cannot own
k-anonymity. Engineering a fixture where those three are the *only* discriminators
(so the metric would reward them) would be gaming the eval, not measuring reality.

**Contrast with Chinese:** there the same detectors moved re-id modestly and
provider-dependently (condition on DeepSeek, hobby on Qwen) — small but non-zero,
which together with their coverage value justified shipping. For English the
marginal re-id contribution is **zero**, and English free-text carries real
false-positive risk (`allergic to Mondays`, `she's a rockstar`). The gate we set —
*a detector that doesn't move re-id **and** adds precision risk is cut* — removes
them.

## Scope and honesty

Measured on one provider (DeepSeek), one synthetic 18-persona closed-world
fixture, fast mode. A different fixture or an open-world setting could differ —
but the combined+city saturation (100% re-id with everything we'd detect *plus*
city removed) makes a per-document occupation/condition/hobby detector an
implausible re-id lever regardless. English occupation/condition/hobby detection
could still be added later as **coverage** (privacy/compliance value independent
of re-id) if a concrete need arises; this note records only that it is **not
re-id-justified** today. The eval harness and fixture remain in-tree so the
measurement is reproducible: `ARGUS_REID_EVAL=1 python -m tests.benchmark.reid_eval
--pool en --provider <p>` and `... reid_ablation --pool en --provider <p>`.
