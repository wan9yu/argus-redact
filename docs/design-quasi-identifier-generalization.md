# Quasi-identifier generalization: an explored-and-removed design

> **Status: removed.** A `generalize` strategy and a Chinese admin-region
> coarsening path were built, measured against the re-identification eval, and
> then removed because the measurement falsified the premise they were built on.
> This note records *why*, so the idea isn't silently re-attempted. The region
> and occupation **detectors** that were built alongside it were kept — they feed
> the default `remove` path and are independently useful.

## The hypothesis

After a redactor strips explicit PII, an LLM can often still re-identify the
subject by matching *residual quasi-identifiers* (age, city, occupation, a
sensitive attribute) against a candidate pool — the inference-re-identification
threat described in [Ko et al. 2026 (arXiv:2603.18382)](https://arxiv.org/abs/2603.18382).
The intuition was: if we **coarsen** quasi-identifiers instead of leaving them
verbatim (`上海浦东新区建国路100号` → `上海市`, district → city), residual
re-identification should drop while the downstream LLM keeps useful context.

So we built:

- a `generalize` redaction strategy (lossy, irreversible — omitted from the
  restore key), driven by a GB/T 2260 Chinese admin-region gazetteer with a
  `coarsen(span, level)` ancestor lookup (`city` | `province`);
- evidence-gated zh **region** and **occupation** detectors (so bare regions /
  job titles are caught at L1, not only structured addresses);
- a re-identification eval (`tests/benchmark/reid_eval.py`, the "PRvL+ X axis"):
  a closed-world, fully synthetic 24-persona fixture, `temperature=0`, asking an
  LLM to match a redacted profile back to a candidate in the pool. Lower re-id
  rate = better.

## The measurement

Run across three OpenAI-compatible backends (DeepSeek, Qwen, OpenRouter),
`temperature=0`, same fixture, before vs after each change. Re-id rate =
fraction of the 24 personas the LLM correctly re-identified.

**Occupation removal** (detect job titles → default `remove`) — the one change
that moved the metric, modestly:

| provider | before | after |
|---|---|---|
| DeepSeek | 87.5% | 83.3% |
| Qwen | 95.8% | 91.7% |

About one persona per provider — a real but small drop, near the resolution of a
24-item fixture.

**Location generalization** (`generalize`, keep-city) vs full removal —
within a single run, on the same engine:

| provider | `argus_fast` (remove) | `argus_generalize` (keep city) |
|---|---|---|
| DeepSeek | 83.3% | 83.3% (tie) |
| Qwen | 91.7% | 87.5% (1 better) |
| OpenRouter | 79.2% | 79.2% (tie) |

## What this falsified

The honest reading is **tie-to-noise**: coarsening a quasi-identifier does **not
reduce** single-record re-identification on this fixture, and **removal is at
least as good** — because removal deletes the signal entirely, whereas
coarsening *keeps a true-but-coarse signal* (a surviving `上海市` still narrows
to the city's cluster in the candidate pool). It does **not** "backfire" — the
within-run numbers never show generalize clearly worse than removal — but the
motivating claim ("coarsening reduces re-id") is not supported.

Two structural reasons it can't be the privacy lever it was framed as:

1. **The residual is in the *combination*, not any one field.** In the fixture,
   age + coarse location + a free-text attribute is unique across all 24
   personas; coarsening one field while the others survive verbatim doesn't
   break the combination. Reducing re-id materially means suppressing the
   *combination* (and the free-text attributes that survive verbatim), not
   coarsening a single field.
2. **k-anonymity is a property of a dataset, not a document.** True
   generalization-to-anonymity needs population-level class sizes ("coarsen
   until ≥ k records share these values"). argus is a per-document, single-pass
   redactor and structurally does not have that knowledge — so it cannot
   *guarantee* re-id reduction by coarsening, only trade specificity for
   utility.

## The decision

- **Removed** the `generalize` strategy, `coarsen()`, and the `level` config
  axis. It was never released (absent from every tag through v0.7.11), so this
  is a clean pre-release removal, not an API break.
- **Kept** the evidence-gated region and occupation detectors and the GB/T 2260
  gazetteer (now purely the region detector's dictionary). They feed the default
  `remove` path — legitimate PII-detection coverage, and occupation removal is
  the one measured re-id win.
- **Decoupled** the re-id eval from generalization. `reid_eval.py` keeps only
  `raw` vs `argus_fast`; the high residual re-id rate stays as an **honest
  documented limitation** — *removing explicit PII is not anonymization* — not a
  gate that a future generalization feature is promised to close.

If generalization returns, it should return as a **utility-preservation**
feature (a true-but-coarse value for analytics / training on sanitized corpora,
where no other strategy fits: `realistic` gives a *fake* value, `remove` gives
nothing, `pseudonym` gives an opaque code) — explicitly *not* a privacy control,
and gated on a named downstream consumer. Re-id reduction itself is a separate,
combination-level problem.
