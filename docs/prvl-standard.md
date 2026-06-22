# PRvL: Privacy-Reversibility-Language Evaluation Standard

**Version 1.0** · argus-redact project · 2026

## What is PRvL?

PRvL (pronounced "prevail") is an open evaluation framework for PII redaction tools used with Large Language Models. It measures three axes that matter to real users:

- **P (Privacy):** Does redacted text leak PII?
- **R (Reversibility):** Can you restore original identities after LLM processing?
- **L (Language/Usability):** Does the LLM still understand and produce useful output?

Traditional evaluation only measures detection accuracy (precision/recall/F1). PRvL measures **what happens after detection** — the full redact → LLM → restore pipeline.

---

## Why PRvL?

Existing PII tools report F1 scores, but users care about different questions:

| What tools measure | What users need to know |
|-------------------|------------------------|
| "We detect 95% of phone numbers" | "Will my phone number appear in ChatGPT's response?" |
| "F1=0.97 on benchmark X" | "Can AI still help me after my data is encrypted?" |
| "Supports 50 PII types" | "Can I get my original data back after AI processes it?" |

PRvL answers the user's questions, not the developer's.

---

## Three Axes

### P — Privacy (0-100%)

**Question:** Does PII from the original text appear in the LLM's response?

**Measurement:**
1. Redact a text containing known PII
2. Send the redacted text to an LLM with a task prompt
3. Check if any original PII strings appear in the LLM's response

```
P = 1 - (PII tokens found in LLM output / total PII tokens in original)
```

**Target:** P ≥ 99%. Any PII leak is a failure.

### U — Usability (0-100%)

U has two sub-axes that should both be reported. Only the structural axis is part of the grade; the pragmatic axis is informational.

#### U-structural — Semantic token preservation

**Question:** Does the redacted text retain its non-PII semantic surface?

**Measurement:**
1. Redact a text
2. Check that non-PII semantic tokens (verbs, context words) survive redaction

```
U_structural = semantic tokens preserved in redacted text / total semantic tokens
```

**Target:** U_structural ≥ 95%. Trigger words like "diagnosed", "salary", "住在" must survive.

**Key principle:** Only the PII content should be redacted, not the surrounding context. "确诊糖尿病" → "确诊MED-51675" (✓) not "MED-51675" (✗).

#### U-pragmatic — LLM-judged task quality

**Question:** Does the LLM still produce a useful output given the redacted input?

**Measurement:**
1. Redact a text, send to LLM with a task prompt
2. Have a separate judge LLM score the output quality on 0.0–1.0

```
U_pragmatic = mean(judge_score) over (text, task) cells
```

**Target:** None. U_pragmatic varies by model and task; report the distribution, do not gate on a threshold. It is informational because it depends on the downstream LLM, not on the redaction tool.

**Caveat:** LLM-as-judge introduces evaluator bias. Spot-check a sample manually before drawing conclusions across tools.

### R — Reversibility (0-100%, per task type)

**Question:** Do pseudonym tokens survive LLM processing so restore() works?

**Measurement:**
1. Redact a text (producing pseudonyms like P-83811, MED-51675)
2. Send to LLM with a specific task
3. Check how many pseudonyms appear in the LLM's response

```
R = pseudonym tokens in LLM output / total pseudonym tokens in redacted text
```

**Critical insight:** R depends on task type, not tool quality:

| Task Type | Example | Expected R (primitive layer) | Why |
|-----------|---------|:----------:|-----|
| **Reference** | Summarize, translate | ≥ 90% | LLM quotes original tokens; literal substring `restore()` catches them |
| **Extract** | QA, data extraction | ≥ 50% | LLM partially quotes; mixed restore success |
| **Creative** | Advice, writing | ~0% | LLM paraphrases / introduces variants (titles, pronouns, partial references); literal `restore()` cannot follow |

**A tool should NOT be penalized for low R on creative tasks.** When you ask "give health advice for MED-51675", the LLM correctly says "manage your diet" without repeating MED-51675. This is by design.

### What the numbers above measure (and what they don't)

The R column above is the **primitive layer** measurement — `restore()` is a
literal substring inverse, and its R is bounded by how often the LLM echoes
pseudonyms verbatim. This is the **floor**, not a ceiling.

A `compose` layer (see [Architecture Layers](architecture-layers.md)) can lift
R higher via heuristic helpers:

- **`compose.prompt_anchor()`** — input-side system-prompt addendum asking the
  LLM not to abbreviate / retitle / pronoun-substitute. Reduces variant
  generation at the source.
- **`compose.expand_aliases()`** — output-side surname+title composite alias
  expansion (e.g., `张先生` → `黄先生` when the key has `张三` → `黄芳`).
  Best-effort coverage of common patterns.

Compose-layer R is **best-effort and unbounded above** — depends on LLM
compliance with the prompt anchor and on alias coverage breadth. PRvL
standard does not certify compose-layer R; that's an empirical, version-by-
version measurement.

Full-fidelity round-trip — NLP coreference resolution, paraphrase reversal,
multimodal — is **out of scope** for both primitive and compose layers. That
work belongs to downstream products (e.g., a coref-aware gateway) or to
caller-side post-processing.

### X — Re-identification resistance (extension)

**Question:** after redaction, can an LLM still re-identify the subject by combining
the *residual quasi-identifiers* (age, city/district, occupation, employer, sensitive
attribute, hobby) with a known candidate pool? (cf. arXiv 2603.18382.)

**Metric:** re-identification rate = correct top-1 matches / N, per (redactor × model).
**Lower is better.** Reported alongside a `raw` (no-redaction) upper bound.

**Methodology (closed-world):** a fully synthetic candidate pool + profile set
(`tests/benchmark/fixtures/reid_profiles.json`); each profile is redacted, then an
OpenAI-compatible LLM is asked to match it to the numbered pool
(`python -m tests.benchmark.reid_eval`). No real people, no live web.

**Scope caveat (read this):** this is a **controlled, closed-world directional
indicator on a small synthetic set (N=24), per model** — *not* a real-world
re-identification guarantee or an upper bound on adversarial inference. `fast` mode
removes explicit PII but not quasi-identifiers, so a **high residual re-id rate is
expected**; the metric exists to quantify that gap honestly — *removing explicit
PII is not anonymization*. The residual comes from the *combination* of surviving
quasi-identifiers, not any single field: coarsening one field (e.g. location) does
not measurably reduce it, and removal is at least as good (see
[the explored-and-removed generalize experiment](design-quasi-identifier-generalization.md)).
It is a documented limitation, not a gated roadmap promise.

---

## Test Methodology

### Minimum test corpus

A PRvL evaluation requires at least:
- 10 texts with known PII across multiple types (L1 direct identifiers + L3 sensitive attributes)
- 4 task prompts covering reference, extract, and creative tasks
- 3 LLMs (at least 1 commercial + 1 open-source)

### Test protocol

```
For each (text, task_prompt, llm) combination:
  1. redacted, key = redact(text)
  2. prompt = task_prompt.format(text=redacted)
  3. llm_output = query_llm(prompt)
  4. restored = restore(llm_output, key)
  5. Measure P: count PII tokens in llm_output
  6. Measure U: count semantic tokens in redacted
  7. Measure R: count pseudonym tokens in llm_output
```

### Reporting format

PRvL scores should be reported as:

```
PRvL v1.0 Evaluation
Tool: [name] v[version]
Date: [date]
Corpus: [N] texts, [M] task prompts

Fast Mode (no LLM):
  P = [score]%
  U = [score]%
  R = [score]% (direct restore)

Through-LLM (per model):
  [Model Name]:
    P = [score]%
    R-reference = [score]%
    R-extract = [score]%
    R-creative = [score]%
    Response quality: [pass/fail]
```

---

## Scoring Thresholds

| Level | P | U-structural | R-reference | Description |
|-------|:-:|:------------:|:-----------:|-------------|
| **Gold** | 100% | ≥ 98% | ≥ 90% | Production-ready for sensitive data |
| **Silver** | ≥ 99% | ≥ 90% | ≥ 70% | Suitable for most use cases |
| **Bronze** | ≥ 95% | ≥ 80% | ≥ 50% | Minimum viable protection |
| **Fail** | < 95% | < 80% | < 50% | Not recommended |

R-extract, R-creative, and U-pragmatic are informational only, not part of the grade.

---

## Reference Implementation

The reference PRvL benchmark is implemented in argus-redact:

```bash
# Fast PRvL (no LLM required)
pytest tests/benchmark/test_prvl.py -v -s

# Through-LLM PRvL (requires Ollama)
pytest tests/benchmark/test_prvl.py -v -s -m semantic

# Multi-LLM PRvL (requires Poe API key)
export POE_API_KEY=your_key
pytest tests/benchmark/test_prvl_multi_llm.py -v -s -m semantic
```

Source code: `tests/benchmark/test_prvl.py`, `tests/benchmark/test_prvl_multi_llm.py`

---

## argus-redact v0.6.4 Results

Evaluated against the reference test suite. Applies to v0.6.5 — the
v0.6.4 → v0.6.5 diff was compliance metadata SSOT exports only, with no
change to redact / restore / pseudonym behavior.

### Fast Mode (no LLM)

| Axis | Score | Grade |
|------|:-----:|:-----:|
| P (Privacy) | 100% | Gold |
| U-structural | 100% | Gold |
| R (Direct restore) | 100% | Gold |

### Through-LLM (4 frontier LLMs × 2 profiles)

Setup: 4 task cases × 2 profiles (`default` / `pseudonym-llm`) × 4 frontier
LLMs via Poe API. Privacy = leak count of original PII tokens / total PII
tokens. U-pragmatic = task quality 0.0–1.0 judged by Claude-Opus-4.5.

#### Privacy (P)

| Profile | Model | P | Grade |
|---|---|:---:|:---:|
| `default` | Claude-Opus-4.5 | 100% | Gold |
| `default` | GPT-5 | 100% | Gold |
| `default` | Gemini-2.5-Pro | 100% | Gold |
| `default` | GLM-4.5 | 100% | Gold |
| `pseudonym-llm` | GPT-5 | 100% | Gold |
| `pseudonym-llm` | Gemini-2.5-Pro | 100% | Gold |
| `pseudonym-llm` | GLM-4.5 | 100% | Gold |
| `pseudonym-llm` | Claude-Opus-4.5 | 96% | Bronze |

**Finding — pseudonym-llm + Claude-Opus-4.5 leak:** Claude-Opus-4.5
occasionally treats realistic-looking reserved-range fakes as if they were
real values it should preserve verbatim, and partially reconstructs
original-looking patterns. Out of 4 task cases, this surfaced once. Other
LLMs in the test did not exhibit this behavior. For maximum P, prefer
`default` profile when the downstream model is Claude-Opus-4.5.

#### U-pragmatic (LLM-judged task quality, informational)

| Profile | Model | U-pragmatic |
|---|---|:---:|
| `default` | GPT-5 | 0.57 |
| `default` | GLM-4.5 | 0.50 |
| `default` | Claude-Opus-4.5 | 0.42 |
| `default` | Gemini-2.5-Pro | 0.35 |
| `pseudonym-llm` | GPT-5 | 0.55 |
| `pseudonym-llm` | GLM-4.5 | 0.53 |
| `pseudonym-llm` | Claude-Opus-4.5 | 0.50 |
| `pseudonym-llm` | Gemini-2.5-Pro | 0.30 |

**Read:** `pseudonym-llm` lifts U-pragmatic on 3 of 4 models (Claude
+0.08, GLM +0.03, GPT roughly flat) at the cost of the Claude leak above.
Gemini-2.5-Pro is the outlier on both axes — investigate before deploying
behind it.

#### Reversibility (R) by task type

R-reference / R-extract / R-creative were not re-measured in this run. The
v0.5.x baseline (still valid because `restore()` semantics are unchanged)
holds: R-reference ≥ 90% across LLMs, R-extract ~50% on summarize/QA
tasks, R-creative ≈ 0% on advice/writing tasks (by design — see "R is
task-dependent" above).

### Overall Grade

- **`default` profile: Gold** across all 4 frontier LLMs
- **`pseudonym-llm` profile: Gold on 3/4 LLMs, Bronze on Claude-Opus-4.5**

### Caveats specific to this run

- n = 4 task cases per cell. Differences ≤ 0.05 in U-pragmatic should be
  treated as noise.
- `pseudonym-llm` rejects inputs containing reserved-range names
  (张三 / 王五 / etc.) to prevent re-encoding loops. Test cases use
  黄芳 / 王建国 / 赵敏 instead.
- LLM-as-judge bias: Claude-Opus-4.5 judging tasks where Claude-Opus-4.5
  is also under test introduces possible self-preference. Cross-judge
  validation is on the roadmap.

---

## Design Principles

1. **Measure what users care about**, not what's easy to measure
2. **Task-aware evaluation** — don't penalize correct LLM behavior
3. **Multi-LLM testing** — results vary significantly across models
4. **Reproducible** — all tests are automated with fixed seeds
5. **Open** — anyone can run the benchmark on their own tool

---

## Contributing

PRvL is an open standard. To propose changes:
- Open an issue at [argus-redact/issues](https://github.com/wan9yu/argus-redact/issues)
- Tag with `prvl-standard`
- Include rationale and test data supporting the change

---

## Citation

```
@standard{prvl2026,
  title={PRvL: Privacy-Reversibility-Language Evaluation Standard for PII Redaction},
  author={argus-redact project},
  year={2026},
  version={1.0},
  url={https://github.com/wan9yu/argus-redact/blob/main/docs/prvl-standard.md}
}
```
