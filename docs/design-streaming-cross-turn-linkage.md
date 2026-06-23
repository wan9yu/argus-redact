# Streaming cross-turn linkage: a research spike

> **Status: research spike (explore-only, no feature).** This note documents the
> cross-turn linkage threat for `StreamingRedactor`, explains why a
> per-document/per-stream redactor *structurally* cannot fully prevent it, and
> references a measurement script that quantifies whether the threat is real on
> the reference fixture. **No new engine behavior is built here** — this is a
> threat-model record plus one measurement, in the spirit of
> [design-quasi-identifier-generalization.md](design-quasi-identifier-generalization.md).

## The threat

In a multi-turn dialogue, an attacker who can read the redacted stream may link
the same subject *across turns* even though each turn is individually redacted.
This is the inference / linkage threat described in
[Ko et al. 2026 (arXiv:2603.18382)](https://arxiv.org/abs/2603.18382). Two
mechanisms:

1. **Consistent-pseudonym-as-linkage-signal.** `StreamingRedactor`
   (`src/argus_redact/streaming.py`) reuses the *same* code for an entity across
   turns — a realistic fake or a placeholder like `P-04217`/`LOCA-59624` — by
   carrying an accumulated key across `feed()` calls in one session. This
   consistency is **required** for downstream coherence: the LLM must understand
   that turn-3's `P-04217` is turn-1's person, or it cannot reason about the same
   entity across the conversation. But the very same consistency **is** a linkage
   signal: an attacker reading the redacted stream can follow `P-04217` (or the
   reused fake name) from turn to turn and know it refers to one subject.

2. **Accumulated quasi-identifiers.** Each turn leaks a little — age in turn 1, a
   city or district in turn 3, a medical condition in turn 5. Individually each is
   below an identifying threshold; *jointly*, accumulated across the transcript,
   they can re-identify the subject against a known candidate pool. This is the
   same residual-quasi-identifier-combination effect measured by
   [reid_eval.py](../tests/benchmark/reid_eval.py), but spread across turns rather
   than packed into one document.

## Why a per-document redactor structurally can't fully prevent it

The utility/coherence requirement (consistent pseudonyms) is in **direct tension**
with cross-turn unlinkability:

- True cross-turn unlinkability would need **per-turn-fresh** pseudonyms, so the
  same subject gets a different code in every turn and an attacker can't follow
  the thread.
- But per-turn-fresh pseudonyms break the LLM's ability to reason about the same
  entity across turns — turn 3 could no longer connect "this person" back to
  turn 1.

This is a **fundamental tradeoff, not a bug**. `argus-redact` is a
per-document/per-stream redactor whose contract is "consistent, reversible
pseudonyms that keep an LLM pipeline coherent." That contract and full cross-turn
unlinkability cannot both hold. A redactor that picks coherence (as argus does)
therefore *cannot* structurally eliminate the consistent-pseudonym linkage
signal.

## What argus *does* help with

This is not "argus does nothing about cross-turn risk." Within each turn argus
still removes the explicit PII (names, phones, IDs) and — with this version — the
condition / hobby / region quasi-identifiers that the residual-quasi-identifier
work added to the default `remove` path. So:

- per-turn leakage is **reduced** — each turn carries fewer raw quasi-identifiers
  than the unredacted text;
- the residual linkage signal is the **pseudonym plus the surviving
  combination** of quasi-identifiers, not raw PII.

In other words, argus shrinks *what* accumulates across turns and replaces raw
identifiers with codes; it does not, and structurally cannot, make the same
subject unlinkable across turns while keeping the pseudonyms consistent.

## Measurement

[tests/benchmark/reid_multiturn.py](../tests/benchmark/reid_multiturn.py)
(`ARGUS_REID_EVAL=1` + a provider key required; off by default, no network without
the gate) splits each reference persona into 2–3 turns, redacts each turn through
**one shared** `StreamingRedactor` (consistent pseudonyms across turns),
concatenates the redacted turns into a multi-turn transcript, and asks an LLM to
re-identify the subject against the 24-candidate synthetic pool — versus
single-shot `argus_fast`. It prints both re-id rates, the delta, and a one-line
interpretation.

Closed-world, fully synthetic fixture
([reid_profiles.json](../tests/benchmark/fixtures/reid_profiles.json)); the number
is a controlled directional indicator, **not** a real-world linkage guarantee.

> **MEASURED (deepseek-chat, N=24, temperature=0):** single-shot `argus_fast`
> **79.2%** (19/24) vs multi-turn streaming **70.8%** (17/24) — delta **−8.3%**.
> (Run: `ARGUS_REID_EVAL=1 python -m tests.benchmark.reid_multiturn --provider deepseek`.)
>
> **Interpretation — the simple measurement is inconclusive about the threat.**
> Multi-turn came out *less* identifying than single-shot, the opposite of what a
> linkage-amplification threat would predict. This is almost certainly a per-turn
> redaction-coverage artifact (the streaming/`pseudonym-llm` path redacts each turn
> a touch more aggressively, and sentence-split turns give the model less joint
> context at once), **not** evidence that streaming is safer. It means this fixture's
> personas are already single-shot-identifiable, so splitting them across turns adds
> no *additional* linkage value the attacker didn't already have. Honestly quantifying
> the cross-turn threat needs a fixture where the subject is identifiable **only** by
> combining signals spread across turns — a future measurement, not built here. The
> theoretical concern (consistent pseudonym = a deliberate linkage signal) stands as a
> documented tradeoff regardless of this number.

## Directions for a future version (not now)

Honest options, none committed to and none overclaimed:

- **Per-session salt rotation.** Rotating the salt between sessions limits how far
  a pseudonym can be linked across *sessions*, but does nothing for linkage
  *within* a session — and changing the salt mid-session breaks coherence. A real
  tradeoff to characterize, not a fix.
- **Optional per-turn-fresh pseudonyms (unlinkability over utility).** An opt-in
  mode that trades the consistent-pseudonym coherence guarantee for cross-turn
  unlinkability, for callers who do not need the LLM to reason about the same
  entity across turns. This is a different product contract, not a tweak to the
  current one.
- **Document cross-turn linkage as an explicit limitation.** Regardless of which
  (if any) of the above ship, the consistent-pseudonym linkage signal should be
  named in the user-facing limitations: argus reduces per-turn leakage and keeps
  pipelines coherent; it does **not** guarantee that a subject is unlinkable
  across the turns of a conversation.

Per the project's documentation standards: this is scoped to the reference test
suite, honest about the limitation, and makes no absolute privacy claim.
