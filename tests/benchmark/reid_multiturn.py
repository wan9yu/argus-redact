"""Streaming cross-turn linkage measurement (research spike) — eval/defensive only.

Splits each fixture persona across 2-3 turns, redacts each turn through ONE shared
StreamingRedactor (consistent pseudonyms across turns), concatenates, and asks the
LLM to re-identify — vs single-shot argus_fast. Quantifies whether multi-turn
splitting + consistent-pseudonym linkage changes re-id. cf.
docs/design-streaming-cross-turn-linkage.md. Off by default; ARGUS_REID_EVAL=1 +
a provider key required. NO new engine behavior.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys


# Split on Chinese sentence/clause punctuation, KEEPING the terminator with its
# clause so each turn stays a complete sentence-group (the StreamingRedactor
# buffers to sentence boundaries; feeding whole clauses keeps per-turn redaction
# clean and the cross-turn key consistent). Falls back to ASCII '.' for the two
# English profiles in the fixture.
_SPLIT_RE = re.compile(r"(?<=[。！？])|(?<=\. )|(?<=，)")


def _split_into_turns(text: str, n_turns: int = 3) -> list[str]:
    """Split ``text`` into ~``n_turns`` roughly-equal turns on CJK punctuation.

    Splits on 。！？ (and ，/ASCII '. ' as fallbacks), keeps the terminator, then
    groups the resulting clauses into at most ``n_turns`` near-equal buckets. A
    short persona may yield fewer turns; that is fine — the point is to spread the
    quasi-identifiers across multiple turns of one shared redactor session.
    """
    import math

    clauses = [c for c in _SPLIT_RE.split(text) if c and c.strip()]
    if len(clauses) <= 1:
        return [text]
    target = min(n_turns, len(clauses))
    per = math.ceil(len(clauses) / target)
    return ["".join(clauses[i : i + per]) for i in range(0, len(clauses), per)]


def _redact_multiturn(text: str, salt: int, n_turns: int = 3) -> tuple[str, int]:
    """Redact ``text`` as a multi-turn stream through ONE StreamingRedactor.

    Returns ``(concatenated_redacted_transcript, n_turns_emitted)``. The single
    shared redactor gives the SAME pseudonym/placeholder code to the same entity
    across turns (the consistent-pseudonym linkage signal the doc discusses) and
    accumulates a shared key. mode='fast' matches the single-shot argus_fast
    baseline this is compared against.
    """
    from argus_redact.streaming import StreamingRedactor

    redactor = StreamingRedactor(salt=salt, lang=["zh", "en"], mode="fast")
    pieces: list[str] = []
    for turn in _split_into_turns(text, n_turns):
        res = redactor.feed(turn)
        if res.downstream_text:
            pieces.append(res.downstream_text)
    final = redactor.flush()
    if final.downstream_text:
        pieces.append(final.downstream_text)
    return "".join(pieces), len(pieces)


def main() -> int:
    if os.environ.get("ARGUS_REID_EVAL") != "1":
        print("multi-turn linkage measurement skipped "
              "(set ARGUS_REID_EVAL=1 + a provider key)")
        return 0

    # REUSE reid_eval.py's real helpers — client, prompt, parser, fixture, salt.
    from tests.benchmark import reid_eval as E

    ap = argparse.ArgumentParser(
        description="streaming cross-turn linkage measurement (research spike)"
    )
    ap.add_argument("--provider", choices=list(E.PROVIDERS), default=None,
                    help="LLM backend (default: first with a key in env)")
    ap.add_argument("--model", default=None, help="override model id")
    ap.add_argument("--limit", type=int, default=None,
                    help="evaluate only the first N profiles")
    ap.add_argument("--turns", type=int, default=3,
                    help="max turns to split each persona into (default: 3)")
    args = ap.parse_args()

    # 1. Resolve provider (CLI arg, else reid_eval's "first with a key" logic).
    label, base_url, resolved_model, key = E.resolve_provider(args.provider)
    model = args.model or resolved_model

    # 2. Load the fixture via reid_eval's path constant + field layout.
    data = json.loads(E.FIXTURE.read_text(encoding="utf-8"))
    candidates = data["candidates"]
    profiles = data["profiles"][: args.limit] if args.limit else data["profiles"]

    print(f"\n[provider] {label} (model={model})")
    print(f"[fixture] {len(candidates)} candidates, {len(profiles)} profiles")
    print(f"[turns] up to {args.turns} turns per persona, ONE shared StreamingRedactor\n")
    print(f"{'arm':<22}{'re-id rate':<14}{'correct/N'}")
    print("-" * 48)

    # 3. Two arms over the SAME profiles + SAME candidate pool + SAME LLM ask:
    #    (a) single-shot argus_fast (the existing reid_eval baseline);
    #    (b) multi-turn: split → redact each turn through one shared redactor →
    #        concatenate → ask. Both use mode='fast' + reid_eval.SALT, so the only
    #        difference is single-document vs cross-turn-stream redaction.
    arms = {
        "argus_fast (1-shot)": lambda t: E.redactor_argus_fast(t),
        "argus_stream (multi)": lambda t: _redact_multiturn(t, E.SALT, args.turns)[0],
    }

    rates: dict[str, float | None] = {}
    for arm, redact_fn in arms.items():
        correct = n = 0
        for p in profiles:
            truth = p["truth"]
            try:
                redacted = redact_fn(p["text"])
            except Exception as e:  # noqa: BLE001
                print(f"[redact-error] {arm} truth={truth}: {e}", file=sys.stderr)
                redacted = p["text"]
            try:
                reply = E.call_llm(
                    base_url, model, key, E.SYSTEM,
                    E.build_prompt(redacted, candidates),
                )
            except Exception as e:  # noqa: BLE001
                print(f"[api-error] {arm} truth={truth}: {e}", file=sys.stderr)
                continue
            guess = E.parse_guess(reply)
            n += 1
            correct += int(guess == truth)
        rate = (correct / n) if n else None
        rates[arm] = rate
        rate_s = "n/a" if rate is None else f"{rate:.2%}"
        print(f"{arm:<22}{rate_s:<14}{correct}/{n}")

    # 4. Interpretation: does cross-turn splitting + consistent pseudonyms move
    #    re-id vs single-shot? The pseudonym is the same code every turn (required
    #    for downstream coherence) AND a linkage signal; quasi-identifiers also
    #    accumulate across turns. A near-zero delta means, on this fixture, the
    #    re-id signal already lives in the residual quasi-identifier COMBINATION
    #    that survives BOTH arms — splitting into turns neither hides nor amplifies
    #    it materially. A positive delta would mean the cross-turn transcript is
    #    MORE identifying than the single document.
    print()
    base = rates.get("argus_fast (1-shot)")
    multi = rates.get("argus_stream (multi)")
    if base is not None and multi is not None:
        delta = multi - base
        print(f"[delta] multi-turn re-id − single-shot = {delta:+.2%}")
        if abs(delta) < 0.05:
            print("[interpretation] within noise: on this fixture, splitting across "
                  "turns + consistent pseudonyms neither materially hides nor "
                  "amplifies re-id — the signal is the residual quasi-identifier "
                  "combination surviving both arms (cf. the design doc's linkage "
                  "discussion).")
        elif delta > 0:
            print("[interpretation] multi-turn transcript is MORE identifying — "
                  "cross-turn accumulation / the consistent-pseudonym linkage "
                  "signal raised re-id above the single-document baseline.")
        else:
            print("[interpretation] multi-turn transcript is LESS identifying than "
                  "single-shot on this fixture — likely a per-turn redaction-"
                  "coverage artifact, not unlinkability; treat with caution.")
    else:
        print("[interpretation] no comparable runs (an arm errored or was empty).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
