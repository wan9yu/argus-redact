"""text_intent person-FP ablation — the honest, reproducible §9.8 table.

§9.8 claim: the ``text_intent`` cross-layer hint suppresses person false-positives
on instruction-like text. When the engine classifies a text as
``text_intent="instruction"`` it raises the L1b person threshold (0.8 → 1.2),
which suppresses every evidence-scored candidate (max score 1.0 < 1.2). On a
command/prompt that merely *mentions* a name-shaped token, that token is a false
positive, and the hint removes it.

This harness measures person-FP/sample over ``fixtures/instruction_ablation.json``
(40 instruction texts, each carrying a name-shaped token but NO real person PII,
so every ``person`` detection is a false positive) under two conditions, in
``mode="fast"``:

  on  — text_intent suppression ACTIVE: the instruction text is run as-is, the
        engine sees ``text_intent="instruction"`` → threshold 1.2 → ~0 FP.
  off — text_intent suppression INACTIVE: the leading command clause is removed
        (the body after the first ``，`` / ``:`` delimiter), so the engine sees a
        plain non-instruction frame → default threshold 0.8 → the token fires.

``person_fp_per_sample.off`` > ``.on`` is the refreshed headline: the hint
demonstrably drives instruction person-FP toward zero.

## Why the ARGUS_ABLATION_HINTS env hook is NOT the off/on axis

The research env hook (``ARGUS_ABLATION_HINTS``) is resolved Python-side
(``glue/redact._ablation_enabled_hints`` → ``pure/hints._apply_ablation``) and
applied to the hints AFTER ``_core.detect_l1`` has already run. In ``mode="fast"``
the L1b person detector and its ``text_intent`` threshold live entirely inside
the Rust core (``redact_l1::detect_l1`` → ``get_person_threshold``), computed from
the core's own hints — so the post-hoc Python ablation never reaches the person
threshold. The hook still governs L2/L3 NER gating and self-reference filtering,
but it does not change L1b person FP in fast mode. ``evaluate()`` records this
directly as ``env_toggle_check`` (toggling the env over the instruction fixture
leaves person FP unchanged), and the off/on suppression is therefore exercised
through the text framing — the signal the engine actually responds to.

    python tests/benchmark/hint_ablation.py \
        --output tests/benchmark/results/hint_ablation_0.7.16.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

_REPO_SRC = str(Path(__file__).resolve().parent.parent.parent / "src")
if _REPO_SRC not in sys.path:
    sys.path.insert(0, _REPO_SRC)

from argus_redact import redact  # noqa: E402

_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "instruction_ablation.json"

# Delimiters that terminate the leading command clause. Taking the body after the
# first one drops the command + self-reference, so the engine no longer classifies
# the text as text_intent="instruction".
_DELIMS = "：:，"


def _strip_instruction(text: str) -> str:
    """Return the non-instruction body (after the first command-clause delimiter)."""
    for i, ch in enumerate(text):
        if ch in _DELIMS:
            return text[i + 1 :].strip()
    return text


def _person_count(text: str, lang: str) -> int:
    """Number of ``person`` detections in ``redact(text, mode='fast')``.

    The fixture carries no real persons, so this is the person-FP count.
    """
    _redacted, _key, details = redact(text, mode="fast", lang=lang, detailed=True)
    return sum(1 for e in details["entities"] if e["type"] == "person")


def _per_sample(counts: list[int]) -> float:
    return round(sum(counts) / len(counts), 4) if counts else 0.0


def _set_env(value: str | None) -> None:
    if value is None:
        os.environ.pop("ARGUS_ABLATION_HINTS", None)
    else:
        os.environ["ARGUS_ABLATION_HINTS"] = value


def evaluate() -> dict:
    """Compute the text_intent person-FP ablation table over the fixture."""
    import argus_redact

    fixture = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    items = fixture["items"]

    # ── Headline axis: text_intent suppression on (instruction) vs off (plain). ──
    # Run with the env hook cleared so the measured difference is purely the
    # text-framing signal, not the (inert) research hook.
    _set_env(None)
    on_counts: dict[str, list[int]] = {"zh": [], "en": []}
    off_counts: dict[str, list[int]] = {"zh": [], "en": []}
    for it in items:
        lang, text = it["lang"], it["text"]
        on_counts.setdefault(lang, [])
        off_counts.setdefault(lang, [])
        on_counts[lang].append(_person_count(text, lang))
        off_counts[lang].append(_person_count(_strip_instruction(text), lang))

    all_on = [c for cs in on_counts.values() for c in cs]
    all_off = [c for cs in off_counts.values() for c in cs]
    off_ps = _per_sample(all_off)
    on_ps = _per_sample(all_on)

    by_lang = {
        lang: {
            "samples": len(on_counts[lang]),
            "off": _per_sample(off_counts[lang]),
            "on": _per_sample(on_counts[lang]),
        }
        for lang in sorted(on_counts)
        if on_counts[lang]
    }

    # ── env_toggle_check: confirm ARGUS_ABLATION_HINTS does NOT move person FP. ──
    # Same instruction texts, run as-is, env hook off vs on. Equal counts document
    # that the env ablation never reaches the Rust-internal L1b person threshold in
    # fast mode (see module docstring), so it cannot realize the "off" condition.
    _set_env("off")
    env_off = _per_sample([_person_count(it["text"], it["lang"]) for it in items])
    _set_env(None)
    env_on = _per_sample([_person_count(it["text"], it["lang"]) for it in items])

    return {
        "benchmark": "hint_ablation",
        "package_version": argus_redact.__version__,
        "hint": "text_intent",
        "mode": "fast",
        "fixture": _FIXTURE.name,
        "samples": len(items),
        "person_fp_per_sample": {
            "off": off_ps,
            "on": on_ps,
            "delta": round(off_ps - on_ps, 4),
        },
        "by_lang": by_lang,
        "env_toggle_check": {
            "description": (
                "ARGUS_ABLATION_HINTS over the instruction fixture, redact() as-is; "
                "off vs on are equal because the env hook is post-hoc Python and does "
                "not reach the Rust-internal L1b person threshold in fast mode."
            ),
            "fp_per_sample_off": env_off,
            "fp_per_sample_on": env_on,
            "changes_person_fp": env_off != env_on,
        },
        "note": (
            'text_intent="instruction" raises the L1b person threshold 0.8 → 1.2, '
            "suppressing name-shaped false positives in command/prompt text. off = "
            "plain (non-instruction) frame; on = instruction frame. The off magnitude "
            "reflects this fixture (one fireable token per sample, by construction); "
            "the reproduced shape is the suppression of instruction person-FP to ~0."
        ),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="text_intent person-FP ablation table.")
    ap.add_argument("--output", default=None)
    args = ap.parse_args()

    result = evaluate()
    if args.output:
        Path(args.output).write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        print(f"[wrote] {args.output}")

    fp = result["person_fp_per_sample"]
    print(f"\nperson_fp_per_sample ({result['samples']} samples, mode=fast):")
    print(f"  text_intent OFF (plain frame)       : {fp['off']:.4f}")
    print(f"  text_intent ON  (instruction frame) : {fp['on']:.4f}")
    print(f"  delta (off - on)                    : {fp['delta']:.4f}")
    print("\nby lang:")
    for lang, r in result["by_lang"].items():
        print(f"  {lang}: off={r['off']:.4f} on={r['on']:.4f} (n={r['samples']})")
    env = result["env_toggle_check"]
    print(
        f"\nenv_toggle_check: ARGUS_ABLATION_HINTS off={env['fp_per_sample_off']:.4f} "
        f"on={env['fp_per_sample_on']:.4f} changes_person_fp={env['changes_person_fp']}"
    )


if __name__ == "__main__":
    main()
