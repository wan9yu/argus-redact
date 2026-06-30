"""Structural + non-vacuous guard for the text_intent person-FP ablation (§9.8).

Pins the refreshed headline: the ``text_intent`` hint drives instruction person-FP
toward zero, and the fixture actually produces person false positives when the
suppression is off (so the result is not vacuously true). Pure argus (fast mode) —
no NER/LLM, runs on the default ``pytest`` selection.
"""

import os
import sys
from pathlib import Path

_BENCH = Path(__file__).resolve().parent
if str(_BENCH) not in sys.path:
    sys.path.insert(0, str(_BENCH))

import hint_ablation as ha  # noqa: E402


def _evaluate():
    """Run evaluate() and restore the env hook it toggles."""
    try:
        return ha.evaluate()
    finally:
        os.environ.pop("ARGUS_ABLATION_HINTS", None)


def test_result_is_wellformed():
    res = _evaluate()
    assert res["benchmark"] == "hint_ablation"
    assert res["hint"] == "text_intent"
    assert res["mode"] == "fast"
    assert res["samples"] == 40
    fp = res["person_fp_per_sample"]
    assert set(fp) == {"off", "on", "delta"}
    assert set(res["by_lang"]) == {"zh", "en"}


def test_hint_reduces_person_fp_non_vacuously():
    res = _evaluate()
    fp = res["person_fp_per_sample"]
    # Non-vacuity: the fixture MUST produce person FPs with suppression off — else
    # the suppression below would be vacuously satisfied.
    assert fp["off"] > 0.0, fp
    # The hint demonstrably reduces FPs: off (plain frame) > on (instruction frame).
    assert fp["off"] > fp["on"], fp
    assert fp["delta"] == round(fp["off"] - fp["on"], 4)
    # Suppression on instruction text drives person-FP to ~0.
    assert fp["on"] == 0.0, fp


def test_both_languages_show_suppression():
    res = _evaluate()
    for lang, r in res["by_lang"].items():
        assert r["off"] > r["on"], (lang, r)
        assert r["off"] > 0.0, (lang, r)


def test_env_toggle_does_not_reach_l1b_person_in_fast_mode():
    # Records the v0.7.16 architecture: ARGUS_ABLATION_HINTS is applied Python-side
    # AFTER _core.detect_l1, so it never reaches the Rust-internal L1b person
    # threshold in fast mode. The off/on suppression above is therefore exercised
    # through the text framing, not this env hook. If the hook is ever plumbed into
    # the Rust threshold, this assertion flips and the module docstring needs an
    # update.
    res = _evaluate()
    env = res["env_toggle_check"]
    assert env["changes_person_fp"] is False, env
    assert env["fp_per_sample_off"] == env["fp_per_sample_on"], env
