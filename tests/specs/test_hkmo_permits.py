"""v0.6.12 — the HK/Macao permit pair (eep + hrp).

- eep  往来港澳通行证 (mainland -> HK/Macao, 双程证)  — C-prefix
- hrp  港澳居民来往内地通行证 (HK/Macao -> mainland, 回乡证) — H/M-prefix

These are a DIRECTION-OPPOSITE pair. The prefix letter (C vs H/M) is the only
discriminator, so they are separate types with separate regexes — never merged
into one alternation. The cross-contamination assertions (C-input must not be
typed hrp; H/M-input must not be typed eep) are the most important locks here.

Both types are anchor-required: a bare format with no keyword context must
survive verbatim (no false positive).
"""
from __future__ import annotations

import pytest

import argus_redact.specs.zh as _zh  # noqa: F401  ensure registry loaded
from argus_redact import redact
from argus_redact.specs.registry import lookup


@pytest.mark.parametrize("type_name", ["eep", "hrp"])
def test_type_registered(type_name):
    td = lookup(type_name)
    assert td, f"{type_name} not registered"
    assert td[0].lang == "zh"
    assert td[0].strategy == "remove"


@pytest.mark.parametrize("type_name", ["eep", "hrp"])
def test_examples_are_redacted(type_name):
    """Every spec example string: its PII payload must not survive verbatim."""
    td = lookup(type_name)[0]
    assert td.examples, f"{type_name} has no examples"
    for ex in td.examples:
        out, _key = redact(ex, mode="fast", lang="zh")
        assert out != ex, f"{type_name}: example not redacted at all: {ex!r} -> {out!r}"


@pytest.mark.parametrize("type_name", ["eep", "hrp"])
def test_counterexamples_do_not_fire_this_type(type_name):
    """Every spec counterexample: THIS type must not claim the input.

    Repo convention (see assert_pattern_match): should_match=False is per-type.
    A cross-prefix counterexample (e.g. hrp's '往来港澳通行证C12345678') is a
    valid OTHER type — eep is *expected* to fire on it; only hrp must stay out.
    """
    td = lookup(type_name)[0]
    for cx in td.counterexamples:
        _out, _key, types = redact(cx, mode="fast", lang="zh", with_types=True)
        assert type_name not in set(types.values()), (
            f"{type_name}: counterexample wrongly matched by {type_name}: "
            f"{cx!r} -> types={types}"
        )


def test_eep_payloads_disappear():
    cases = {
        "往来港澳通行证C12345678": "C12345678",
        "电子往来港澳通行证CA0000001": "CA0000001",
        "港澳通行证号码：CB1234567": "CB1234567",
        "双程证 C87654321": "C87654321",
    }
    for text, payload in cases.items():
        out, _ = redact(text, mode="fast", lang="zh")
        assert payload not in out, f"eep payload survived: {text!r} -> {out!r}"


def test_hrp_payloads_disappear():
    cases = {
        "港澳居民来往内地通行证H12345678": "H12345678",
        "回乡证 M87654321": "M87654321",
        "回乡卡H1234567801": "H1234567801",
        "Home Return Permit H00000001": "H00000001",
    }
    for text, payload in cases.items():
        out, _ = redact(text, mode="fast", lang="zh")
        assert payload not in out, f"hrp payload survived: {text!r} -> {out!r}"


def test_bare_formats_survive():
    """Anchor-required: a bare C/H/M number with no keyword context must survive."""
    for bare in ("C12345678", "H12345678", "M87654321"):
        out, _ = redact(bare, mode="fast", lang="zh")
        assert out == bare, f"bare format wrongly redacted: {bare!r} -> {out!r}"


def test_distractor_prefix_is_suppressed():
    """check_context negative backstop: 订单号-prefixed C-number must survive."""
    out, _ = redact("订单号C12345678", mode="fast", lang="zh")
    assert "C12345678" in out, f"distractor-prefixed eep wrongly redacted: {out!r}"


def test_illegal_second_letter_does_not_match():
    """New-segment EEP excludes I/O in the second position."""
    for bad in ("往来港澳通行证CI1234567", "往来港澳通行证CO1234567"):
        out, _ = redact(bad, mode="fast", lang="zh")
        assert bad.endswith(out[-9:]) or out == bad, f"illegal I/O matched: {bad!r} -> {out!r}"
        assert out == bad, f"illegal-second-letter wrongly redacted: {bad!r} -> {out!r}"


# ── Cross-contamination — the C <-> H/M prefix is the ONLY discriminator ──
# These are the most important assertions: a C-prefix input must never be
# attributed to hrp, and an H/M-prefix input must never be attributed to eep.


def test_eep_does_not_fire_on_hrp_input():
    """回乡证 H-prefix payload must not be caught by the eep type."""
    _out, _key, types = redact("回乡证H12345678", mode="fast", lang="zh", with_types=True)
    assert "eep" not in set(types.values()), (
        f"eep fired on an H-prefix (hrp) input: types={types}"
    )


def test_hrp_does_not_fire_on_eep_input():
    """双程证 C-prefix payload must not be caught by the hrp type."""
    _out, _key, types = redact("往来港澳通行证C12345678", mode="fast", lang="zh", with_types=True)
    assert "hrp" not in set(types.values()), (
        f"hrp fired on a C-prefix (eep) input: types={types}"
    )


def test_eep_input_is_typed_eep_not_hrp():
    _out, _k, types = redact("往来港澳通行证C12345678", mode="fast", lang="zh", with_types=True)
    assigned = set(types.values())
    assert "eep" in assigned, f"eep did not fire on its own input: types={types}"
    assert "hrp" not in assigned, f"hrp contaminated an eep input: types={types}"


def test_hrp_input_is_typed_hrp_not_eep():
    _out, _k, types = redact("回乡证H12345678", mode="fast", lang="zh", with_types=True)
    assigned = set(types.values())
    assert "hrp" in assigned, f"hrp did not fire on its own input: types={types}"
    assert "eep" not in assigned, f"eep contaminated an hrp input: types={types}"
