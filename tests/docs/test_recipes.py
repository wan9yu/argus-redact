"""Executable spec for the compose recipes under docs/recipes/.

The recipes used to end on a bare ``restore(text, key)``, which since v0.8.0 fails
closed without an anchor — the documented round-trip would restore nothing. Each test
below runs the FIXED recipe flow offline (``mode="fast"``, no network/LLM) with a
simulated model reply, and asserts the originals really come back. If a recipe drifts
back to an unguarded ``restore`` (or the guard flow changes), the matching test breaks.

Offline contract: no NER model, no Ollama, no LLM call. The "model reply" is a plain
string that mimics a well-behaved LLM which preserved the placeholders and echoed the
anchor nonce, exactly as ``prompt_anchor(..., anchor=...)`` instructs it to.
"""

from __future__ import annotations

import warnings

import pytest

from argus_redact import redact, restore
from argus_redact.compose import (
    PatternMatch,
    PIITypeDef,
    expand_aliases,
    guarded_restore,
    make_anchor,
    prompt_anchor,
    register_pii_type,
)
from argus_redact.exceptions import SecurityWarning
from argus_redact.specs.registry import unregister


@pytest.fixture(autouse=True)
def _quiet_low_entropy_salt():
    # The recipes use salt=42 for a readable example; that trips the low-entropy
    # SecurityWarning. Silence it here so the flow assertions stay the signal.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SecurityWarning)
        yield


def test_compose_prompt_anchor_recipe_round_trips():
    """docs/recipes/compose-prompt-anchor.md — Usage block."""
    text = "张三的电话13812345678"
    redacted, key = redact(text, names=["张三"], lang="zh", salt=42)

    anchor_obj = make_anchor(key)
    anchor = prompt_anchor(key, lang="zh", anchor=anchor_obj)
    assert anchor_obj.nonce in anchor  # the addendum asks the model to echo the nonce

    # A well-behaved model preserved the placeholders and echoed the nonce.
    llm_output = redacted + "\n" + anchor_obj.nonce
    restored = guarded_restore(llm_output, key, anchor=anchor_obj)

    assert restored == text
    assert anchor_obj.nonce not in restored  # nonce stripped on a clean pass


def test_compose_prompt_anchor_recipe_fails_closed_without_the_nonce():
    """The guard the recipe now uses actually bites: a reply that dropped the nonce
    restores nothing (provenance failure), rather than silently substituting."""
    text = "张三的电话13812345678"
    redacted, key = redact(text, names=["张三"], lang="zh", salt=42)
    anchor_obj = make_anchor(key)

    tampered = redacted  # no nonce echoed
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SecurityWarning)
        out = guarded_restore(tampered, key, anchor=anchor_obj)
    assert "13812345678" not in out  # fail-closed: original not reinserted


def test_compose_expand_aliases_recipe_restores_a_retitled_name():
    """docs/recipes/compose-expand-aliases.md — Usage block."""
    text = "黄芳的电话13912345678"
    redacted, key = redact(text, names=["黄芳"], lang="zh", salt=42)

    expanded = expand_aliases(key, lang="zh")
    assert "黄先生" in expanded  # surname+title alias added
    anchor_obj = make_anchor(expanded)  # scope must cover the alias entries

    # Model retitled 黄芳 -> 黄先生 and echoed the nonce.
    phone_code = next(p for p, o in key.items() if o == "13912345678")
    llm_output = f"你好黄先生，请确认 {phone_code} 这个号码\n{anchor_obj.nonce}"
    restored = guarded_restore(llm_output, expanded, anchor=anchor_obj)

    assert "黄芳" in restored  # the retitle mapped back
    assert "13912345678" in restored
    assert anchor_obj.nonce not in restored


def test_writing_an_adapter_recipe_round_trips():
    """docs/recipes/writing-an-adapter.md — the _pre_detected + guarded_restore flow."""
    register_pii_type(
        PIITypeDef(
            name="employee_id",
            lang="en",
            format="EMP-NNNNNN",
            strategy="pseudonym",
            sensitivity=2,
        )
    )
    try:
        text = "Ping EMP-123456 about the ticket"
        matches = [PatternMatch(type="employee_id", text="EMP-123456", start=5, end=15)]
        redacted, key = redact(text, lang="en", salt=42, _pre_detected=matches)
        assert "EMP-123456" not in redacted  # detected + redacted

        expanded = expand_aliases(key, lang="en")
        anchor_obj = make_anchor(expanded)
        anchor = prompt_anchor(key, lang="en", anchor=anchor_obj)
        assert anchor_obj.nonce in anchor

        llm_output = redacted + "\n" + anchor_obj.nonce
        restored = guarded_restore(llm_output, expanded, anchor=anchor_obj)
        assert "EMP-123456" in restored  # original recovered through the guard
    finally:
        # Don't leak the demo type into the global registry — a lingering entry
        # bumps list_types() and would RED the type-count gates under the full suite.
        unregister("en", "employee_id")


def test_local_cli_proxy_recipe_uses_the_guard_false_optout():
    """docs/recipes/local-cli-proxy.py — the streaming/per-chunk proxy has no
    per-exchange anchor, so it restores with guard=False (the documented opt-out).
    A bare guard=True restore with no anchor would fail closed and leave the chunk
    un-restored, which is exactly why the recipe opts out."""
    text = "张三的电话13812345678"
    redacted, key = redact(text, names=["张三"], lang="zh", salt=42)

    # What the proxy does per chunk:
    plain = restore(redacted, key, guard=False)
    assert plain == text

    # Why it must opt out: guard=True (the default) with no anchor fails closed.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SecurityWarning)
        guarded = restore(redacted, key)  # no anchor
    assert "13812345678" not in guarded
