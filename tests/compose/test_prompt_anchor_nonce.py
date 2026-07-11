"""compose.prompt_anchor with anchor param — nonce-echo guard tests."""

from __future__ import annotations

from argus_redact.compose import make_anchor, prompt_anchor


def test_prompt_anchor_embeds_nonce_when_anchor_given():
    key = {"P-001": "张三"}
    a = make_anchor(key)
    out = prompt_anchor(key, lang="en", anchor=a)
    assert a.nonce in out  # nonce present for the LLM to echo


def test_prompt_anchor_backward_compatible_without_anchor():
    key = {"P-001": "张三"}
    assert "P-001" in prompt_anchor(key, lang="en")  # today's behavior unchanged
