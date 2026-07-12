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


def test_nonce_echo_instruction_shape():
    """Pin the cross-module contract that D0's fix depends on.

    `pure.restore._strip_nonce` removes the token by the shape these instructions
    ask for: LAST in the reply, on its OWN LINE. Reword them without updating the
    stripper and the token silently rides back into the caller's plaintext — which
    is exactly the v0.7.19 D0 defect, and it regressed with zero test failures
    because nothing pinned the wording. This is that pin.
    """
    from argus_redact.compose.anchor import _NONCE_ECHO_EN, _NONCE_ECHO_ZH

    assert "own line" in _NONCE_ECHO_EN
    assert "End your reply with" in _NONCE_ECHO_EN
    assert "独立的一行" in _NONCE_ECHO_ZH
    assert "末尾" in _NONCE_ECHO_ZH
    # the token must be the final element of the instruction, so it lands last
    for template in (_NONCE_ECHO_EN, _NONCE_ECHO_ZH):
        assert template.rstrip().endswith("{nonce}")


def test_strip_nonce_round_trips_the_real_instruction():
    """End-to-end: build the reply the way prompt_anchor actually asks for it, and
    assert the guarded restore hands back clean plaintext. Guards against the two
    modules drifting apart."""
    from argus_redact import make_anchor, redact, restore
    from argus_redact.compose import prompt_anchor

    for lang in ("zh", "en"):
        original = "张三的电话是13912345678" if lang == "zh" else "Call John at 4155551234"
        redacted, key = redact(original, lang=lang, mode="fast")
        anchor = make_anchor(key)
        addendum = prompt_anchor(key, lang, anchor=anchor)
        assert anchor.nonce in addendum
        # an obedient model: answer, then the token last on its own line
        reply = redacted + "\n" + anchor.nonce
        out = restore(reply, key, guard=True, anchor=anchor)
        assert anchor.nonce not in out
        assert out == original
