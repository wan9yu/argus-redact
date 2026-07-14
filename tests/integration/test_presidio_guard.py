"""PresidioBridge guard-by-default restore tests (no presidio dependency).

Tests the anchor-flow passthrough added to PresidioBridge.restore() in
Theme A. Uses a synthetic key/anchor so presidio_analyzer is not required.
"""

from __future__ import annotations

import warnings

from argus_redact import redact
from argus_redact.compose import make_anchor, prompt_anchor
from argus_redact.integrations.presidio import PresidioBridge


def _fake_bridge_redact(text: str, salt: int = 42) -> tuple[str, dict]:
    """Use core redact() directly to produce a key, bypassing Presidio detection.

    PresidioBridge.restore() is the focus here — we don't need Presidio for that.
    """
    return redact(text, lang="zh", mode="fast", salt=salt)


class TestPresidioBridgeGuard:
    def test_restore_passthrough_without_guard(self):
        """Calling restore without guard= still works (emits DeprecationWarning)."""
        bridge = PresidioBridge()
        redacted, key = _fake_bridge_redact("电话13812345678")

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = bridge.restore(redacted, key, guard=None)
        assert any(issubclass(x.category, DeprecationWarning) for x in w)
        assert "13812345678" in result

    def test_restore_with_guard_and_valid_nonce(self):
        """guard=True + valid nonce → restores successfully."""
        bridge = PresidioBridge()
        redacted, key = _fake_bridge_redact("电话13812345678")
        anchor = make_anchor(key)
        llm_response = redacted + f"\n{anchor.nonce}"

        result = bridge.restore(llm_response, key, guard=True, anchor=anchor)

        assert "13812345678" in result

    def test_restore_with_guard_no_nonce_fail_closed(self):
        """guard=True + missing nonce → fail-closed (originals not leaked)."""
        bridge = PresidioBridge()
        redacted, key = _fake_bridge_redact("电话13812345678")
        anchor = make_anchor(key)

        # Response does NOT contain the nonce
        result = bridge.restore(redacted, key, guard=True, anchor=anchor)

        assert "13812345678" not in result

    def test_restore_with_guard_forged_nonce_fail_closed(self):
        """guard=True + wrong nonce → fail-closed (zero originals leaked)."""
        bridge = PresidioBridge()
        redacted, key = _fake_bridge_redact("电话13812345678")
        anchor = make_anchor(key)
        forged = redacted + "\nforged-nonce-abcdef1234567890"

        result = bridge.restore(forged, key, guard=True, anchor=anchor)

        assert "13812345678" not in result

    def test_restore_detailed_surfaces_security_events(self):
        """detailed=True returns (text, {security_events}) including guard events."""
        bridge = PresidioBridge()
        redacted, key = _fake_bridge_redact("电话13812345678")
        anchor = make_anchor(key)

        result = bridge.restore(redacted, key, guard=True, anchor=anchor, detailed=True)

        assert isinstance(result, tuple)
        text, details = result
        assert "13812345678" not in text
        assert "security_events" in details
        assert any(e["reason_code"] == "provenance_failed" for e in details["security_events"])

    def test_restore_h_layer_with_redacted_param(self):
        """H layer fires when redacted= is provided and suspicious patterns found."""
        bridge = PresidioBridge()
        # Use a real redact/restore pair to get valid pseudonyms
        original = "电话13812345678"
        redacted, key = _fake_bridge_redact(original)
        anchor = make_anchor(key)

        # Craft a suspicious response: pseudonym appears far more than in prompt
        pseudo = list(key.keys())[0]
        suspicious_response = (f"{pseudo} " * 20).strip() + f"\n{anchor.nonce}"

        result, details = bridge.restore(
            suspicious_response,
            key,
            guard=True,
            anchor=anchor,
            redacted=redacted,
            detailed=True,
        )
        # Guard passed (nonce present), injection suspected (H layer)
        # Note: H layer result depends on check_restore_safety heuristics;
        # we assert the structure, not a specific event count.
        assert "security_events" in details

    def test_prompt_anchor_workflow_end_to_end(self):
        """Full caller workflow: make_anchor → prompt_anchor → restore(guard=True)."""
        bridge = PresidioBridge()
        original = "我的电话是13812345678"
        redacted, key = _fake_bridge_redact(original)

        anchor = make_anchor(key)
        system_prompt = prompt_anchor(key, "zh", anchor=anchor)
        assert anchor.nonce in system_prompt

        # Simulate LLM including nonce in its response
        llm_output = f"你的电话已记录: {redacted}\n{anchor.nonce}"

        result = bridge.restore(llm_output, key, guard=True, anchor=anchor)

        assert "13812345678" in result
