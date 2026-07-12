"""v0.7.19 (D5) — the keep-downgrade SecurityWarning must not put raw PII in the log stream.

The warning fires exactly when a `keep` strategy is refused, i.e. when text the caller
believed would be preserved is about to be redacted — so `entity.text[:40]` is, by
construction, an un-redacted identifier (a full SSN, phone, or 18-digit ID).

Its sibling consumer of the same predicate, `keep_downgraded_event`, is PII-free by
construction (`detail="types: ..."`). This asserts the warning matches that bar, and
mirrors the discipline already enforced in tests/safety/test_layer3_log_scrub.py.
"""

from __future__ import annotations

import warnings

from argus_redact import redact
from argus_redact.pure.replacer import SecurityWarning

_SECRETS = {
    "bank_card": "4111111111111111",
    "phone": "13912345678",
}


def _capture_keep_warnings(text: str, pii_type: str) -> list[str]:
    """Force a keep-downgrade on a non-self_reference type and return the warning texts."""
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        redact(
            text,
            lang="zh",
            mode="fast",
            config={pii_type: {"strategy": "keep"}},
        )
    return [str(w.message) for w in caught if issubclass(w.category, SecurityWarning)]


def test_keep_downgrade_warning_fires():
    """Guard the guard: if this stops warning, the PII-free assertions below go vacuous."""
    msgs = _capture_keep_warnings(f"卡号{_SECRETS['bank_card']}", "bank_card")
    assert any("downgrad" in m for m in msgs), msgs


def test_keep_downgrade_warning_contains_no_raw_pii():
    for pii_type, secret in _SECRETS.items():
        msgs = _capture_keep_warnings(f"号码{secret}", pii_type)
        joined = " ".join(msgs)
        assert secret not in joined, f"{pii_type}: raw PII leaked into warning: {joined!r}"


def test_keep_downgrade_warning_still_names_the_type():
    """PII-free must not mean information-free — the operator still needs the type."""
    msgs = _capture_keep_warnings(f"卡号{_SECRETS['bank_card']}", "bank_card")
    assert any("bank_card" in m for m in msgs), msgs
