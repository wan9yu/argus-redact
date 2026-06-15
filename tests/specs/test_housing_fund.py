"""v0.6.12 — housing_fund (住房公积金账号).

No national format standard (varies by city) -> the type is anchor-required
with a generous digit run. The anchor must include 账号/账户, not bare "公积金",
so it does not match 公积金余额/amounts.
"""
from __future__ import annotations

import argus_redact.specs.zh as _zh  # noqa: F401  ensure registry loaded
from argus_redact import redact
from argus_redact.specs.registry import lookup


def test_type_registered():
    td = lookup("housing_fund")
    assert td, "housing_fund not registered"
    assert td[0].lang == "zh"
    assert td[0].strategy == "remove"
    # Financial-account tier (high), one below bank-card critical.
    assert td[0].sensitivity == 3


def test_examples_are_redacted():
    """Every spec example string: its PII payload must not survive verbatim."""
    td = lookup("housing_fund")[0]
    assert td.examples, "housing_fund has no examples"
    for ex in td.examples:
        out, _key = redact(ex, mode="fast", lang="zh")
        assert out != ex, f"housing_fund: example not redacted: {ex!r} -> {out!r}"


def test_counterexamples_do_not_fire():
    """Every spec counterexample: housing_fund must not claim the input."""
    td = lookup("housing_fund")[0]
    for cx in td.counterexamples:
        _out, _key, types = redact(cx, mode="fast", lang="zh", with_types=True)
        assert "housing_fund" not in set(types.values()), (
            f"housing_fund wrongly matched: {cx!r} -> types={types}"
        )


def test_payloads_disappear():
    cases = {
        "公积金账号：110123456789": "110123456789",
        "住房公积金账户 123456789012": "123456789012",
        "公积金账号 6001234567": "6001234567",
    }
    for text, payload in cases.items():
        out, _ = redact(text, mode="fast", lang="zh")
        assert payload not in out, f"housing_fund payload survived: {text!r} -> {out!r}"


def test_bare_digits_survive():
    """Anchor-required: a bare digit run with no keyword context must survive."""
    out, _ = redact("110123456789", mode="fast", lang="zh")
    assert out == "110123456789", f"bare digits wrongly redacted: {out!r}"


def test_anchor_requires_account_word_not_balance():
    """公积金余额/amounts must not match — anchor needs 账号/账户, not bare 公积金."""
    out, _ = redact("公积金余额12000", mode="fast", lang="zh")
    assert "12000" in out, f"housing_fund matched an amount, not an account: {out!r}"
