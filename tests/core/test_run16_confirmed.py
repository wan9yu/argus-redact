"""Run-16 confirmed defects (v0.8.1).

- V6AGA: an unknown or mis-cased type name in ``types=`` / ``types_exclude=``
  silently filtered out every real entity and returned success with nothing
  redacted — a fail-open leak (the R3 fix guarded the container type, not the
  names in it). Unknown names now raise.
- D50YP: the PARTIAL restore warning asserted "in-scope pseudonyms WERE
  substituted" even when none were present — a message that claims more than the
  PARTIAL outcome (out-of-scope withheld) actually witnessed.
- QQZJG: on v0.8.0 the guard=None DeprecationWarning still read "will default to
  guard=True in v0.8.0" — future tense for a flip that already shipped.
"""

import warnings

import pytest

from argus_redact import redact
from argus_redact.compose.anchor import Anchor
from argus_redact.exceptions import SecurityWarning
from argus_redact.pure.restore import restore


# --- V6AGA ---------------------------------------------------------------
def test_unknown_type_name_raises():
    with pytest.raises(ValueError, match="telephone"):
        redact("电话13800138000", types=["telephone"])


def test_miscased_type_name_raises():
    # "Phone" is not the SSOT name "phone"; silently redacting nothing is fail-open.
    with pytest.raises(ValueError, match="Phone"):
        redact("电话13800138000", types=["Phone"])


def test_unknown_types_exclude_name_raises():
    with pytest.raises(ValueError, match="fone"):
        redact("电话13800138000", types_exclude=["fone"])


def test_valid_type_names_still_work():
    out, key = redact("电话13800138000", types=["phone"])
    assert "13800138000" not in out  # correctly redacted
    # a valid subset that happens to match nothing is fine (no raise)
    out2, _ = redact("电话13800138000", types=["email"])
    assert out2 == "电话13800138000"  # email not present, nothing redacted, no error


# --- D50YP ---------------------------------------------------------------
def test_partial_warning_does_not_claim_in_scope_substitution_when_none():
    red, key = redact("张三的电话是13800138000，李四的邮箱abc@x.com", lang="zh", mode="fast")
    items = list(key.items())
    in_scope = items[0][0]  # in scope, NOT present in the text below
    out_ps = items[1][0]  # out of scope, present
    nonce = "a1b2c3d4e5f6a7b8"  # 16 chars, a plausible provenance token
    anchor = Anchor(nonce=nonce, scope=frozenset({in_scope}))
    text = f"only {out_ps} appears here\n{nonce}"
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        restore(text, key, guard=True, anchor=anchor)
    msg = " | ".join(str(x.message) for x in w if issubclass(x.category, SecurityWarning))
    assert "PARTIAL" in msg
    # Must NOT assert in-scope substitution happened (none were present here).
    assert "WERE substituted" not in msg
    assert "withheld" in msg  # the witnessed fact


# --- QQZJG ---------------------------------------------------------------
def test_deprecation_warning_not_future_tense_for_shipped_flip():
    red, key = redact("张三的电话是13800138000", lang="zh", mode="fast")
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        restore(red, key, guard=None)
    dep = " | ".join(str(x.message) for x in w if issubclass(x.category, DeprecationWarning))
    assert "will default to guard=True in v0.8.0" not in dep  # the stale future-tense line
    assert "guard=None" in dep or "guard=False" in dep  # names the real choice
