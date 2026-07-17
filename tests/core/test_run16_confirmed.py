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
- F5 (v0.8.2): ``strategy_overrides`` validated the strategy VALUE but not the
  type KEY, so a miscased/unknown type name was silently dropped from the
  override — the profile's default strategy applied instead with no warning.
"""

import warnings

import pytest

from argus_redact import redact
from argus_redact.compose.anchor import Anchor
from argus_redact.exceptions import SecurityWarning
from argus_redact.glue.redact_pseudonym_llm import redact_pseudonym_llm
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


# --- F5 (v0.8.2) -----------------------------------------------------------
def test_strategy_overrides_unknown_type_key_raises():
    with pytest.raises(ValueError, match="Phone"):
        redact_pseudonym_llm("电话13800138000", salt=42, strategy_overrides={"Phone": "realistic"})


def test_strategy_overrides_valid_type_key_still_works():
    result = redact_pseudonym_llm(
        "电话13800138000", salt=42, strategy_overrides={"phone": "remove"}
    )
    assert "13800138000" not in result.downstream_text


# --- Task 4 follow-up: redact_pseudonym_llm's OWN _pre_detected branch ------
class TestPseudonymLLMPreDetectedMergeAndFilter:
    """``redact_pseudonym_llm`` has its own ``_pre_detected`` branch, separate
    from ``redact()``'s. Task 4 fixed the fail-open on the ``redact()`` side
    (caller-supplied entities skipped ``merge_entities`` and the
    types/types_exclude filter); this branch had the identical defect.
    """

    def test_overlapping_entities_merge_before_replace(self):
        """Two overlapping phone spans must be deduped (merged) before either
        replace pass. Detection ran once and both the realistic and audit
        passes consume the SAME merged entity list, so one merged entity
        yields exactly 2 key entries (1 realistic + 1 audit fake). Without
        the merge, the dead overlap duplicates this to 4 — a corrupt/unusable
        key, same failure mode as the redact() side."""
        from argus_redact._types import PatternMatch

        text = "call 13800138000 today"
        overlapping = [
            PatternMatch(
                text="13800138000", type="phone", start=5, end=16, confidence=0.9, layer=1
            ),
            PatternMatch(text="1380013800", type="phone", start=5, end=15, confidence=0.5, layer=1),
        ]

        result = redact_pseudonym_llm(text, salt=42, _pre_detected=overlapping)

        assert "13800138000" not in result.downstream_text
        assert "13800138000" not in result.audit_text
        assert len(result.key) == 2, f"expected merged overlap, got {result.key!r}"

    def test_types_exclude_unknown_type_rejected_on_pre_detected_branch(self):
        """The unknown-type-name guard must fire on this branch too —
        inherited via the shared ``_apply_type_filter`` helper, not skipped
        because detection was bypassed by ``_pre_detected``."""
        from argus_redact._types import PatternMatch

        text = "call 13800138000"
        entities = [PatternMatch(text="13800138000", type="phone", start=5, end=16)]

        with pytest.raises(ValueError, match="Phone"):
            redact_pseudonym_llm(text, salt=42, _pre_detected=entities, types_exclude=["Phone"])
