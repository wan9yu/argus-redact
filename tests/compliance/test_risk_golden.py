"""Frozen golden for assess_risk — locks RiskResult bit-for-bit across the port.

Captured against the pre-port Python implementation. After assess_risk moves to
Rust the SAME assertions must hold unchanged. Vectors deliberately include level
cutoff boundaries (0.6 → high, 0.85 → critical) and a registry-absent type (the
typedef-None skip path) so any rounding / lookup / ordering drift is caught.
"""

from __future__ import annotations

from argus_redact.pure.risk import assess_risk


def _astuple(r):
    return (
        r.score,
        r.level,
        tuple((e["type"], e["sensitivity"]) for e in r.entities),
        r.reasons,
        r.pipl_articles,
        r.gdpr_special_category,
        r.hipaa_categories,
    )


def test_empty_entities():
    r = assess_risk([])
    assert _astuple(r) == (0.0, "none", (), (), (), False, ())


def test_single_low():
    r = assess_risk([{"type": "ip_address", "sensitivity": 1}])
    assert r.score == 0.25
    assert r.level == "low"
    assert r.entities == ({"type": "ip_address", "sensitivity": 1},)


def test_single_critical_id_number():
    r = assess_risk([{"type": "id_number", "sensitivity": 4}])
    assert r.score == 1.0
    assert r.level == "critical"
    assert "PIPL Art.13" in r.pipl_articles
    assert "PIPL Art.51" in r.pipl_articles


def test_multi_high_critical_amplifies():
    # two sensitivity>=3 entities → +0.1; base 0.75 → 0.85 → critical (cutoff edge)
    r = assess_risk(
        [
            {"type": "phone", "sensitivity": 3},
            {"type": "bank_card", "sensitivity": 3},
        ]
    )
    assert r.score == 0.85
    assert r.level == "critical"
    assert "multiple high/critical entities detected" in r.reasons


def test_self_reference_amplification():
    # self_reference + sensitive → +0.15
    r = assess_risk(
        [
            {"type": "self_reference", "sensitivity": 1},
            {"type": "medical", "sensitivity": 4},
        ]
    )
    assert "self-reference amplification: PII directly linked to user" in r.reasons
    assert r.gdpr_special_category is True


def test_quasi_id_combo_single_bonus():
    # date_of_birth+address+phone matches all three quasi-id combos but the break yields +0.1 once
    r = assess_risk(
        [
            {"type": "date_of_birth", "sensitivity": 2},
            {"type": "address", "sensitivity": 2},
            {"type": "phone", "sensitivity": 3},
        ]
    )
    combo_reasons = [x for x in r.reasons if x.startswith("quasi-identifier combination")]
    assert len(combo_reasons) == 1


def test_cardinality_triggers_art55():
    r = assess_risk(
        [
            {"type": "phone", "sensitivity": 3},
            {"type": "email", "sensitivity": 2},
            {"type": "name", "sensitivity": 2},
        ]
    )
    assert "PIPL Art.55" in r.pipl_articles


def test_unregistered_type_skips_compliance():
    # arbitrary type name not in the registry → typedef None → no compliance, but
    # cardinality<3 so no Art.55; score still computed from sensitivity.
    r = assess_risk([{"type": "totally_made_up", "sensitivity": 2}])
    assert r.score == 0.5
    assert r.level == "medium"
    assert r.pipl_articles == ()


def test_level_cutoff_high_no_amplification():
    r = assess_risk(
        [
            {"type": "phone", "sensitivity": 3},
            {"type": "email", "sensitivity": 2},
        ]
    )
    # base 0.75 (max sens 3) → no amplification (only one >=3) → 0.75 → high
    assert r.score == 0.75
    assert r.level == "high"


def test_level_cutoff_06_is_high():
    # base 0.5 (max sens 2) + 0.1 quasi-id combo {date_of_birth, address} = 0.6;
    # 0.6 is NOT < 0.6, so it maps to "high" (locks the medium/high cutoff edge).
    r = assess_risk(
        [
            {"type": "date_of_birth", "sensitivity": 2},
            {"type": "address", "sensitivity": 2},
        ]
    )
    assert r.score == 0.6
    assert r.level == "high"
