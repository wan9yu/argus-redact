"""International (de/ja/ko/uk/in/br) ID types must carry full risk + compliance
metadata, not the bare default.

These types are detected + redacted from the core RON patterns, but were absent
from the compliance registry, so report=True understated them (sensitivity 2, no
PIPL/GDPR/HIPAA). specs/intl.py registers them; this pins the classification.
"""

from __future__ import annotations

import pytest

from argus_redact._core_loader import HAS_CORE
from argus_redact.specs import lookup

# name → (sensitivity, gdpr_special_category, hipaa_phi_category)
_EXPECTED = {
    "tax_id": (3, False, None),
    "my_number": (4, False, None),
    "rrn": (4, False, None),
    "nhs_number": (4, True, "medical_record"),  # health identifier
    "nino": (3, False, None),
    "postcode": (2, False, "geographic"),  # v0.8.10: postcode→geographic HIPAA (B)
    "aadhaar": (4, False, None),
    "pan": (3, False, None),
    "cpf": (4, False, None),
    "cnpj": (2, False, None),
}


@pytest.mark.parametrize("name,expected", _EXPECTED.items())
def test_intl_type_registered_with_compliance(name, expected):
    sens, gdpr, hipaa = expected
    tds = lookup(name)
    assert tds, f"{name} is not registered (specs/intl.py not loaded?)"
    td = tds[0]
    assert td.sensitivity == sens, f"{name} sensitivity {td.sensitivity} != {sens}"
    assert td.gdpr_special_category is gdpr, (
        f"{name} gdpr_special {td.gdpr_special_category} != {gdpr}"
    )
    assert td.hipaa_phi_category == hipaa, f"{name} hipaa {td.hipaa_phi_category!r} != {hipaa!r}"
    # PIPL articles are auto-derived and must be non-empty for any registered type
    # (the bug emitted no articles at all for these foreign IDs).
    assert td.pipl_articles, f"{name} has no PIPL articles"


@pytest.mark.skipif(not HAS_CORE, reason="Rust core not available")
def test_nhs_number_assess_risk_flags_health():
    # The one health identifier must surface GDPR Art.9 special category + a HIPAA
    # PHI category through assess_risk (the report path), keyed on its own lang.
    import argus_redact._core as _core

    _score, _level, _ents, _reasons, pipl, gdpr, hipaa, _gdpr_art10 = _core.assess_risk(
        [("nhs_number", 4)], "uk"
    )
    assert gdpr is True
    assert "medical_record" in hipaa
    assert pipl  # PIPL articles populated (was empty before registration)


@pytest.mark.skipif(not HAS_CORE, reason="Rust core not available")
def test_foreign_tax_id_no_longer_understated():
    # Regression: a German tax_id used to assess as sensitivity-2 with empty
    # compliance. It must now carry PIPL articles via the (de, tax_id) entry (and
    # the any-lang name fallback keeps it working under other langs).
    import argus_redact._core as _core

    _score, _level, _ents, _reasons, pipl, _gdpr, _hipaa, _gdpr_art10 = _core.assess_risk(
        [("tax_id", 3)], "de"
    )
    assert pipl, "de tax_id must carry PIPL articles after registration"
