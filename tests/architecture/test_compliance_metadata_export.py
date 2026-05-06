"""Drift guards for v0.6.5 compliance metadata SSOT exports.

Catches the failure mode: a future contributor adds a new PII type but
forgets to set pipl_articles, leaking past the smoke test because risk
assessment still functions on default-empty articles.
"""
from __future__ import annotations

from argus_redact import (
    GDPR_SPECIAL_CATEGORIES,
    HIPAA_PHI_CATEGORIES,
    PIPL_REFERENCES,
)
from argus_redact.specs import list_types


def test_pipl_references_covers_every_registered_type():
    expected = {td.name for td in list_types()}
    assert set(PIPL_REFERENCES.keys()) == expected


def test_pipl_references_each_type_has_at_least_one_article():
    """Every PII type must cite at least one PIPL article — fail-loud
    on a contributor adding a new type without compliance metadata."""
    for name, articles in PIPL_REFERENCES.items():
        assert articles, f"PII type {name!r} has empty pipl_articles"
        for article in articles:
            assert article.startswith("PIPL Art."), (
                f"{name!r} has malformed PIPL article string: {article!r}"
            )


def test_pipl_references_values_are_tuple_of_str():
    for name, articles in PIPL_REFERENCES.items():
        assert isinstance(articles, tuple), (
            f"{name!r} PIPL articles is {type(articles).__name__}, expected tuple"
        )
        for art in articles:
            assert isinstance(art, str), f"{name!r} contains non-string: {art!r}"


def test_gdpr_special_categories_covers_every_registered_type():
    expected = {td.name for td in list_types()}
    assert set(GDPR_SPECIAL_CATEGORIES.keys()) == expected


def test_gdpr_special_categories_values_are_bool():
    for name, flag in GDPR_SPECIAL_CATEGORIES.items():
        assert isinstance(flag, bool), (
            f"{name!r} GDPR flag is {type(flag).__name__}, expected bool"
        )


def test_hipaa_phi_categories_covers_every_registered_type():
    expected = {td.name for td in list_types()}
    assert set(HIPAA_PHI_CATEGORIES.keys()) == expected


def test_hipaa_phi_categories_values_are_str_or_none():
    for name, category in HIPAA_PHI_CATEGORIES.items():
        assert category is None or isinstance(category, str), (
            f"{name!r} HIPAA category is {type(category).__name__}"
        )


def test_well_known_types_have_expected_classification():
    """Smoke check on classifier output for stability across releases."""
    # phone: base personal info under PIPL; not GDPR special; HIPAA phone identifier
    assert "PIPL Art.28" in PIPL_REFERENCES["phone"]
    assert GDPR_SPECIAL_CATEGORIES["phone"] is False
    assert HIPAA_PHI_CATEGORIES["phone"] == "phone_numbers"

    # medical: sensitive under PIPL Art.29; GDPR special category; HIPAA medical_record
    assert "PIPL Art.29" in PIPL_REFERENCES["medical"]
    assert GDPR_SPECIAL_CATEGORIES["medical"] is True
    assert HIPAA_PHI_CATEGORIES["medical"] == "medical_record"

    # self_reference: no HIPAA category (not a PHI identifier)
    assert HIPAA_PHI_CATEGORIES["self_reference"] is None
