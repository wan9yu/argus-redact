"""redact(report=True) must resolve the score tier and the PIPL/GDPR/HIPAA
articles from ONE language entry.

The report scores each entity from a sensitivity, while assess_risk resolves
the article set via the Rust ``compliance_for(effective_lang, type)`` — exact
effective-lang match, else first-registered. When the score sensitivity was
read from the first-registered (zh) typedef instead, the two disagreed for
every zh+en type: an EN report scored ``person``/``phone`` high/critical while
classifying ordinary PII, and inverted ``date_of_birth`` the other way.

These tests anchor the report sensitivity on the effective-lang REGISTRY
typedef (``ComplianceMeta`` carries no sensitivity field, so the registry
typedef is the only stable anchor) and pin the two directional score crossings.
"""

import warnings

import pytest

from argus_redact import redact
from argus_redact._types import PatternMatch
from argus_redact.specs import get, lookup


def _sensitivity_for(report, type_name):
    """The sensitivity the report fed the risk model for ``type_name``."""
    return next(
        (e["sensitivity"] for e in report.risk.entities if e["type"] == type_name),
        None,
    )


# (type, en-text that triggers it in fast mode, names= override for NER-only types)
# Each type has genuinely different zh vs en sensitivity — the divergence the
# fix closes. self_reference detection emits a strategy='keep' downgrade
# SecurityWarning that is irrelevant here.
_DIVERGING_EN_FIXTURES = [
    ("person", "John Smith called", ["John Smith"]),
    ("phone", "Call at (415) 555-1234", None),
    ("date_of_birth", "DOB: 01/15/1990", None),
    ("religion", "practising Catholic", None),
    ("political", "a registered Democrat", None),
    ("self_reference", "my mother", None),
]


class TestReportSensitivityIsEffectiveLang:
    @pytest.mark.parametrize("type_name,text,names", _DIVERGING_EN_FIXTURES)
    def test_en_report_uses_en_typedef_sensitivity_not_zh(self, type_name, text, names):
        en_sens = get("en", type_name).sensitivity
        zh_sens = get("zh", type_name).sensitivity
        # Fixture guard: a non-diverging type would make this test vacuous.
        assert en_sens != zh_sens, f"{type_name} no longer diverges zh vs en"

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            report = redact(text, lang="en", mode="fast", names=names, report=True)

        got = _sensitivity_for(report, type_name)
        assert got is not None, f"{type_name} was not detected in {text!r}"
        assert got == en_sens, f"{type_name}: report used {got}, en typedef is {en_sens}"
        assert got != zh_sens

    @pytest.mark.parametrize(
        "type_name,text,names",
        [("person", "张伟 说", ["张伟"]), ("date_of_birth", "出生日期1990-01-15", None)],
    )
    def test_zh_report_uses_zh_typedef_sensitivity(self, type_name, text, names):
        # The other side of the same rule: an exact zh match keeps the zh value.
        zh_sens = get("zh", type_name).sensitivity
        report = redact(text, lang="zh", mode="fast", names=names, report=True)
        assert _sensitivity_for(report, type_name) == zh_sens

    def test_zh_only_type_under_en_falls_back_to_first_registered(self):
        # id_number is registered only for zh (langs[0]-absent for lang='en').
        # compliance_for('en', 'id_number') falls back to the first-registered
        # (zh) entry; the report sensitivity must fall back the same way.
        expected = lookup("id_number")[0].sensitivity
        report = redact("ID 110101199003074610", lang="en", mode="fast", report=True)
        assert _sensitivity_for(report, "id_number") == expected

    def test_intl_only_type_under_en_falls_back_to_first_registered(self):
        # aadhaar is registered only for 'in' and does not detect under 'en';
        # inject it so the report-build fallback for an intl-only type is
        # exercised directly. Its sensitivity must be the first-registered one.
        expected = lookup("aadhaar")[0].sensitivity
        text = "num 234567890123 here"
        pm = PatternMatch(
            text="234567890123", type="aadhaar", start=4, end=16, confidence=1.0, layer=1
        )
        report = redact(text, lang="en", mode="fast", report=True, _pre_detected=[pm])
        assert _sensitivity_for(report, "aadhaar") == expected

    def test_register_pii_type_absent_from_ron_still_scores(self):
        # A runtime-registered type is absent from risk_data.ron, so
        # compliance_for returns None for it. The report must still score it off
        # its registered sensitivity via the first-registered fallback.
        from argus_redact.compose import PIITypeDef, register_pii_type
        from argus_redact.specs.registry import unregister

        register_pii_type(
            PIITypeDef(name="custom_badge", lang="en", format="BADGE-N", sensitivity=3)
        )
        try:
            pm = PatternMatch(
                text="XYZ", type="custom_badge", start=6, end=9, confidence=1.0, layer=1
            )
            report = redact(
                "badge XYZ here", lang="en", mode="fast", report=True, _pre_detected=[pm]
            )
            assert _sensitivity_for(report, "custom_badge") == 3
        finally:
            unregister("en", "custom_badge")


class TestReportRiskDirectional:
    def test_en_person_plus_phone_is_not_critical(self):
        # zh person+phone are both sensitivity 3 → two high entities →
        # critical(0.85). en person+phone are both sensitivity 2, so the EN
        # report must NOT land in the critical(0.85) tier.
        report = redact(
            "John Smith at (415) 555-1234",
            lang="en",
            mode="fast",
            names=["John Smith"],
            report=True,
        )
        present = {e["type"] for e in report.risk.entities}
        assert {"person", "phone"} <= present
        assert report.risk.level != "critical"
        assert report.risk.score < 0.85

    def test_en_date_of_birth_is_high_not_zh_deflated_medium(self):
        # en date_of_birth is sensitivity 3 → high(0.75). Reading the zh typedef
        # (sensitivity 2) deflated it to medium(0.5).
        report = redact("DOB: 01/15/1990", lang="en", mode="fast", report=True)
        assert report.risk.level == "high"
        assert report.risk.score == 0.75


class TestEmptyLangGuard:
    def test_empty_lang_list_report_raises_valueerror_not_indexerror(self):
        # Before the central guard this raised IndexError at the report's
        # lang[0] (an HTTP 500 over the wire) — now a clean ValueError.
        with pytest.raises(ValueError, match="No language specified"):
            redact("张伟手机13812345678", lang=[], mode="fast", report=True)

    def test_empty_lang_list_default_raises_valueerror(self):
        with pytest.raises(ValueError, match="No language specified"):
            redact("张伟手机13812345678", lang=[], mode="fast")

    def test_empty_lang_pre_detected_report_raises_valueerror(self):
        # The _pre_detected branch skips _detect, so it must carry its own guard.
        pm = PatternMatch(text="XYZ", type="phone", start=0, end=3, confidence=1.0, layer=1)
        with pytest.raises(ValueError, match="No language specified"):
            redact("XYZ here", lang=[], mode="fast", report=True, _pre_detected=[pm])

    def test_empty_lang_does_not_fail_open(self):
        # Fail-open would silently return an under-redacted result (no language
        # pattern pack loaded). Rejecting the call is the non-fail-open outcome.
        with pytest.raises(ValueError):
            redact("张伟手机13812345678", lang=[], mode="fast")
