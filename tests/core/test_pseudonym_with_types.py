"""Tests for PseudonymLLMResult.types — detection-time SSOT PII types (#009).

Twin of ``redact(with_types=True)`` (#003): ``redact_pseudonym_llm`` now exposes
the same canonical SSOT type names on ``result.types`` (fake -> type), covering
both the realistic downstream fakes and the ``[TYPE-NNNNN]`` audit placeholders.
"""

from argus_redact import redact
from argus_redact._types import PseudonymLLMResult
from argus_redact.glue.redact_pseudonym_llm import redact_pseudonym_llm
from argus_redact.streaming import StreamingRedactor

# zh+en fixture exercising a person (via names list, so it detects in fast mode),
# an email, a bank card, and BOTH passport variants (zh ``passport`` + en
# ``us_passport`` share the ``PASS-`` audit prefix — the collision case).
_TEXT = (
    "客户王建国的邮箱wang@example.com，银行卡6222021234567890123，"
    "护照E12345678，passport G12345678。"
)
_LANG = ["zh", "en"]
_MODE = "fast"
_NAMES = ["王建国"]
_SALT = b"test-salt"


def _run():
    return redact_pseudonym_llm(
        _TEXT,
        salt=_SALT,
        lang=_LANG,
        mode=_MODE,
        names=_NAMES,
        _polluted_input_ok=True,
    )


class TestPopulatedAndCanonical:
    def test_types_is_non_empty_dict(self):
        result = _run()
        assert isinstance(result.types, dict)
        assert result.types  # non-empty

    def test_values_are_canonical_ssot_names(self):
        values = set(_run().types.values())
        # Canonical names, NOT the audit-prefix reverse-parse garbage.
        assert "bank_card" in values  # not "cn_bank_card"
        assert "person" in values
        assert "email" in values
        assert "passport" in values
        # No garbled lowercased-prefix fragments leaked through.
        assert "o" not in values
        assert "cred" not in values
        assert "cn_bank_card" not in values


class TestParityWithRedactWithTypes:
    """#1657 AC-3 recurrence-guard: the two code paths must agree on the type set.

    Same input, same detector, same SSOT names -> identical set of PII types,
    with no audit-prefix path divergence.
    """

    def test_type_sets_match(self):
        pseudo_types = set(_run().types.values())

        _, _key, type_map = redact(
            _TEXT,
            lang=_LANG,
            mode=_MODE,
            salt=_SALT,
            names=_NAMES,
            with_types=True,
        )
        redact_types = set(type_map.values())

        assert pseudo_types == redact_types


class TestBothFakeSpacesTyped:
    def test_every_key_fake_is_typed(self):
        result = _run()
        # Every fake in the unified key (realistic fakes AND [TYPE-] audit
        # placeholders) corresponds to a detected entity and is typed.
        assert set(result.types) == set(result.key)

    def test_realistic_and_audit_fakes_both_present(self):
        result = _run()
        # A realistic email fake (e.g. user...@example.org) and an audit email
        # placeholder ([EMAI-...]) both map to "email".
        email_fakes = [f for f, t in result.types.items() if t == "email"]
        assert any("@" in f for f in email_fakes)  # realistic fake
        assert any(f.startswith("[EMAI-") for f in email_fakes)  # audit placeholder


class TestCollisionCase:
    """passport vs us_passport share the ``PASS-`` audit prefix.

    Prefix reverse-parsing fundamentally cannot tell them apart; ``result.types``
    carries ``e.type`` directly, so it distinguishes them.
    """

    def test_passport_variants_distinguished(self):
        result = _run()
        values = set(result.types.values())
        assert "passport" in values
        assert "us_passport" in values

        pass_prefixed = {f: t for f, t in result.types.items() if f.startswith("[PASS-")}
        # Two distinct audit placeholders, one per canonical type.
        assert set(pass_prefixed.values()) == {"passport", "us_passport"}


class TestStreaming:
    def test_chunks_carry_types_and_aggregate(self):
        r = StreamingRedactor(salt=_SALT, lang="zh", mode=_MODE)
        results = [
            r.feed("请拨打 13912345678 联系我。"),
            r.feed("身份证 110101199003077651 已核对。"),
        ]
        results.append(r.flush())

        for res in results:
            if res.downstream_text:  # non-empty emit
                assert isinstance(res.types, dict)

        agg = r.aggregate_types()
        assert isinstance(agg, dict)
        assert "phone" in agg.values()
        assert "id_number" in agg.values()
        # aggregate_types returns a copy, not the live backing dict.
        agg["__mutated__"] = "x"
        assert "__mutated__" not in r.aggregate_types()

    def test_empty_stream_has_empty_types(self):
        r = StreamingRedactor(salt=_SALT, lang="zh", mode=_MODE)
        result = r.flush()  # nothing fed
        assert result.downstream_text == ""
        assert result.types == {}


class TestNonBreaking:
    def test_construct_without_types_defaults_empty(self):
        # Existing consumers that build the result with only the old fields.
        result = PseudonymLLMResult(audit_text="a", downstream_text="b", display_text="c")
        assert result.types == {}
