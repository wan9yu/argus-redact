"""Tests for PIITypeDef.to_patterns() — spec-derived patterns should match
the same inputs as hand-written patterns."""

from argus_redact.pure.patterns import match_patterns
from argus_redact.lang.zh.patterns import PATTERNS as ZH_HAND_WRITTEN
from argus_redact.lang.shared.patterns import PATTERNS as SHARED
from argus_redact.specs import list_types
from argus_redact.specs import zh as _zh  # noqa: F401

# Test inputs covering all types
TEST_INPUTS = [
    # phone
    "手机13812345678",
    "电话138 1234 5678",
    "号码138-1234-5678",
    # phone_landline
    "座机010-12345678",
    "0755-12345678",
    # id_number
    "身份证号110101199003074610",
    "证件号 110101 19900307 4610",
    "11010119900307002X",
    # bank_card
    "银行卡4111111111111111",
    "卡号6217001234567890",
    # passport
    "护照E12345678",
    # license_plate
    "车牌京A12345",
    "粤B·12345",
    # address
    "北京市朝阳区建国路100号",
    "广东省深圳市南山区科技路1号",
    "朝阳建国路100号",
    # person
    "客户张三的手机号",
    "联系人王小明",
    "赵敏女士已确认",
    # email (shared)
    "邮箱test@qq.com",
    # negative
    "今天天气不错",
    "版本号v2.0.1",
]


class TestToPatterns:
    def test_spec_patterns_should_exist(self):
        """Every zh spec should produce at least one pattern."""
        for typedef in list_types("zh"):
            patterns = typedef.to_patterns()
            assert len(patterns) >= 1, (
                f"{typedef.name} produced no patterns"
            )

    def test_spec_patterns_should_have_required_keys(self):
        """Each generated pattern dict must have type, label, pattern."""
        for typedef in list_types("zh"):
            for pat in typedef.to_patterns():
                assert "type" in pat
                assert "label" in pat
                assert "pattern" in pat
                assert pat["type"] == typedef.name or (
                    typedef.name == "phone_landline" and pat["type"] == "phone"
                )

    def test_spec_patterns_should_match_same_as_hand_written(self):
        """For every test input, spec-derived patterns should detect
        the same entity types as the hand-written patterns."""
        spec_patterns = []
        for typedef in list_types("zh"):
            spec_patterns.extend(typedef.to_patterns())

        for text in TEST_INPUTS:
            hand = {r.type for r in match_patterns(text, ZH_HAND_WRITTEN + SHARED)}
            spec = {r.type for r in match_patterns(text, spec_patterns + SHARED)}
            assert hand == spec, (
                f"Mismatch on '{text[:40]}...': "
                f"hand={hand} spec={spec}"
            )

    def test_build_patterns_replaces_hand_written(self):
        """build_patterns('zh') should be a drop-in replacement."""
        from argus_redact.specs.zh import build_patterns

        built = build_patterns()

        for text in TEST_INPUTS:
            hand = {(r.type, r.text) for r in match_patterns(text, ZH_HAND_WRITTEN)}
            spec = {(r.type, r.text) for r in match_patterns(text, built)}
            assert hand == spec, (
                f"Mismatch on '{text[:40]}...': "
                f"hand-only={hand - spec} spec-only={spec - hand}"
            )
