# tests/security/test_obfuscation_recall.py
import pytest

from argus_redact import redact

PHONE = "13800138000"  # 11-digit zh mobile


def _hidden(text, lang="zh"):
    out, key = redact(text, lang=lang, mode="fast", salt=42)
    # detected iff the raw phone digits are NOT present verbatim and a key entry exists
    return (PHONE not in out) and len(key) > 0


@pytest.mark.parametrize(
    "text",
    [
        "请拨打 13800138000 咨询",  # plain (control)
        "请拨打 13⑧00138000 咨询",  # interior circled  -> fold catches
        "请拨打 13800138000¹ 咨询",  # trailing superscript -> keep-edge catches
        "请拨打 ¹13800138000 咨询",  # leading superscript  -> keep-edge catches
        "请拨打 13800138000͏2024",  # fusion via NEW ignorable -> keep-boundary catches
    ],
)
def test_zh_phone_detected_under_obfuscation(text):
    assert _hidden(text), f"phone leaked under obfuscation: {text!r}"


def test_cjk_homograph_digit_detected():
    # pre-existing CJK hole: 八 = 8
    assert _hidden("请拨打 13八00138000 咨询")
