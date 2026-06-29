"""A Chinese-digit homograph char before an ASCII PII value must NOT break detection."""

from argus_redact import redact


def test_name_then_phone_no_separator():
    out, key = redact("张三13800138000", lang="zh", mode="fast", salt=42)
    assert "13800138000" not in out  # phone redacted
    assert "张三" not in out  # name redacted (proximity restored)
    assert len(key) >= 2


def test_name_then_id_no_separator():
    out, _ = redact("李四110101199003074610", lang="zh", mode="fast", salt=42)
    assert "110101199003074610" not in out


def test_bare_cjk_digit_then_phone():
    out, _ = redact("三13800138000", lang="zh", mode="fast", salt=42)
    assert "13800138000" not in out


def test_contact_list_both_phones():
    out, _ = redact("张三13800138000，李四13900139000", lang="zh", mode="fast", salt=42)
    assert "13800138000" not in out and "13900139000" not in out


def test_genuine_chinese_digit_phone_still_folds():
    # All-CJK phone: majority CJK → still folds → still detected (no regression).
    out, key = redact("电话一三八零零一三八零零零", lang="zh", mode="fast", salt=42)
    assert "一三八零零一三八零零零" not in out
    assert len(key) >= 1
