"""A Chinese-digit homograph char before an ASCII PII value must NOT break detection."""

from argus_redact import redact


def test_redact_should_redact_name_and_phone_when_no_separator():
    out, key = redact("张三13800138000", lang="zh", mode="fast", salt=42)
    assert "13800138000" not in out  # phone redacted
    assert "张三" not in out  # name redacted (proximity restored)
    assert len(key) >= 2


def test_redact_should_redact_id_when_name_has_no_separator():
    out, _ = redact("李四110101199003074610", lang="zh", mode="fast", salt=42)
    assert "110101199003074610" not in out


def test_redact_should_redact_phone_when_preceded_by_bare_cjk_digit():
    out, _ = redact("三13800138000", lang="zh", mode="fast", salt=42)
    assert "13800138000" not in out


def test_redact_should_redact_both_phones_when_two_contacts_are_listed():
    out, _ = redact("张三13800138000，李四13900139000", lang="zh", mode="fast", salt=42)
    assert "13800138000" not in out and "13900139000" not in out


def test_redact_should_redact_phone_when_digits_are_entirely_cjk():
    # All-CJK phone: majority CJK → still folds → still detected (no regression).
    out, key = redact("电话一三八零零一三八零零零", lang="zh", mode="fast", salt=42)
    assert "一三八零零一三八零零零" not in out
    assert len(key) >= 1
