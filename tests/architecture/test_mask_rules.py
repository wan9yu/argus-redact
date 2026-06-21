"""Tests for enterprise mask rules — configurable per-type masking."""

import argus_redact._core as _core
from argus_redact import redact


class TestBankCardMask:
    def test_should_show_first6_last4_by_default(self):
        config = {"bank_card": {"strategy": "mask", "visible_prefix": 6, "visible_suffix": 4}}

        _, key = redact("卡号4111111111111111", salt=42, mode="fast", config=config)

        replacement = list(key.keys())[0]
        assert replacement.startswith("411111")
        assert replacement.endswith("1111")
        assert "*" in replacement


class TestChineseNameMask:
    def test_should_mask_2char_name(self):
        assert _core.mask_name("张三") == "张*"

    def test_should_mask_3char_name(self):
        assert _core.mask_name("李小明") == "李**"

    def test_should_mask_4char_name_show_first2(self):
        assert _core.mask_name("欧阳小明") == "欧阳**"

    def test_should_mask_5char_name_show_first2(self):
        assert _core.mask_name("爱新觉罗弘") == "爱新***"


class TestEmailMask:
    def test_should_show_first_char_and_domain(self):
        _, key = redact("邮箱test@qq.com", salt=42, mode="fast")

        replacement = list(key.keys())[0]
        assert replacement.startswith("t")
        assert "@qq.com" in replacement
        assert "*" in replacement


class TestLandlineMask:
    def test_should_keep_area_code_and_last3(self):
        assert _core.mask_landline("0755-12345678") == "0755-*****678"
        assert _core.mask_landline("010-12345678") == "010-*****678"

    def test_should_handle_no_dash(self):
        assert _core.mask_landline("075512345678") == "0755*****678"


class TestIdNumberMask:
    def test_should_show_first4_last4(self):
        config = {"id_number": {"strategy": "mask", "visible_prefix": 4, "visible_suffix": 4}}

        _, key = redact("身份证110101199003074610", salt=42, mode="fast", config=config)

        replacement = list(key.keys())[0]
        assert replacement.startswith("1101")
        assert replacement.endswith("4610")
        assert "*" in replacement


class TestMaskVisibleCoercion:
    """`visible_prefix`/`visible_suffix` from config must int-coerce like Python.

    Pre-port `_build_type_info` ran `int(ec.get('visible_prefix', 0) or 0)`, so a
    numeric string ('5') or a float (2.7 → 2) carried through (config from
    json.loads / yaml.safe_load arrives with these). The c872064 port's
    `extract::<usize>().ok()` dropped any non-integer to None → 0 → the per-type
    mask default, REVEALING MORE digits for bank_card (a privacy regression).
    These assert the pre-port byte-identical mask output.
    """

    def test_numeric_string_visible_values(self):
        config = {"phone": {"strategy": "mask", "visible_prefix": "5", "visible_suffix": "2"}}
        out, _ = redact("Call 13800138000", salt=5, mode="fast", lang=["zh"], config=config)
        # Pre-port: int('5')=5, int('2')=2 → 13800****00 (not the 3+4 default).
        assert out == "Call 13800****00", f"numeric-string coercion failed: {out!r}"

    def test_float_visible_values_truncate(self):
        config = {"phone": {"strategy": "mask", "visible_prefix": 2.7, "visible_suffix": 3.9}}
        out, _ = redact("Call 13800138000", salt=5, mode="fast", lang=["zh"], config=config)
        # Pre-port: int(2.7)=2, int(3.9)=3 → 13******000.
        assert out == "Call 13******000", f"float truncation failed: {out!r}"

    def test_negative_visible_values_clamp_to_default(self):
        # Python `int(ec.get(..,0) or 0)` keeps -1, but the negative falls
        # through to the per-type mask default downstream (len <= p+s guard /
        # default branch). Pre-port output: the 3+4 phone default.
        config = {"phone": {"strategy": "mask", "visible_prefix": -1, "visible_suffix": -1}}
        out, _ = redact("Call 13800138000", salt=5, mode="fast", lang=["zh"], config=config)
        assert out == "Call 138****8000", f"negative clamp failed: {out!r}"


class TestPhoneRegionalMask:
    def test_should_mask_mainland_3_4_4(self):
        from argus_redact.pure.replacer import _mask_phone_regional

        assert _mask_phone_regional("13712345678") == "137****5678"

    def test_should_mask_hk_2_4_2(self):
        from argus_redact.pure.replacer import _mask_phone_regional

        assert _mask_phone_regional("90123456", region="hk") == "90****56"

    def test_should_mask_tw_2_4_3(self):
        from argus_redact.pure.replacer import _mask_phone_regional

        assert _mask_phone_regional("901234567", region="tw") == "90****567"
