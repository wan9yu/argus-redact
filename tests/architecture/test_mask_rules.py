"""Tests for enterprise mask rules — configurable per-type masking."""

from argus_redact import redact


class TestBankCardMask:
    def test_should_show_first6_last4_by_default(self):
        config = {"bank_card": {"strategy": "mask", "visible_prefix": 6, "visible_suffix": 4}}

        _, key = redact("卡号4111111111111111", seed=42, mode="fast", config=config)

        replacement = list(key.keys())[0]
        assert replacement.startswith("411111")
        assert replacement.endswith("1111")
        assert "*" in replacement


class TestChineseNameMask:
    def test_should_mask_2char_name(self):
        from argus_redact.pure.replacer import _mask_name

        assert _mask_name("张三") == "张*"

    def test_should_mask_3char_name(self):
        from argus_redact.pure.replacer import _mask_name

        assert _mask_name("李小明") == "李**"

    def test_should_mask_4char_name_show_first2(self):
        from argus_redact.pure.replacer import _mask_name

        assert _mask_name("欧阳小明") == "欧阳**"

    def test_should_mask_5char_name_show_first2(self):
        from argus_redact.pure.replacer import _mask_name

        assert _mask_name("爱新觉罗弘") == "爱新***"


class TestEmailMask:
    def test_should_show_first_char_and_domain(self):
        _, key = redact("邮箱test@qq.com", seed=42, mode="fast")

        replacement = list(key.keys())[0]
        assert replacement.startswith("t")
        assert "@qq.com" in replacement
        assert "*" in replacement


class TestLandlineMask:
    def test_should_keep_area_code_and_last3(self):
        from argus_redact.pure.replacer import _mask_landline

        assert _mask_landline("0755-12345678") == "0755-*****678"
        assert _mask_landline("010-12345678") == "010-*****678"

    def test_should_handle_no_dash(self):
        from argus_redact.pure.replacer import _mask_landline

        assert _mask_landline("075512345678") == "0755*****678"


class TestIdNumberMask:
    def test_should_show_first4_last4(self):
        config = {"id_number": {"strategy": "mask", "visible_prefix": 4, "visible_suffix": 4}}

        _, key = redact("身份证110101199003074610", seed=42, mode="fast", config=config)

        replacement = list(key.keys())[0]
        assert replacement.startswith("1101")
        assert replacement.endswith("4610")
        assert "*" in replacement


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
