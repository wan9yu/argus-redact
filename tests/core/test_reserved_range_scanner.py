"""Tests for reserved-range pattern scanner."""

import time

from argus_redact.pure.reserved_range_scanner import scan_for_pollution


class TestScanForPollution:
    def test_should_match_phone_19999_prefix(self):
        hits = scan_for_pollution("call 19999123456 now")
        assert any(t == "phone_zh" for _, _, t in hits)

    def test_should_match_id_999_prefix(self):
        hits = scan_for_pollution("id 999101199003077654 here")
        assert any(t == "id_number_zh" for _, _, t in hits)

    def test_should_match_bank_999999_bin(self):
        hits = scan_for_pollution("card 9999990000000018 ok")
        assert any(t == "bank_card_zh" for _, _, t in hits)

    def test_should_match_landline_099(self):
        hits = scan_for_pollution("call 099-12345678 now")
        assert any(t == "phone_landline_zh" for _, _, t in hits)

    def test_should_not_match_real_phone(self):
        hits = scan_for_pollution("call 13912345678 now")
        assert not hits

    def test_should_match_multiple_in_one_text(self):
        text = "phone 19999123456 id 999101199003077654 card 9999990000000018"
        hits = scan_for_pollution(text)
        types = {t for _, _, t in hits}
        assert types == {"phone_zh", "id_number_zh", "bank_card_zh"}


# Performance budget: scanner must stay under this per 1KB so default-profile
# users who opt into pollution checks pay near-zero cost.
_PER_1KB_BUDGET_MS = 5


class TestScanPerformance:
    def test_should_scan_1kb_under_5ms(self):
        # 1KB of clean text (~600 Chinese chars + ~440 ASCII chars)
        text = "今天天气不错，普通业务消息。" * 50
        text = text + "ASCII filler. " * 30

        start = time.perf_counter()
        for _ in range(100):
            scan_for_pollution(text)
        elapsed_ms = (time.perf_counter() - start) * 1000 / 100

        assert elapsed_ms < _PER_1KB_BUDGET_MS, f"Scan too slow: {elapsed_ms:.2f}ms per 1KB"
