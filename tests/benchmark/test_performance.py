"""Performance benchmarks — measure latency on M1 Max.

Run with: pytest tests/benchmark/test_performance.py -v -s
"""

import time

from argus_redact import redact, restore


def _measure(fn, rounds=100):
    """Run fn multiple times, return (avg_ms, min_ms, max_ms)."""
    times = []
    for _ in range(rounds):
        start = time.perf_counter()
        fn()
        elapsed = (time.perf_counter() - start) * 1000
        times.append(elapsed)
    return sum(times) / len(times), min(times), max(times)


def _report(label, avg, mn, mx):
    print(f"\n  {label}: avg={avg:.2f}ms min={mn:.2f}ms max={mx:.2f}ms")


# ── Test texts of varying sizes ──

SHORT_TEXT = "张三的电话是13812345678"
MEDIUM_TEXT = (
    "张三的电话是13812345678，邮箱zhang@test.com，"
    "身份证110101199003074610，银行卡4111111111111111。"
) * 10
LONG_TEXT = (
    "客户王五，手机13812345678，邮箱wang@corp.com，"
    "身份证110101199003074610，银行卡4111111111111111，"
    "车牌京A88888，住在北京市朝阳区建国路100号。"
) * 100


class TestRegexPerformance:
    """Layer 1 (regex only) performance."""

    def test_should_redact_short_text_under_1ms(self):
        avg, mn, mx = _measure(
            lambda: redact(SHORT_TEXT, seed=42, mode="fast"),
        )

        _report(f"Short ({len(SHORT_TEXT)} chars)", avg, mn, mx)
        assert avg < 1.0, f"Too slow: {avg:.2f}ms"

    def test_should_redact_medium_text_under_5ms(self):
        avg, mn, mx = _measure(
            lambda: redact(MEDIUM_TEXT, seed=42, mode="fast"),
        )

        _report(f"Medium ({len(MEDIUM_TEXT)} chars)", avg, mn, mx)
        assert avg < 10.0, f"Too slow: {avg:.2f}ms"

    def test_should_redact_long_text_under_50ms(self):
        avg, mn, mx = _measure(
            lambda: redact(LONG_TEXT, seed=42, mode="fast"),
            rounds=20,
        )

        _report(f"Long ({len(LONG_TEXT)} chars)", avg, mn, mx)
        assert avg < 200.0, f"Too slow: {avg:.2f}ms"


class TestRestorePerformance:
    """restore() should be fast — pure string replacement."""

    def test_should_restore_under_1ms(self):
        redacted, key = redact(MEDIUM_TEXT, seed=42, mode="fast")

        avg, mn, mx = _measure(lambda: restore(redacted, key))

        _report(f"Restore ({len(redacted)} chars, {len(key)} keys)", avg, mn, mx)
        assert avg < 1.0, f"Too slow: {avg:.2f}ms"


class TestThroughput:
    """Measure documents per second."""

    def test_should_process_1000_short_docs_under_1s(self):
        docs = [SHORT_TEXT] * 1000

        start = time.perf_counter()
        for doc in docs:
            redact(doc, seed=42, mode="fast")
        elapsed = time.perf_counter() - start

        throughput = len(docs) / elapsed
        print(f"\n  Throughput: {throughput:.0f} docs/sec" f" ({len(docs)} docs in {elapsed:.2f}s)")
        assert elapsed < 1.0, f"Too slow: {elapsed:.2f}s"

    def test_should_process_100_medium_docs_under_2s(self):
        docs = [MEDIUM_TEXT] * 100

        start = time.perf_counter()
        for doc in docs:
            redact(doc, seed=42, mode="fast")
        elapsed = time.perf_counter() - start

        throughput = len(docs) / elapsed
        print(f"\n  Throughput: {throughput:.0f} docs/sec" f" ({len(docs)} docs in {elapsed:.2f}s)")
        assert elapsed < 2.0, f"Too slow: {elapsed:.2f}s"


class TestMixedLanguagePerformance:
    """Multi-language overhead."""

    def test_should_not_be_much_slower_with_four_languages(self):
        text = "手机13812345678, SSN 123-45-6789, " "携帯090-1234-5678, 전화010-1234-5678"

        avg_single, _, _ = _measure(
            lambda: redact(text, seed=42, mode="fast", lang="zh"),
        )
        avg_four, _, _ = _measure(
            lambda: redact(
                text,
                seed=42,
                mode="fast",
                lang=["zh", "en", "ja", "ko"],
            ),
        )

        ratio = avg_four / avg_single if avg_single > 0 else 0
        print(f"\n  1 lang: {avg_single:.2f}ms, " f"4 lang: {avg_four:.2f}ms, ratio: {ratio:.1f}x")
        assert ratio < 5.0, f"Too much overhead: {ratio:.1f}x"
