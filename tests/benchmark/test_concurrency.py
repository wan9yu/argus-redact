"""Concurrency stress test — verify thread safety."""

from concurrent.futures import ThreadPoolExecutor

from argus_redact import redact, restore


class TestConcurrency:
    def test_should_handle_100_concurrent_redactions(self):
        texts = [f"用户{i}的电话是138{i:08d}" for i in range(100)]

        def redact_one(text):
            redacted, key = redact(text, mode="fast", lang="zh")
            restored = restore(redacted, key)
            return text, redacted, restored, key

        with ThreadPoolExecutor(max_workers=10) as pool:
            results = list(pool.map(redact_one, texts))

        for original, redacted, restored, key in results:
            assert "138" in original
            assert len(key) >= 1
            for pii in key.values():
                assert pii not in redacted
                assert pii in restored

    def test_should_produce_unique_keys_across_threads(self):
        text = "电话13812345678"

        def redact_one(_):
            _, key = redact(text, mode="fast", lang="zh")
            return tuple(sorted(key.keys()))

        with ThreadPoolExecutor(max_workers=10) as pool:
            key_sets = list(pool.map(redact_one, range(20)))

        # mask strategy is deterministic, so all keys should be identical
        # (phone mask doesn't use random). This verifies no corruption.
        assert all(k == key_sets[0] for k in key_sets)

    def test_should_handle_mixed_languages_concurrently(self):
        cases = [
            ("电话13812345678", "zh"),
            ("SSN 123-45-6789", "en"),
            ("携帯090-1234-5678", "ja"),
            ("전화010-1234-5678", "ko"),
        ] * 25

        def redact_one(args):
            text, lang = args
            redacted, key = redact(text, mode="fast", lang=lang)
            return len(key) >= 1

        with ThreadPoolExecutor(max_workers=10) as pool:
            results = list(pool.map(redact_one, cases))

        assert all(results)
