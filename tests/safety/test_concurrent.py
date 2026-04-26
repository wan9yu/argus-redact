"""Concurrent safety tests — verify no data corruption under parallel load."""

from concurrent.futures import ThreadPoolExecutor

from argus_redact import redact, restore


class TestConcurrentRedact:
    def test_should_not_corrupt_when_parallel_redact(self):
        """Multiple threads calling redact() must not leak data between calls."""
        texts = [f"客户{chr(0x5F20 + i)}三电话138{i:08d}" for i in range(50)]

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [
                pool.submit(redact, t, seed=i, mode="fast", names=[t[2:4]])
                for i, t in enumerate(texts)
            ]
            results = [f.result() for f in futures]

        for i, (redacted, key) in enumerate(results):
            phone = f"138{i:08d}"
            assert phone not in redacted, f"Thread {i}: phone leaked"
            assert phone in key.values(), f"Thread {i}: phone missing from key"
            # No cross-contamination: other threads' phones should not be in this key
            for j in range(50):
                if j != i:
                    other_phone = f"138{j:08d}"
                    assert other_phone not in key.values(), (
                        f"Thread {i} key contains thread {j}'s phone"
                    )

    def test_should_roundtrip_when_parallel(self):
        """redact → restore roundtrip must work under concurrency."""
        texts = [f"电话138{i:08d}" for i in range(20)]

        def roundtrip(text, seed):
            redacted, key = redact(text, seed=seed, mode="fast")
            restored = restore(redacted, key)
            return text, restored

        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(roundtrip, t, i) for i, t in enumerate(texts)]
            results = [f.result() for f in futures]

        for original, restored in results:
            phone = original[2:]  # strip "电话"
            assert phone in restored

    def test_should_not_deadlock_when_high_concurrency(self):
        """100 concurrent calls should complete without deadlock."""
        with ThreadPoolExecutor(max_workers=16) as pool:
            futures = [
                pool.submit(redact, "电话13812345678", seed=i, mode="fast") for i in range(100)
            ]
            results = [f.result() for f in futures]

        assert len(results) == 100
        assert all("13812345678" not in r for r, _ in results)
