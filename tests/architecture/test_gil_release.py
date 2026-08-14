"""The pure-Rust core calls must release the interpreter lock.

A PyO3 extension holds the GIL for the whole duration of a call unless it
explicitly detaches. Every entry point exercised here does nothing but run Rust
over data it already owns — no Python object is touched inside — so holding the
lock serialises callers that have no reason to be serialised: a thread pool
redacting N documents runs at one core no matter how many it is given.

The test measures WALL-CLOCK SPEEDUP across threads. It cannot assert a hard
speed number (CI runners vary wildly), so it asserts the qualitative property:
running the same total work spread over several threads must be meaningfully
faster than running it on one. Under a GIL-holding binding the two are equal (or
the threaded run is slower, from contention), so the assertion is a real
discriminator rather than a tautology.

To de-flake the threshold on shared/contended CI runners, the speedup is taken
as the best of several trials rather than a single measurement.
"""

from __future__ import annotations

import os
import threading
import time

import pytest

from argus_redact import _core
from argus_redact.pure.replacer import _KEEP_WHITELIST, DEFAULT_PREFIXES, _build_type_info

# Enough text that one call is comfortably longer than thread-spawn overhead.
_UNIT = "Contact Zhang Wei at 13812345678 or wei.zhang@example.com in Beijing. "
TEXT = _UNIT * 400

THREADS = 4
CALLS_PER_THREAD = 6


def _detect_many(n: int) -> None:
    for _ in range(n):
        _core.detect_l1(TEXT, ["zh", "en"], None)


def _elapsed(fn, *args) -> float:
    start = time.perf_counter()
    fn(*args)
    return time.perf_counter() - start


def _threaded(n_threads: int, calls_each: int) -> float:
    threads = [threading.Thread(target=_detect_many, args=(calls_each,)) for _ in range(n_threads)]
    start = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return time.perf_counter() - start


_TRIALS = 5


def _best_speedup(measure_serial, measure_parallel) -> tuple[float, float, float]:
    """Best (max) serial/parallel speedup over _TRIALS runs, to de-flake the
    timing threshold on shared/contended CI runners.

    A GIL-RELEASED build hits its true ~N-core speedup on at least one
    uncontended trial; a GIL-HELD build stays ~1.0 on EVERY trial (it cannot
    parallelise), so max-over-trials keeps the held-vs-released discriminator
    intact while a lone contention spike no longer false-fails.
    Returns (best_speedup, serial_of_best, parallel_of_best).
    """
    best = (0.0, 0.0, 0.0)
    for _ in range(_TRIALS):
        serial = measure_serial()
        parallel = measure_parallel()
        speedup = serial / parallel
        if speedup > best[0]:
            best = (speedup, serial, parallel)
    return best


@pytest.mark.skipif(
    (os.cpu_count() or 1) < 4, reason="needs >= 4 cores to observe parallel speedup"
)
def test_detect_l1_releases_the_lock_so_threads_actually_parallelise() -> None:
    # Warm every lazy static (pattern compiles, name pools) before timing.
    _core.detect_l1(TEXT, ["zh", "en"], None)

    speedup, serial, parallel = _best_speedup(
        lambda: _elapsed(_detect_many, THREADS * CALLS_PER_THREAD),
        lambda: _threaded(THREADS, CALLS_PER_THREAD),
    )
    # A GIL-holding binding cannot exceed ~1.0x on any trial: with the lock
    # held, the 4 threads serialise, so parallel wall-clock is roughly serial
    # wall-clock plus thread overhead (best-of-N tops out ~1.0-1.05x). A
    # GIL-released build clears ~1.4x even on the weakest GitHub-hosted
    # runner observed in CI (best-of-5 floor 1.41x there; a single-shot
    # measurement on that same runner class was as low as 1.29x, which is
    # what best-of-N is for). 1.2 sits ~0.2 above the held ceiling and below
    # the released floor, so it still fails an un-detached build on every
    # trial while no longer false-failing a correct build on a 2-core CI box.
    assert speedup > 1.2, (
        f"detect_l1 does not appear to release the GIL (best of {_TRIALS}): "
        f"serial={serial:.3f}s parallel={parallel:.3f}s speedup={speedup:.2f}x"
    )


@pytest.mark.skipif(
    (os.cpu_count() or 1) < 4, reason="needs >= 4 cores to observe parallel speedup"
)
def test_restore_releases_the_lock_so_threads_actually_parallelise() -> None:
    key = {f"P-{i:05d}": f"Person Number {i}" for i in range(4000)}
    text = " ".join(f"P-{i:05d}" for i in range(0, 4000, 40))

    def restore_many(n: int) -> None:
        for _ in range(n):
            _core.restore(text, key)

    _core.restore(text, key)  # warm

    def restore_serial() -> float:
        return _elapsed(restore_many, THREADS * 2)

    def restore_parallel() -> float:
        start = time.perf_counter()
        threads = [threading.Thread(target=restore_many, args=(2,)) for _ in range(THREADS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return time.perf_counter() - start

    speedup, serial, parallel = _best_speedup(restore_serial, restore_parallel)
    # See test_detect_l1_releases_the_lock...'s comment: held ~1.0x vs
    # released ~1.4x on GitHub-hosted runners, so 1.2 discriminates with
    # margin without false-failing on a 2-core CI box.
    assert speedup > 1.2, (
        f"restore does not appear to release the GIL (best of {_TRIALS}): "
        f"serial={serial:.3f}s parallel={parallel:.3f}s speedup={speedup:.2f}x"
    )


def _make_replace_workload() -> tuple[str, list, dict]:
    """A pure-Rust replace workload: many DISTINCT phone values under the
    realistic strategy (built-in Rust faker → SHAKE, no Python callback). Each
    distinct value drives one faker generation, so the work is CPU-bound in Rust
    and scales with the entity count.
    """
    n = 4000
    numbers = [str(13800000000 + i) for i in range(n)]  # 11 digits each, distinct
    text = " ".join(numbers)
    entities = []
    pos = 0
    for num in numbers:
        entities.append(_core.PatternMatch(num, "phone", pos, pos + len(num), 1.0, 0))
        pos += len(num) + 1  # +1 for the single-space separator
    type_info, custom_fakers = _build_type_info(
        entities, {"phone": {"strategy": "realistic"}}, ["zh"]
    )
    # The whole point of this test is the no-custom-faker path (the one that
    # detaches). A built-in realistic faker must NOT register a custom callable.
    assert not custom_fakers, "workload must stay on the pure-Rust no-custom-faker path"
    return text, entities, type_info


@pytest.mark.skipif(
    (os.cpu_count() or 1) < 4, reason="needs >= 4 cores to observe parallel speedup"
)
def test_replace_releases_the_lock_so_threads_actually_parallelise() -> None:
    # `_core.replace` was the odd one out: it held the GIL for a CPU-bound pass
    # (unlike detect_l1 / restore), so a large redact serialised every other
    # thread — and, over HTTP, froze the whole server event loop. It must now
    # release the lock on the common no-custom-faker path.
    text, entities, type_info = _make_replace_workload()

    def replace_once() -> None:
        _core.replace(
            text,
            entities,
            salt=42,
            key=None,
            type_info=type_info,
            person_prefix=DEFAULT_PREFIXES["person"],
            org_prefix=DEFAULT_PREFIXES["organization"],
            unified_prefix=None,
            keep_whitelist=_KEEP_WHITELIST,
            custom_fakers=None,
        )

    def replace_many(n: int) -> None:
        for _ in range(n):
            replace_once()

    replace_once()  # warm the lazy statics (faker pools, salt resolve)

    def replace_serial() -> float:
        return _elapsed(replace_many, THREADS * CALLS_PER_THREAD)

    def replace_parallel() -> float:
        threads = [
            threading.Thread(target=replace_many, args=(CALLS_PER_THREAD,)) for _ in range(THREADS)
        ]
        start = time.perf_counter()
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return time.perf_counter() - start

    speedup, serial, parallel = _best_speedup(replace_serial, replace_parallel)
    # See test_detect_l1_releases_the_lock...'s comment for the 1.2 threshold:
    # a GIL-holding replace tops out ~1.0x on every trial (the 4 threads
    # serialise), a released one clears ~1.4x, so 1.2 fails the un-detached
    # binding while leaving margin on a contended CI box.
    assert speedup > 1.2, (
        f"replace does not appear to release the GIL (best of {_TRIALS}): "
        f"serial={serial:.3f}s parallel={parallel:.3f}s speedup={speedup:.2f}x"
    )
