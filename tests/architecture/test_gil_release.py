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
    # A GIL-holding binding lands at ~1.0 on every trial (often below it). The
    # best of several trials clearly above 1 proves the lock was released;
    # 1.5 leaves generous headroom for a loaded or throttled CI box while
    # still failing the un-detached build on every single trial.
    assert speedup > 1.5, (
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
    assert speedup > 1.5, (
        f"restore does not appear to release the GIL (best of {_TRIALS}): "
        f"serial={serial:.3f}s parallel={parallel:.3f}s speedup={speedup:.2f}x"
    )
