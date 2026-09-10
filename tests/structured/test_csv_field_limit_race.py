"""Concurrent structured parses must never let one thread observe another's
raised csv field-size limit as its own 'old' value to restore.

``csv.field_size_limit`` is a process-global: a big-enough field keeps the
whole per-row C parse running for long enough that, without a lock around
the read-raise-parse-restore sequence, another thread reliably reads the
already-raised value and later restores it as if it were the original,
leaving the limit raised past this call. The field is sized to make the
race land in a handful of threads/iterations rather than needing a huge
fleet or a slow soak — the underlying mechanism is size-independent."""

import csv
import threading

from argus_redact import redact_csv

_KEYCELL = "13812345678,"
_BIG = "x" * 400_000


def _worker(errors):
    # 8 threads x 5 iterations = 40 concurrent parses: the final assertion
    # fails on a single leaked interleave anywhere, so at an unlocked build's
    # measured ~25%-per-attempt leak rate this still catches a regression
    # with >99.9% probability, at a fraction of the wall-time.
    try:
        for _ in range(5):
            redact_csv(f"{_KEYCELL}{_BIG}\n", salt=b"0" * 32, has_header=False)
    except Exception as e:  # noqa: BLE001
        errors.append(e)


def test_redact_csv_should_restore_the_default_field_size_limit_when_parsed_concurrently():
    default = csv.field_size_limit()
    errors: list = []
    threads = [threading.Thread(target=_worker, args=(errors,)) for _ in range(8)]

    try:
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, errors
        assert csv.field_size_limit() == default, "field_size_limit leaked past the call"
    finally:
        csv.field_size_limit(default)
