"""Performance budget runner — measure 6 workloads with 5-run median.

Usage:
    python tests/benchmark/run_perf_budget.py --output current.json
    python tests/benchmark/run_perf_budget.py --output current.json \
        --platform Linux --commit abc1234

Output JSON shape lives in `tests/benchmark/baseline.json`.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

_REPO_SRC = str(Path(__file__).parent.parent.parent / "src")


# ── Test inputs ──
# The zh/en perf corpora live in _corpus (shared with bench_l1 + perf_profile so
# all three measure the same bytes — byte-identical to the prior inline copies).
from _corpus import _EN_1KB, _ZH_1KB  # noqa: E402

_SALT_FOR_PSEUDONYM_LLM = b"perf-budget-fixed-salt-32-bytes!"


def _measure_p50(fn, runs: int = 5) -> float:
    """Return median wall-clock duration over `runs` calls (in milliseconds)."""
    times = []
    for _ in range(runs):
        start = time.perf_counter()
        fn()
        times.append((time.perf_counter() - start) * 1000)
    return statistics.median(times)


def _measure_import_time() -> float:
    """Cold-start import time via subprocess (median of 5 runs).

    Includes process-spawn overhead (~20-50ms); useful for relative
    regression detection, less useful as an absolute "import argus_redact"
    cost. Inherits parent env to keep platform PATH semantics — hardcoding
    PATH would break Windows CI (no /usr/bin) and surface env-resolution
    differences across runners.
    """
    env = os.environ.copy()
    env["PYTHONPATH"] = _REPO_SRC
    times = []
    for _ in range(5):
        start = time.perf_counter()
        subprocess.run(
            [sys.executable, "-c", "import argus_redact"],
            check=True,
            env=env,
        )
        times.append((time.perf_counter() - start) * 1000)
    return statistics.median(times)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--platform", default=sys.platform)
    parser.add_argument("--commit", default="unknown")
    args = parser.parse_args()

    sys.path.insert(0, _REPO_SRC)
    from argus_redact import redact, redact_pseudonym_llm

    # Warm caches
    redact("warm-up", salt=1)

    measurements = {
        "import_time_ms": _measure_import_time(),
        "redact_zh_fast_1kb_p50_ms": _measure_p50(
            lambda: redact(_ZH_1KB, salt=42, mode="fast", lang="zh")
        ),
        "redact_en_fast_1kb_p50_ms": _measure_p50(
            lambda: redact(_EN_1KB, salt=42, mode="fast", lang="en")
        ),
        # strict_input=False: _ZH_1KB contains "王五" which is in the reserved
        # canonical-name pool. Without the bypass, redact_pseudonym_llm raises
        # PseudonymPollutionError on first call.
        "redact_pseudonym_llm_zh_1kb_p50_ms": _measure_p50(
            lambda: redact_pseudonym_llm(
                _ZH_1KB,
                salt=_SALT_FOR_PSEUDONYM_LLM,
                lang="zh",
                strict_input=False,
            )
        ),
        "restore_1kb_p50_ms": _measure_p50(_restore_workload),
        # Single 256-char feed that reaches a sentence boundary and EMITS — measures
        # the irreducible detect-once cost of the v0.7.14 correctness design. The
        # emit_possible gate does NOT speed this up (the feed always emits); the
        # value reflects the inherent cost of one _detect call over ~256 chars.
        "streaming_feed_per_chunk_p50_ms": _measure_p50(_streaming_workload),
        # Realistic small-chunk "dribble": ~1KB fed in 4-char increments through one
        # StreamingRedactor, plus flush(). The MAJORITY of feeds are boundary-less
        # holds that the emit_possible gate short-circuits before _detect runs; only
        # the feeds that reach a sentence boundary run detection. Reported as the
        # TOTAL wall-time of the whole dribble+flush run (ms-scale, stable) rather
        # than a per-chunk p50 (which is µs-scale and noise-flaky against the ±10%
        # gate). Captures the gate optimization as a number that won't flap.
        "streaming_dribble_total_ms": _measure_p50(_streaming_dribble_workload),
    }

    output = {
        "schema_version": 1,
        "platform": args.platform,
        "python": f"{sys.version_info.major}.{sys.version_info.minor}",
        "commit": args.commit,
        # Round to 4 decimals — measurement precision is sub-µs, so keeping 16
        # significant digits creates noise in baseline.json git diffs.
        "measurements": {k: round(v, 4) for k, v in measurements.items()},
    }

    serialized = json.dumps(output, indent=2) + "\n"
    Path(args.output).write_text(serialized, encoding="utf-8")
    print(serialized, end="")


def _restore_workload() -> None:
    from argus_redact import redact, restore

    redacted, key = redact(_ZH_1KB, salt=42, mode="fast", lang="zh")
    restore(redacted, key)


def _streaming_workload() -> None:
    from argus_redact.compose import StreamingRedactor

    r = StreamingRedactor(salt=_SALT_FOR_PSEUDONYM_LLM, strict_input=False)
    chunk = _ZH_1KB[:256]
    r.feed(chunk)
    r.flush()


def _streaming_dribble_workload() -> None:
    """Feed ~1KB in 4-char chunks through one StreamingRedactor, then flush().

    The emit_possible gate makes the majority of feeds (boundary-less holds) cheap:
    the gate fires before _detect runs; only the feeds that reach a sentence boundary
    trigger detection. Timed by _measure_p50 as one ms-scale unit (total run time) —
    stable against the ±10% regression gate, unlike a µs-scale per-chunk p50.
    """
    from argus_redact.compose import StreamingRedactor

    text = _ZH_1KB  # ~1KB, contains sentence boundaries
    chunk_size = 4
    r = StreamingRedactor(salt=_SALT_FOR_PSEUDONYM_LLM, lang="zh", strict_input=False)
    for i in range(0, len(text), chunk_size):
        r.feed(text[i : i + chunk_size])
    r.flush()


if __name__ == "__main__":
    main()
