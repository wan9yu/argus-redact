"""Performance budget runner — measure 6 workloads with 5-run median.

Usage:
    python tests/benchmark/run_perf_budget.py --output current.json
    python tests/benchmark/run_perf_budget.py --output current.json --platform Linux --commit abc1234

Output JSON shape lives in `tests/benchmark/baseline.json`.
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path


_REPO_SRC = str(Path(__file__).parent.parent.parent / "src")


# ── Test inputs ──

_ZH_1KB = (
    "客户王五，手机13812345678，邮箱wang@corp.com，"
    "身份证110101199003074610，银行卡4111111111111111，"
    "车牌京A88888，住在北京市朝阳区建国路100号。"
) * 8  # ~1KB

_EN_1KB = (
    "Patient John Smith called at (415) 555-1234. "
    "SSN 123-45-6789. Email john.smith@hospital.com. "
    "Address: 1234 Market Street, San Francisco, CA. "
) * 6  # ~1KB

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
    """Cold-start import time via subprocess (median of 5 runs)."""
    times = []
    for _ in range(5):
        start = time.perf_counter()
        subprocess.run(
            [sys.executable, "-c", "import argus_redact"],
            check=True,
            env={"PYTHONPATH": _REPO_SRC, "PATH": "/usr/bin:/bin"},
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
    from argus_redact import StreamingRedactor, redact, redact_pseudonym_llm, restore

    # Warm caches
    redact("warm-up", seed=1)

    measurements = {
        "import_time_ms": _measure_import_time(),
        "redact_zh_fast_1kb_p50_ms": _measure_p50(
            lambda: redact(_ZH_1KB, seed=42, mode="fast", lang="zh")
        ),
        "redact_en_fast_1kb_p50_ms": _measure_p50(
            lambda: redact(_EN_1KB, seed=42, mode="fast", lang="en")
        ),
        "redact_pseudonym_llm_zh_1kb_p50_ms": _measure_p50(
            lambda: redact_pseudonym_llm(
                _ZH_1KB,
                salt=_SALT_FOR_PSEUDONYM_LLM,
                lang="zh",
                strict_input=False,
            )
        ),
        "restore_1kb_p50_ms": _measure_p50(_restore_workload),
        "streaming_feed_per_chunk_p50_ms": _measure_p50(_streaming_workload),
    }

    output = {
        "schema_version": 1,
        "platform": args.platform,
        "python": f"{sys.version_info.major}.{sys.version_info.minor}",
        "commit": args.commit,
        "measurements": measurements,
    }

    Path(args.output).write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(json.dumps(output, indent=2))


def _restore_workload() -> None:
    from argus_redact import redact, restore

    redacted, key = redact(_ZH_1KB, seed=42, mode="fast", lang="zh")
    restore(redacted, key)


def _streaming_workload() -> None:
    from argus_redact import StreamingRedactor

    r = StreamingRedactor(salt=_SALT_FOR_PSEUDONYM_LLM, strict_input=False)
    chunk = _ZH_1KB[:256]
    r.feed(chunk)
    r.flush()


if __name__ == "__main__":
    main()
