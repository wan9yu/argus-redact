"""Layer-1 Rust-vs-Python micro-benchmark + current end-to-end throughput.

Two things live here:

1. **Component A/B (Part 1).** L1 detection is 100% Rust today, but two pure-Python
   *oracles* survive for parity testing: ``pure/patterns._match_python_patterns``
   (real ``re.finditer`` over the builtin pattern set) and ``pure/hints.produce_hints``.
   We time each against its Rust counterpart on the SAME corpus and report the
   Rust:Python speedup ratio per language.

   Coverage caveat: the A/B covers only the regex hot path (+ hints). The named
   validators (ssn / credit-card Luhn / ...) and person-name detection are
   **Rust-only** — there is no surviving Python oracle for them — so they are NOT
   in this ratio. Because the Rust ``match_patterns`` ALSO runs the named
   validator while the Python ``_match_python_patterns`` does not (builtin
   patterns carry a Rust ``validator`` string, never a Python ``validate``
   callable), Rust does strictly *more* work per call: the reported pattern
   speedup is a conservative lower bound for the regex+context portion.

2. **Throughput profile (Part 3).** Current ``redact(text, mode="fast")`` and
   raw ``_core.detect_l1`` p50 on short / medium / long en+zh inputs.

No absolute paths: the repo ``src`` is resolved relative to this file. Run with::

    python tests/benchmark/bench_l1_rust_vs_python.py

Every number is measured at runtime on the invoking machine; nothing is hardcoded.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from pathlib import Path

_REPO_SRC = str(Path(__file__).resolve().parent.parent.parent / "src")
if _REPO_SRC not in sys.path:
    sys.path.insert(0, _REPO_SRC)


# ── Fixed representative corpus ──
#
# Short ~1KB texts mirror the perf-budget corpus (run_perf_budget.py) so the
# component A/B and the throughput profile share a comparable density of PII.
# Medium/long are the same text repeated to reach roughly the stated size.

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

_ZH_SHORT = _ZH_1KB[: len(_ZH_1KB) // 8]  # ~one repetition, ~120 chars
_EN_SHORT = _EN_1KB[: len(_EN_1KB) // 6]  # ~one repetition

_ZH_LONG = _ZH_1KB * 10  # ~10KB
_EN_LONG = _EN_1KB * 10  # ~10KB

# Fixed 32-byte salt — high-entropy so the bench doesn't trip the low-entropy
# SecurityWarning (the value is irrelevant to timing).
_BENCH_SALT = b"bench-l1-rust-vs-python-fixed!!!"


# ── timing helpers ──


def _timeit_p50(fn, *, iterations: int, warmup: int = 50) -> float:
    """Median per-call duration in milliseconds over `iterations` calls."""
    for _ in range(warmup):
        fn()
    samples = []
    for _ in range(iterations):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000)
    return statistics.median(samples)


def _machine_label() -> str:
    """Generic machine label — no hostname/username."""
    mach = platform.machine()
    sysname = platform.system()
    if sysname == "Darwin" and mach == "arm64":
        return "Apple M-series (arm64, macOS)"
    return f"{sysname} {mach}"


def _python_label() -> str:
    return f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"


# ── Part 1: component A/B ──


def component_ab(*, iterations: int = 2000) -> dict:
    """Rust:Python speedup for the regex hot path and the hints producer.

    Returns a dict keyed by component+lang with p50 (ms) for each engine and the
    ratio python_p50 / rust_p50 (>1 means Rust is faster).
    """
    from argus_redact._core_loader import _core
    from argus_redact.lang._loader import core_patterns
    from argus_redact.pure.hints import produce_hints
    from argus_redact.pure.patterns import _match_python_patterns

    out: dict[str, dict] = {}

    for lang, text in (("en", _EN_1KB), ("zh", _ZH_1KB)):
        patterns = core_patterns(lang)

        # -- patterns hot path --
        def _py_patterns(t=text, p=patterns):
            results: list = []
            near_misses: list = []
            _match_python_patterns(t, p, results, near_misses)
            return results

        def _rust_patterns(t=text, p=patterns):
            return _core.match_patterns(t, p)

        py_pat = _timeit_p50(_py_patterns, iterations=iterations)
        rust_pat = _timeit_p50(_rust_patterns, iterations=iterations)
        out[f"patterns_{lang}"] = {
            "python_p50_ms": round(py_pat, 5),
            "rust_p50_ms": round(rust_pat, 5),
            "rust_speedup_x": round(py_pat / rust_pat, 2),
        }

        # -- hints producer --
        # Build the entity sets ONCE (outside the timed loop) so we measure only
        # the hint producer, not the upstream regex.
        rust_matches = _core.match_patterns(text, patterns)
        py_results: list = []
        py_near: list = []
        _match_python_patterns(text, patterns, py_results, py_near)

        def _py_hints(e=py_results, t=text, nm=py_near):
            return produce_hints(e, t, near_misses=nm)

        def _rust_hints(e=rust_matches, t=text):
            return _core.produce_hints_l1(e, t)

        py_h = _timeit_p50(_py_hints, iterations=iterations)
        rust_h = _timeit_p50(_rust_hints, iterations=iterations)
        out[f"hints_{lang}"] = {
            "python_p50_ms": round(py_h, 5),
            "rust_p50_ms": round(rust_h, 5),
            "rust_speedup_x": round(py_h / rust_h, 2),
        }

    return out


# ── Part 3: current throughput profile ──

_THROUGHPUT_CORPUS = {
    "en_short": ("en", _EN_SHORT),
    "en_1kb": ("en", _EN_1KB),
    "en_long": ("en", _EN_LONG),
    "zh_short": ("zh", _ZH_SHORT),
    "zh_1kb": ("zh", _ZH_1KB),
    "zh_long": ("zh", _ZH_LONG),
}


def throughput_profile(*, iterations: int = 500) -> dict:
    """p50 (ms) + docs/s for redact(mode='fast') and raw _core.detect_l1."""
    from argus_redact import redact
    from argus_redact._core_loader import _core

    redact("warm-up", salt=_BENCH_SALT)  # warm caches

    out: dict[str, dict] = {}
    for label, (lang, text) in _THROUGHPUT_CORPUS.items():

        def _redact(t=text, lng=lang):
            return redact(t, salt=_BENCH_SALT, mode="fast", lang=lng)

        def _detect(t=text, lng=lang):
            return _core.detect_l1(t, [lng], [])

        red_p50 = _timeit_p50(_redact, iterations=iterations, warmup=20)
        det_p50 = _timeit_p50(_detect, iterations=iterations, warmup=20)
        out[label] = {
            "bytes": len(text.encode("utf-8")),
            "redact_fast_p50_ms": round(red_p50, 4),
            "redact_fast_docs_per_s": round(1000.0 / red_p50, 1),
            "detect_l1_p50_ms": round(det_p50, 4),
            "detect_l1_docs_per_s": round(1000.0 / det_p50, 1),
        }
    return out


# ── Part 2: cross-version end-to-end (driven by an external venv) ──


def end_to_end_fast(*, iterations: int = 500) -> dict:
    """redact(mode='fast') p50 + docs/s for whatever argus_redact is importable.

    Used by Part 2 to measure the v0.6.12 worktree (via an isolated venv) and the
    current build with identical corpus + iteration count. The version of the
    importable package is recorded so the caller can confirm isolation.
    """
    import argus_redact
    from argus_redact import redact

    redact("warm-up", salt=_BENCH_SALT)
    out: dict[str, dict] = {"_version": argus_redact.__version__}
    for label, (lang, text) in (("en_1kb", ("en", _EN_1KB)), ("zh_1kb", ("zh", _ZH_1KB))):

        def _redact(t=text, lng=lang):
            return redact(t, salt=_BENCH_SALT, mode="fast", lang=lng)

        p50 = _timeit_p50(_redact, iterations=iterations, warmup=20)
        out[label] = {
            "redact_fast_p50_ms": round(p50, 4),
            "redact_fast_docs_per_s": round(1000.0 / p50, 1),
        }
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        choices=("all", "component", "throughput", "e2e"),
        default="all",
        help="component=Part1, throughput=Part3, e2e=Part2 (this importable build only).",
    )
    parser.add_argument("--iterations", type=int, default=None)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON only")
    args = parser.parse_args()

    import argus_redact

    report: dict = {
        "machine": _machine_label(),
        "python": _python_label(),
        "argus_redact_version": argus_redact.__version__,
    }

    if args.mode in ("all", "component"):
        report["component_ab"] = component_ab(iterations=args.iterations or 2000)
    if args.mode in ("all", "throughput"):
        report["throughput"] = throughput_profile(iterations=args.iterations or 500)
    if args.mode == "e2e":
        report["end_to_end"] = end_to_end_fast(iterations=args.iterations or 500)

    if args.json:
        print(json.dumps(report, indent=2))
        return

    print(f"machine : {report['machine']}")
    print(f"python  : {report['python']}")
    print(f"version : {report['argus_redact_version']}")

    if "component_ab" in report:
        print("\n── Part 1: component A/B (Rust vs Python oracle) ──")
        print(f"{'component':<14}{'python p50':>14}{'rust p50':>14}{'rust speedup':>16}")
        for key, m in report["component_ab"].items():
            print(
                f"{key:<14}{m['python_p50_ms']:>12.5f}ms"
                f"{m['rust_p50_ms']:>12.5f}ms{m['rust_speedup_x']:>14.2f}x"
            )
        print(
            "\ncaveat: covers the regex hot path (+hints) only. Named validators "
            "and\nperson detection are Rust-only (no Python oracle). Rust "
            "match_patterns also\nruns the named validator the Python oracle "
            "skips, so the ratio is a\nconservative lower bound for regex+context."
        )

    if "throughput" in report:
        print("\n── Part 3: current throughput (mode='fast') ──")
        print(
            f"{'input':<12}{'bytes':>8}{'redact p50':>14}{'docs/s':>12}"
            f"{'detect_l1 p50':>16}{'docs/s':>12}"
        )
        for key, m in report["throughput"].items():
            print(
                f"{key:<12}{m['bytes']:>8}{m['redact_fast_p50_ms']:>12.4f}ms"
                f"{m['redact_fast_docs_per_s']:>12.1f}"
                f"{m['detect_l1_p50_ms']:>14.4f}ms{m['detect_l1_docs_per_s']:>12.1f}"
            )

    if "end_to_end" in report:
        print("\n── Part 2: end-to-end (this importable build) ──")
        print(json.dumps(report["end_to_end"], indent=2))


if __name__ == "__main__":
    main()
