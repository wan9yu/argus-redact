"""Self-contained Pi Zero 2W perf snapshot for argus-redact (no repo needed).

Mirrors the repo's throughput corpora + redact(mode="fast") / _core.detect_l1
timing so the numbers line up with bench_l1_rust_vs_python / perf_profile.
"""

import json
import platform
import statistics
import time

import argus_redact
from argus_redact import redact

try:
    from argus_redact._core_loader import _core
except Exception:  # pragma: no cover
    try:
        import argus_redact._core as _core
    except Exception:
        _core = None

_ZH_1KB = (
    "客户王五，手机13812345678，邮箱wang@corp.com，"
    "身份证110101199003074610，银行卡4111111111111111，"
    "车牌京A88888，住在北京市朝阳区建国路100号。"
) * 8
_EN_1KB = (
    "Patient John Smith called at (415) 555-1234. "
    "SSN 123-45-6789. Email john.smith@hospital.com. "
    "Address: 1234 Market Street, San Francisco, CA. "
) * 6
_ZH_SHORT = _ZH_1KB[: len(_ZH_1KB) // 8]
_EN_SHORT = _EN_1KB[: len(_EN_1KB) // 6]
_ZH_LONG = _ZH_1KB * 10
_EN_LONG = _EN_1KB * 10
_SALT = b"pi-perf-fixed-salt-32-bytes!!!!!"

CORPORA = {
    "en_short": ("en", _EN_SHORT),
    "en_1kb": ("en", _EN_1KB),
    "en_long": ("en", _EN_LONG),
    "zh_short": ("zh", _ZH_SHORT),
    "zh_1kb": ("zh", _ZH_1KB),
    "zh_long": ("zh", _ZH_LONG),
}

ITERS = 30
WARMUP = 5


def dist(fn):
    for _ in range(WARMUP):
        fn()
    s = []
    for _ in range(ITERS):
        t = time.perf_counter()
        fn()
        s.append((time.perf_counter() - t) * 1000.0)
    s.sort()
    n = len(s)
    med = statistics.median(s)

    def pct(p):
        return s[min(n - 1, int(round(p / 100.0 * (n - 1))))]

    return {
        "min_ms": round(s[0], 4),
        "p50_ms": round(med, 4),
        "p90_ms": round(pct(90), 4),
        "max_ms": round(s[-1], 4),
        "docs_per_s": round(1000.0 / med, 1) if med > 0 else None,
    }


def cpu_model():
    try:
        with open("/proc/device-tree/model") as f:
            return f.read().strip("\x00")
    except Exception:
        return platform.platform()


redact("warm-up", salt=_SALT)

workloads = {}
for label, (lang, text) in CORPORA.items():
    entry = {
        "lang": lang,
        "bytes": len(text.encode("utf-8")),
        "redact_fast": dist(lambda t=text, lg=lang: redact(t, salt=_SALT, mode="fast", lang=lg)),
    }
    if _core is not None:
        try:
            entry["detect_l1"] = dist(lambda t=text, lg=lang: _core.detect_l1(t, [lg], []))
        except Exception as e:
            entry["detect_l1_error"] = str(e)
    workloads[label] = entry

result = {
    "benchmark": "pi_perf",
    "package_version": argus_redact.__version__,
    "device": cpu_model(),
    "platform": platform.platform(),
    "machine": platform.machine(),
    "python": platform.python_version(),
    "iterations": ITERS,
    "workloads": workloads,
}
print(json.dumps(result, indent=2, ensure_ascii=False))
