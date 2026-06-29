"""Shared perf corpora — the single source for the perf scripts.

The ~1KB zh/en inputs, their short/long derivatives, and the throughput-corpus
map are imported by ``run_perf_budget.py`` (the CI perf gate),
``bench_l1_rust_vs_python.py``, and ``perf_profile.py`` so all three measure the
SAME bytes. ``pi_perf.py`` keeps an inline copy ON PURPOSE — it must run on a
repo-less aarch64 device — and ``test_corpus_parity.py`` pins that copy equal to
these, so the standalone copy cannot silently drift.

Salts are intentionally NOT here: each script owns its own fixed salt.
"""

from __future__ import annotations

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

_ZH_SHORT = _ZH_1KB[: len(_ZH_1KB) // 8]  # ~one repetition
_EN_SHORT = _EN_1KB[: len(_EN_1KB) // 6]  # ~one repetition
_ZH_LONG = _ZH_1KB * 10  # ~10KB
_EN_LONG = _EN_1KB * 10  # ~10KB

# (lang, text) per throughput workload — shared by bench_l1 + perf_profile.
_THROUGHPUT_CORPUS = {
    "en_short": ("en", _EN_SHORT),
    "en_1kb": ("en", _EN_1KB),
    "en_long": ("en", _EN_LONG),
    "zh_short": ("zh", _ZH_SHORT),
    "zh_1kb": ("zh", _ZH_1KB),
    "zh_long": ("zh", _ZH_LONG),
}
