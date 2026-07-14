"""Streaming ≡ batch equivalence — the honest, reproducible streaming table.

Replaces the unreproducible "cross-chunk recall 0.836" with the metric that matches
argus's actual design contract: feeding a document in ARBITRARY chunks recovers the
same protection + the same originals as processing it whole (batch), up to the
carry-window bound. Three rates per chunk regime, over an entity-rich zh+en corpus:

  leak_equiv        — every PII value batch REMOVES is also absent from the streamed
                      output (no stream-only leak; the fuzz-oracle guarantee).
  restore_recovers  — restore(stream_out, aggregate_key) == the original document
                      (entity recovery: the round-trip reconstructs every entity).
  output_identical  — stream_out == batch_out (strict equivalence; the strongest claim).

Bound: the longest reliably-recovered straddling entity = CARRY_WINDOW (256 chars).
Bounded patterns (phone / id / email / card / …) are far shorter; unbounded tokens
within the window are covered; beyond it is a documented edge (still leak-safe +
restorable, just not byte-identical). The corpus includes a carry-window-range token.

    python tests/benchmark/streaming_equivalence.py \
        --output tests/benchmark/results/streaming_equivalence_0.7.16.json
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

_REPO_SRC = str(Path(__file__).resolve().parent.parent.parent / "src")
if _REPO_SRC not in sys.path:
    sys.path.insert(0, _REPO_SRC)

from argus_redact.compose import StreamingRedactor  # noqa: E402
from argus_redact.glue._detect_partial import _CARRY_WINDOW  # noqa: E402
from argus_redact.glue.redact_pseudonym_llm import redact_pseudonym_llm  # noqa: E402
from argus_redact.pure.restore import restore  # noqa: E402

_SALT = 42

# Entity-rich corpus (zh + en), incl cross-sentence gated clusters + a
# carry-window-range token. strict_input=False bypasses reserved-name pollution.
_CORPUS = [
    (
        "zh",
        "客户张伟，手机13812345678，邮箱zhangwei@corp.com，"
        "身份证110101199003074610，住在北京市朝阳区建国路100号。",
    ),
    (
        "zh",
        "我以前就住在那里。上海浦东新区那一带。他的手机号13987654321。"
        "今天天气很好，我们一起去公园散步聊天。",
    ),
    (
        "zh",
        "我之前吃过花生。后来过敏很严重。我同事是一名软件工程师。"
        "联系电话13611112222。后面是一段中文结尾填充内容。",
    ),
    (
        "en",
        "Patient John Carter called at (415) 555-1234. SSN 123-45-6789. "
        "Email john.carter@hospital.com.",
    ),
    (
        "en",
        "Reach Mary Olsen at mary.olsen@example.org or 206-555-0190; "
        "card 4111111111111111 on file.",
    ),
    ("en", "The API key ghp_" + "A" * 150 + " was rotated yesterday by the on-call engineer."),
]


def _chunk(text: str, size: int) -> list[str]:
    chars = list(text)
    return ["".join(chars[i : i + size]) for i in range(0, len(chars), size)]


def _random_chunks(text: str, rng: random.Random) -> list[str]:
    chunks, i, n = [], 0, len(text)
    while i < n:
        step = rng.randint(1, 17)
        chunks.append(text[i : i + step])
        i += step
    return chunks


def _stream(chunks: list[str], lang: str):
    r = StreamingRedactor(salt=_SALT, mode="fast", lang=lang, strict_input=False)
    out = "".join(r.feed(c).downstream_text for c in chunks)
    out += r.flush().downstream_text
    return out, r


def _batch(text: str, lang: str):
    res = redact_pseudonym_llm(text, salt=_SALT, lang=lang, mode="fast", strict_input=False)
    removed = [o for o in set(res.key.values()) if o not in res.downstream_text]
    return res, removed


def _score_case(text: str, lang: str, chunks: list[str]) -> dict:
    batch_res, removed = _batch(text, lang)
    out, r = _stream(chunks, lang)
    return {
        "leak_equiv": all(term not in out for term in removed),
        "restore_recovers": restore(out, r.aggregate_key(), guard=False) == text,
        "output_identical": out == batch_res.downstream_text,
        "n_removed": len(removed),
    }


def _rates(cases: list[dict]) -> dict:
    n = len(cases)

    def pct(k):
        return round(100.0 * sum(1 for c in cases if c[k]) / n, 1) if n else None

    return {
        "cases": n,
        "leak_equiv_pct": pct("leak_equiv"),
        "restore_recovers_pct": pct("restore_recovers"),
        "output_identical_pct": pct("output_identical"),
    }


def evaluate(*, seeds: tuple[int, ...] = (1, 2, 3, 4, 5)) -> dict:
    import argus_redact

    regimes: dict[str, dict] = {}
    for label, size in (("1-char", 1), ("4-char", 4), ("64-char", 64)):
        cases = [_score_case(t, lang, _chunk(t, size)) for lang, t in _CORPUS]
        regimes[label] = _rates(cases)
    # random splits × seeds (deterministic via fixed seeds)
    rnd_cases = []
    for s in seeds:
        rng = random.Random(s)
        rnd_cases += [_score_case(t, lang, _random_chunks(t, rng)) for lang, t in _CORPUS]
    regimes["random(1-17)"] = _rates(rnd_cases)

    return {
        "benchmark": "streaming_equivalence",
        "package_version": argus_redact.__version__,
        "carry_window_chars": _CARRY_WINDOW,
        "corpus_docs": len(_CORPUS),
        "salt": _SALT,
        "regimes": regimes,
        "note": (
            "stream≡batch within the carry-window bound; longest reliably-recovered "
            f"straddling entity = {_CARRY_WINDOW} chars (bounded patterns far shorter)."
        ),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Streaming ≡ batch equivalence table.")
    ap.add_argument("--output", default=None)
    args = ap.parse_args()

    result = evaluate()
    if args.output:
        Path(args.output).write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        print(f"[wrote] {args.output}")
    hdr = f"{'regime':14s}{'cases':>6s}{'leak_equiv':>12s}{'restore':>10s}{'identical':>11s}"
    print(hdr)
    print("-" * len(hdr))
    for label, r in result["regimes"].items():
        print(
            f"{label:14s}{r['cases']:>6d}{r['leak_equiv_pct']:>11}%"
            f"{r['restore_recovers_pct']:>9}%{r['output_identical_pct']:>10}%"
        )


if __name__ == "__main__":
    main()
