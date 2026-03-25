"""PRvL three-axis benchmark — Privacy, Reversibility, Language preservation.

Based on arXiv:2508.05545 evaluation framework.
Run with: pytest tests/benchmark/test_prvl.py -v -s
"""

from argus_redact import redact, restore

BENCHMARK_TEXTS = [
    {
        "text": "张三的手机号是13812345678，在北京市朝阳区建国路100号工作",
        "pii": ["13812345678"],
        "semantic_tokens": ["工作"],
        "lang": "zh",
    },
    {
        "text": "John Smith, SSN 123-45-6789, works at Google HQ in Mountain View",
        "pii": ["123-45-6789"],
        "semantic_tokens": ["works", "Google", "Mountain View"],
        "lang": "en",
    },
    {
        "text": "田中太郎の携帯は090-1234-5678、東京で働いている",
        "pii": ["090-1234-5678"],
        "semantic_tokens": ["働いている"],
        "lang": "ja",
    },
    {
        "text": "김철수 전화번호 010-1234-5678, 서울에서 근무",
        "pii": ["010-1234-5678"],
        "semantic_tokens": ["근무"],
        "lang": "ko",
    },
]


def _compute_prvl(texts: list[dict], mode: str = "fast"):
    """Compute PRvL three-axis scores."""
    privacy_scores = []
    reversibility_scores = []
    language_scores = []

    for item in texts:
        redacted, key = redact(
            item["text"],
            mode=mode,
            lang=item["lang"],
            seed=42,
        )

        # Axis 1: Privacy — PII should NOT be in redacted text
        pii_leaked = sum(1 for p in item["pii"] if p in redacted)
        privacy = 1.0 - (pii_leaked / len(item["pii"])) if item["pii"] else 1.0
        privacy_scores.append(privacy)

        # Axis 2: Reversibility — restore should recover PII
        restored = restore(redacted, key)
        pii_recovered = sum(1 for p in item["pii"] if p in restored)
        reversibility = pii_recovered / len(item["pii"]) if item["pii"] else 1.0
        reversibility_scores.append(reversibility)

        # Axis 3: Language preservation — semantic tokens must survive
        tokens_preserved = sum(1 for t in item["semantic_tokens"] if t in redacted)
        language = (
            tokens_preserved / len(item["semantic_tokens"]) if item["semantic_tokens"] else 1.0
        )
        language_scores.append(language)

    def avg(scores):
        return sum(scores) / len(scores) if scores else 0

    return {
        "privacy": avg(privacy_scores),
        "reversibility": avg(reversibility_scores),
        "language": avg(language_scores),
    }


class TestPRvLBenchmark:
    def test_should_achieve_high_privacy(self):
        scores = _compute_prvl(BENCHMARK_TEXTS)

        print(f"\n  PRvL Privacy:       {scores['privacy']:.2%}")
        print(f"  PRvL Reversibility: {scores['reversibility']:.2%}")
        print(f"  PRvL Language:      {scores['language']:.2%}")

        assert scores["privacy"] >= 0.9

    def test_should_achieve_full_reversibility(self):
        scores = _compute_prvl(BENCHMARK_TEXTS)

        assert scores["reversibility"] == 1.0

    def test_should_preserve_language(self):
        scores = _compute_prvl(BENCHMARK_TEXTS)

        assert scores["language"] >= 0.8
