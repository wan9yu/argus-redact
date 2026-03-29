"""Benchmark Layer 3 implicit PII detection across LLM models.

Requires Ollama running locally with models installed.
Run: pytest tests/benchmark/test_layer3_models.py -v -s --no-header

This test is marked 'semantic' — skipped in normal CI.
"""

import json
import time

import pytest
import requests

OLLAMA_URL = "http://localhost:11434/api/generate"

SYSTEM_PROMPT = """你是隐私分析专家。分析以下文本，找出所有隐含的敏感个人信息，包括：
- medical: 暗示疾病、症状、就医、服药
- financial: 暗示收入、债务、经济状况
- religion: 暗示宗教活动、信仰
- political: 暗示政治立场、政治活动
- sexual_orientation: 暗示性取向
- criminal: 暗示违法犯罪经历
- biometric: 暗示生物特征数据采集
- gender: 通过上下文推断性别
- ethnicity: 通过上下文推断民族

只找隐含的、间接的信息，不要重复明确说出的内容。
以JSON数组返回：[{"text": "原文片段", "type": "类型(用英文)", "reason": "推断依据"}]
没有发现则返回 []。只返回JSON，不要其他文字。"""

TEST_CASES = [
    ("她最近总是跑厕所，还经常口渴", "medical"),
    ("他每天要吃好几种药片", "medical"),
    ("自从上次住院回来他瘦了很多", "medical"),
    ("他最近经济压力很大，房子快要断供了", "financial"),
    ("她开的是保时捷，住在汤臣一品", "financial"),
    ("他每周五下午都请假", "religion"),
    ("她不吃猪肉，斋月期间白天不进食", "religion"),
    ("他的立场比较偏左", "political"),
    ("她经常在网上发表对政策的不满", "political"),
    ("他和室友关系特别亲密，经常一起出去旅行", "sexual_orientation"),
    ("她从来没有交过男朋友", "sexual_orientation"),
    ("她怀孕了，下个月预产期", "gender"),
    ("他最近刚做了前列腺检查", "gender"),
    ("他出来后一直找不到工作", "criminal"),
    ("进门需要刷脸", "biometric"),
    ("今天天气不错", "none"),
    ("项目进度正常", "none"),
]

TYPE_ALIASES = {
    "医疗健康": "medical", "医疗": "medical", "健康": "medical", "health": "medical",
    "金融信息": "financial", "金融": "financial", "经济": "financial", "finance": "financial",
    "宗教信仰": "religion", "宗教": "religion", "faith": "religion",
    "政治观点": "political", "政治": "political", "politics": "political",
    "性取向": "sexual_orientation", "sexual": "sexual_orientation",
    "犯罪记录": "criminal", "犯罪": "criminal", "crime": "criminal",
    "生物特征": "biometric", "biometrics": "biometric",
    "性别": "gender", "sex": "gender",
    "民族": "ethnicity", "ethnic": "ethnicity",
}


def _normalize_type(t):
    return TYPE_ALIASES.get(t.lower().strip(), t.lower().strip())


def _query(text, model):
    resp = requests.post(OLLAMA_URL, json={
        "model": model,
        "prompt": f"文本：{text}",
        "system": SYSTEM_PROMPT,
        "stream": False,
        "options": {"temperature": 0.0},
    }, timeout=120)
    return resp.json().get("response", "[]")


def _parse(raw):
    try:
        if raw.strip().startswith("["):
            return json.loads(raw)
        start = raw.find("[")
        end = raw.rfind("]") + 1
        if start >= 0 and end > start:
            return json.loads(raw[start:end])
    except json.JSONDecodeError:
        pass
    return []


def _run_benchmark(model):
    results = []
    for text, expected in TEST_CASES:
        t0 = time.time()
        raw = _query(text, model)
        ms = (time.time() - t0) * 1000

        entities = _parse(raw)
        detected = [_normalize_type(e.get("type", "?")) for e in entities] if entities else []

        if expected == "none":
            ok = len(entities) == 0
        else:
            ok = expected in detected

        results.append({
            "text": text,
            "expected": expected,
            "detected": detected,
            "correct": ok,
            "ms": ms,
        })
    return results


def _check_ollama():
    try:
        requests.get("http://localhost:11434/api/tags", timeout=3)
        return True
    except Exception:
        return False


pytestmark = [pytest.mark.semantic, pytest.mark.slow]


@pytest.fixture(scope="module")
def ollama_available():
    if not _check_ollama():
        pytest.skip("Ollama not running")


class TestLayer3ModelBenchmark:
    """Benchmark implicit PII detection across models. Run with -s to see output."""

    @pytest.mark.parametrize("model", [
        "qwen2.5:3b", "qwen2.5:7b", "qwen2.5:32b",
        "qwen3:8b", "deepseek-r1:7b", "deepseek-r1:8b", "deepseek-r1:14b",
        "glm4:9b", "marco-o1:7b",
        "internlm2:7b", "yi:9b",
    ])
    def test_model_benchmark(self, ollama_available, model, capsys):
        # Check model is installed
        try:
            tags = requests.get("http://localhost:11434/api/tags", timeout=3).json()
            installed = [m["name"] for m in tags.get("models", [])]
            if not any(model in m for m in installed):
                pytest.skip(f"{model} not installed")
        except Exception:
            pytest.skip("Cannot check Ollama models")

        results = _run_benchmark(model)
        correct = sum(1 for r in results if r["correct"])
        total = len(results)
        avg_ms = sum(r["ms"] for r in results) / total

        with capsys.disabled():
            print(f"\n{'='*60}")
            print(f"  {model}: {correct}/{total} ({correct/total*100:.0f}%)  avg {avg_ms:.0f}ms")
            print(f"{'='*60}")
            for r in results:
                status = "✓" if r["correct"] else "✗"
                det = ", ".join(r["detected"])[:20] if r["detected"] else "—"
                print(f"  {status} {r['expected']:<20} got {det:<20} {r['ms']:.0f}ms")

        # At minimum, models should beat random (>20%) and not false-positive on negatives
        assert correct >= 3, f"{model} scored {correct}/{total}, below minimum threshold"
