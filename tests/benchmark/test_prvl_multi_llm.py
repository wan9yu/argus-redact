"""PRvL Multi-LLM Benchmark — test pseudonym survival across GPT-4o, Claude, Gemini.

Uses Poe API (OpenAI-compatible) to access multiple LLMs.
Requires: POE_API_KEY environment variable.

Run: pytest tests/benchmark/test_prvl_multi_llm.py -v -s -m semantic
"""

import json
import os
import time

import pytest

HAS_HTTPX = True
try:
    import httpx
except ImportError:
    HAS_HTTPX = False

from argus_redact import redact, restore

POE_API_URL = "https://api.poe.com/v1/chat/completions"

# Models to test via Poe
MODELS = [
    "GPT-4o",
    "Claude-3.7-Sonnet",
    "Gemini-2.0-Flash",
]

# Test prompts (same as test_prvl.py LLM_PROMPTS but streamlined)
TEST_CASES = [
    {
        "id": "summarize_zh",
        "text": "张三的手机号是13812345678，他在北京市朝阳区建国路100号工作，确诊高血压",
        "prompt": "请用一句话总结以下信息：{text}",
        "lang": "zh",
        "pii": ["13812345678", "高血压"],
    },
    {
        "id": "translate_zh_en",
        "text": "客户李明，手机13912345678，邮箱li@test.com，在腾讯公司工作",
        "prompt": "Translate to English: {text}",
        "lang": "zh",
        "pii": ["13912345678", "li@test.com"],
    },
    {
        "id": "qa_en",
        "text": "John Smith, SSN 123-45-6789, works at Google, diagnosed with diabetes",
        "prompt": "Based on the following info, what health condition does this person have? {text}",
        "lang": "en",
        "pii": ["123-45-6789"],
    },
    {
        "id": "advice_zh",
        "text": "患者王五，35岁，确诊糖尿病，月薪2万元，住在朝阳区",
        "prompt": "基于以下患者信息，给出简短健康建议（50字以内）：{text}",
        "lang": "zh",
        "pii": ["糖尿病", "月薪2万元"],
    },
]


def _get_poe_key():
    key = os.environ.get("POE_API_KEY", "")
    if not key:
        # Try reading from zshrc
        try:
            for line in open(os.path.expanduser("~/.zshrc")):
                if "POE_API_KEY=" in line and not line.strip().startswith("#"):
                    key = line.split("=", 1)[1].strip().strip('"').strip("'")
                    break
        except FileNotFoundError:
            pass
    return key


def _query_poe(prompt: str, model: str, api_key: str) -> str:
    resp = httpx.post(
        POE_API_URL,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json={
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0,
        },
        timeout=60,
    )
    if resp.status_code != 200:
        return f"[ERROR {resp.status_code}]"
    data = resp.json()
    return data["choices"][0]["message"]["content"]


pytestmark = [pytest.mark.semantic, pytest.mark.slow]


@pytest.fixture(scope="module")
def poe_key():
    if not HAS_HTTPX:
        pytest.skip("httpx not installed")
    key = _get_poe_key()
    if not key:
        pytest.skip("POE_API_KEY not set")
    # Verify connectivity
    try:
        resp = httpx.post(
            POE_API_URL,
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            json={"model": "GPT-4o", "messages": [{"role": "user", "content": "hi"}], "temperature": 0},
            timeout=10,
        )
        if resp.status_code != 200:
            pytest.skip(f"Poe API returned {resp.status_code}")
    except Exception as e:
        pytest.skip(f"Poe API unreachable: {e}")
    return key


class TestPRvLMultiLLM:
    """Test pseudonym survival and PII leak across GPT-4o, Claude, Gemini."""

    @pytest.mark.parametrize("model", MODELS)
    def test_pseudonym_survival(self, poe_key, model, capsys):
        survived = 0
        total = 0
        details = []

        for case in TEST_CASES:
            redacted, key = redact(case["text"], mode="fast", lang=case["lang"], seed=42)
            prompt = case["prompt"].format(text=redacted)

            t0 = time.time()
            llm_output = _query_poe(prompt, model, poe_key)
            ms = (time.time() - t0) * 1000

            case_survived = 0
            case_total = len(key)
            for replacement in key.keys():
                total += 1
                if replacement in llm_output:
                    survived += 1
                    case_survived += 1

            details.append({
                "id": case["id"],
                "survived": f"{case_survived}/{case_total}",
                "lost": [r for r in key.keys() if r not in llm_output],
                "ms": ms,
            })

        rate = survived / total if total else 0

        with capsys.disabled():
            print(f"\n  {'='*60}")
            print(f"  {model}: pseudonym survival {rate:.0%} ({survived}/{total})")
            print(f"  {'='*60}")
            for d in details:
                lost = d["lost"]
                status = "✓" if not lost else f"✗ lost: {lost}"
                print(f"  {d['id']}: {d['survived']} {status} ({d['ms']:.0f}ms)")

        assert rate >= 0.5, f"{model} survival rate {rate:.0%} below 50%"

    @pytest.mark.parametrize("model", MODELS)
    def test_pii_not_leaked(self, poe_key, model, capsys):
        leaked_total = 0
        pii_total = 0
        details = []

        for case in TEST_CASES:
            redacted, key = redact(case["text"], mode="fast", lang=case["lang"], seed=42)
            prompt = case["prompt"].format(text=redacted)
            llm_output = _query_poe(prompt, model, poe_key)

            leaked = [p for p in case["pii"] if p in llm_output]
            leaked_total += len(leaked)
            pii_total += len(case["pii"])
            details.append({"id": case["id"], "leaked": leaked})

        rate = leaked_total / pii_total if pii_total else 0

        with capsys.disabled():
            print(f"\n  {model}: PII leak rate {rate:.0%} ({leaked_total}/{pii_total})")
            for d in details:
                status = "✓ clean" if not d["leaked"] else f"✗ leaked: {d['leaked']}"
                print(f"  {d['id']}: {status}")

        assert rate <= 0.3, f"{model} PII leak rate {rate:.0%} above 30%"

    @pytest.mark.parametrize("model", MODELS)
    def test_llm_produces_useful_response(self, poe_key, model, capsys):
        empty = 0
        details = []

        for case in TEST_CASES:
            redacted, key = redact(case["text"], mode="fast", lang=case["lang"], seed=42)
            prompt = case["prompt"].format(text=redacted)
            llm_output = _query_poe(prompt, model, poe_key)

            is_empty = len(llm_output.strip()) < 10
            if is_empty:
                empty += 1
            details.append({"id": case["id"], "length": len(llm_output), "empty": is_empty})

        with capsys.disabled():
            print(f"\n  {model}: response quality")
            for d in details:
                status = "✓" if not d["empty"] else "✗ empty"
                print(f"  {d['id']}: {d['length']} chars {status}")

        assert empty == 0, f"{model}: {empty}/{len(TEST_CASES)} empty responses"
