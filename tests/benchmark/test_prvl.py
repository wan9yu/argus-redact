"""PRvL Three-Axis Benchmark — Privacy, Reversibility, Language (Usability).

Measures the Three Promises quantitatively:
  P (Protected)  — PII leak rate after redaction
  R (Reversible) — restore completeness after direct restore AND through LLM
  U (Usable)     — semantic token survival after redaction

Run:
  pytest tests/benchmark/test_prvl.py -v -s                      # fast (no LLM)
  pytest tests/benchmark/test_prvl.py -v -s -m "semantic"         # with LLM
"""

import importlib.util

import pytest

from argus_redact import redact, restore

# ── Test corpus ──
# Covers all PII levels: L1 direct identifiers, L2 quasi-identifiers,
# L3 sensitive attributes, L4 digital identifiers, mixed languages.

BENCHMARK_TEXTS = [
    # L1: Direct identifiers (zh)
    {
        "id": "zh_multi_pii",
        "text": "张三的手机号是13812345678，身份证110101199003074610，邮箱zhang@test.com",
        "pii": ["13812345678", "110101199003074610", "zhang@test.com"],
        "semantic_tokens": ["手机号", "身份证", "邮箱"],
        "lang": "zh",
    },
    {
        "id": "zh_address_bank",
        "text": "王五住在北京市朝阳区建国路100号，银行卡6222021234567890123",
        "pii": ["6222021234567890123"],
        "semantic_tokens": ["住在", "银行卡"],
        "lang": "zh",
    },
    # L1: Direct identifiers (en)
    {
        "id": "en_ssn_phone",
        "text": "John Smith, SSN 123-45-6789, phone (555) 123-4567, email john@test.com",
        "pii": ["123-45-6789", "john@test.com"],
        "semantic_tokens": ["phone", "email"],
        "lang": "en",
    },
    # L2: Quasi-identifiers
    {
        "id": "zh_quasi",
        "text": "患者35岁，男性，就职于华为技术，骨科医生建议休息",
        "pii": ["35岁", "男性"],
        "semantic_tokens": ["患者", "建议", "休息"],
        "lang": "zh",
    },
    # L3: Sensitive attributes
    {
        "id": "zh_sensitive",
        "text": "他是党员，确诊糖尿病，月薪2万元，民族：回族",
        "pii": ["党员", "糖尿病", "月薪2万元"],
        "semantic_tokens": ["确诊"],
        "lang": "zh",
    },
    # L3: English sensitive
    {
        "id": "en_sensitive",
        "text": "diagnosed with diabetes, salary $120,000, registered Democrat",
        "pii": ["diabetes", "$120,000"],
        "semantic_tokens": ["diagnosed", "salary"],
        "lang": "en",
    },
    # Mixed zh+en
    {
        "id": "mixed_zh_en",
        "text": "张三，身份证110101199003074610，diagnosed with hypertension，月薪3万元",
        "pii": ["110101199003074610", "hypertension", "月薪3万元"],
        "semantic_tokens": ["身份证", "diagnosed"],
        "lang": ["zh", "en"],
    },
    # L4: Digital identifiers
    {
        "id": "zh_digital",
        "text": "服务器IP是192.168.1.100，MAC地址AA:BB:CC:DD:EE:FF",
        "pii": ["192.168.1.100", "AA:BB:CC:DD:EE:FF"],
        "semantic_tokens": ["服务器", "MAC地址"],
        "lang": "zh",
    },
    # Negative: no PII
    {
        "id": "no_pii",
        "text": "今天天气不错，项目进度正常，下周可以交付",
        "pii": [],
        "semantic_tokens": ["天气", "项目", "交付"],
        "lang": "zh",
    },
    # Complex: multiple types in one text
    {
        "id": "zh_complex",
        "text": "客户李明，手机13912345678，在腾讯公司工作，确诊高血压，信用评分720分",
        "pii": ["13912345678", "高血压", "信用评分720分"],
        "semantic_tokens": ["客户", "工作"],
        "lang": "zh",
    },
]


def _compute_prvl(texts: list[dict], mode: str = "fast"):
    """Compute PRvL three-axis scores."""
    privacy_scores = []
    reversibility_scores = []
    language_scores = []
    details = []

    for item in texts:
        lang = item["lang"]
        redacted, key = redact(item["text"], mode=mode, lang=lang, seed=42)

        # P: Privacy — PII should NOT be in redacted text
        if item["pii"]:
            pii_leaked = sum(1 for p in item["pii"] if p in redacted)
            privacy = 1.0 - (pii_leaked / len(item["pii"]))
        else:
            privacy = 1.0
        privacy_scores.append(privacy)

        # R: Reversibility — restore should recover PII
        restored = restore(redacted, key)
        if item["pii"]:
            pii_recovered = sum(1 for p in item["pii"] if p in restored)
            reversibility = pii_recovered / len(item["pii"])
        else:
            reversibility = 1.0
        reversibility_scores.append(reversibility)

        # U: Language/Usability — semantic tokens must survive redaction
        if item["semantic_tokens"]:
            tokens_preserved = sum(1 for t in item["semantic_tokens"] if t in redacted)
            language = tokens_preserved / len(item["semantic_tokens"])
        else:
            language = 1.0
        language_scores.append(language)

        details.append({
            "id": item["id"],
            "privacy": privacy,
            "reversibility": reversibility,
            "language": language,
            "leaked": [p for p in item["pii"] if p in redacted],
            "not_recovered": [p for p in item["pii"] if p not in restored],
            "tokens_lost": [t for t in item["semantic_tokens"] if t not in redacted],
        })

    def avg(scores):
        return sum(scores) / len(scores) if scores else 0

    return {
        "privacy": avg(privacy_scores),
        "reversibility": avg(reversibility_scores),
        "language": avg(language_scores),
        "details": details,
    }


class TestPRvLBenchmark:
    """Fast PRvL benchmark — no LLM required."""

    def test_should_achieve_high_privacy(self):
        scores = _compute_prvl(BENCHMARK_TEXTS)

        print(f"\n  PRvL Privacy (P):       {scores['privacy']:.2%}")
        print(f"  PRvL Reversibility (R): {scores['reversibility']:.2%}")
        print(f"  PRvL Language (U):      {scores['language']:.2%}")

        # Report failures
        for d in scores["details"]:
            if d["leaked"]:
                print(f"  ⚠ {d['id']}: leaked {d['leaked']}")
            if d["not_recovered"]:
                print(f"  ⚠ {d['id']}: not recovered {d['not_recovered']}")
            if d["tokens_lost"]:
                print(f"  ⚠ {d['id']}: tokens lost {d['tokens_lost']}")

        assert scores["privacy"] >= 0.9, f"Privacy score {scores['privacy']:.2%} below 90%"

    def test_should_achieve_full_reversibility(self):
        scores = _compute_prvl(BENCHMARK_TEXTS)
        assert scores["reversibility"] == 1.0, (
            f"Reversibility {scores['reversibility']:.2%} — "
            f"failures: {[d for d in scores['details'] if d['not_recovered']]}"
        )

    def test_should_preserve_language(self):
        scores = _compute_prvl(BENCHMARK_TEXTS)
        # Current baseline: 70%. Target: ≥85% (requires pattern refinement
        # to avoid consuming semantic trigger words like 确诊/diagnosed/salary)
        assert scores["language"] >= 0.65, (
            f"Language score {scores['language']:.2%} — "
            f"tokens lost: {[d for d in scores['details'] if d['tokens_lost']]}"
        )


# ── LLM-through tests (require Ollama) ──

HAS_REQUESTS = importlib.util.find_spec("requests") is not None

LLM_PROMPTS = [
    {
        "id": "summarize_zh",
        "text": "张三的手机号是13812345678，他在北京市朝阳区建国路100号工作，确诊高血压",
        "prompt_template": "请用一句话总结以下信息：{text}",
        "lang": "zh",
        "pii": ["13812345678", "高血压"],
    },
    {
        "id": "translate_zh_en",
        "text": "客户李明，手机13912345678，邮箱li@test.com，在腾讯公司工作",
        "prompt_template": "Translate to English: {text}",
        "lang": "zh",
        "pii": ["13912345678", "li@test.com"],
    },
    {
        "id": "qa_en",
        "text": "John Smith, SSN 123-45-6789, works at Google, diagnosed with diabetes",
        "prompt_template": "Based on the following info, what health condition does this person have? {text}",
        "lang": "en",
        "pii": ["123-45-6789"],
    },
    {
        "id": "advice_zh",
        "text": "患者王五，35岁，确诊糖尿病，月薪2万元，住在朝阳区",
        "prompt_template": "基于以下患者信息，给出健康建议：{text}",
        "lang": "zh",
        "pii": ["糖尿病", "月薪2万元"],
    },
]


def _check_ollama():
    if not HAS_REQUESTS:
        return False
    try:
        import requests
        requests.get("http://localhost:11434/api/tags", timeout=3)
        return True
    except Exception:
        return False


def _query_llm(prompt, model="qwen3:8b"):
    import requests
    from argus_redact.impure.model_profiles import get_model_profile
    profile = get_model_profile(model)
    resp = requests.post("http://localhost:11434/api/generate", json={
        "model": model,
        "prompt": f"{profile.prompt_prefix}{prompt}",
        "stream": False,
        "options": {"temperature": 0.0},
    }, timeout=profile.timeout)
    return resp.json().get("response", "")


@pytest.mark.semantic
@pytest.mark.slow
class TestReversibilityThroughLLM:
    """Test pseudonym survival rate when text passes through an LLM."""

    @pytest.fixture(autouse=True)
    def _skip_if_no_ollama(self):
        if not _check_ollama():
            pytest.skip("Ollama not running")

    def test_pseudonym_survival_rate(self, capsys):
        """Redact → LLM → restore: do pseudonyms survive?"""
        survived = 0
        total_pseudonyms = 0
        details = []

        for item in LLM_PROMPTS:
            redacted, key = redact(item["text"], mode="fast", lang=item["lang"], seed=42)

            # Build prompt with redacted text
            prompt = item["prompt_template"].format(text=redacted)

            # Send to LLM
            llm_output = _query_llm(prompt)

            # Try to restore
            restored_output = restore(llm_output, key)

            # Count pseudonym survival
            for replacement in key.keys():
                total_pseudonyms += 1
                if replacement in llm_output:
                    survived += 1

            details.append({
                "id": item["id"],
                "pseudonyms_in_key": list(key.keys()),
                "survived_in_llm": [r for r in key.keys() if r in llm_output],
                "lost_in_llm": [r for r in key.keys() if r not in llm_output],
            })

        survival_rate = survived / total_pseudonyms if total_pseudonyms else 0

        with capsys.disabled():
            print(f"\n  Pseudonym survival rate: {survival_rate:.0%} ({survived}/{total_pseudonyms})")
            for d in details:
                lost = d["lost_in_llm"]
                status = "✓" if not lost else f"✗ lost: {lost}"
                print(f"  {d['id']}: {status}")

        # Baseline: 86%. All entities now use pseudonym-style codes (MED-XXXXX).
        # Remaining losses are LLM omissions in summaries, not format issues.
        assert survival_rate >= 0.7, (
            f"Pseudonym survival rate {survival_rate:.0%} below 70% — "
            f"details: {details}"
        )

    def test_pii_not_leaked_through_llm(self, capsys):
        """PII in original text should NOT appear in LLM output."""
        leaked_count = 0
        total_pii = 0
        details = []

        for item in LLM_PROMPTS:
            redacted, key = redact(item["text"], mode="fast", lang=item["lang"], seed=42)

            prompt = item["prompt_template"].format(text=redacted)
            llm_output = _query_llm(prompt)

            leaked = [p for p in item["pii"] if p in llm_output]
            leaked_count += len(leaked)
            total_pii += len(item["pii"])
            details.append({"id": item["id"], "leaked": leaked})

        leak_rate = leaked_count / total_pii if total_pii else 0

        with capsys.disabled():
            print(f"\n  PII leak rate through LLM: {leak_rate:.0%} ({leaked_count}/{total_pii})")
            for d in details:
                status = "✓ clean" if not d["leaked"] else f"✗ leaked: {d['leaked']}"
                print(f"  {d['id']}: {status}")

        # Baseline: 14% (1/7). LLM inferred 糖尿病 from context despite redaction.
        # This is a fundamental LLM capability — mitigating requires obscuring context too.
        assert leak_rate <= 0.2, (
            f"PII leaked through LLM: {leaked_count}/{total_pii} — {details}"
        )


@pytest.mark.semantic
@pytest.mark.slow
class TestUsabilityThroughLLM:
    """Test that LLM can still produce useful output from redacted text."""

    @pytest.fixture(autouse=True)
    def _skip_if_no_ollama(self):
        if not _check_ollama():
            pytest.skip("Ollama not running")

    def test_llm_produces_nonempty_response(self, capsys):
        """LLM should produce meaningful (non-empty) responses from redacted text."""
        empty_responses = 0
        details = []

        for item in LLM_PROMPTS:
            redacted, key = redact(item["text"], mode="fast", lang=item["lang"], seed=42)
            prompt = item["prompt_template"].format(text=redacted)
            llm_output = _query_llm(prompt)

            is_empty = len(llm_output.strip()) < 10
            if is_empty:
                empty_responses += 1
            details.append({
                "id": item["id"],
                "output_length": len(llm_output),
                "empty": is_empty,
            })

        with capsys.disabled():
            print(f"\n  LLM response quality:")
            for d in details:
                status = "✓" if not d["empty"] else "✗ empty"
                print(f"  {d['id']}: {d['output_length']} chars {status}")

        assert empty_responses == 0, (
            f"{empty_responses}/{len(LLM_PROMPTS)} empty LLM responses — {details}"
        )
