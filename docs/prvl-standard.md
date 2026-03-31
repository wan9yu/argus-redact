# PRvL: Privacy-Reversibility-Language Evaluation Standard

**Version 1.0** · argus-redact project · 2026

## What is PRvL?

PRvL (pronounced "prevail") is an open evaluation framework for PII redaction tools used with Large Language Models. It measures three axes that matter to real users:

- **P (Privacy):** Does redacted text leak PII?
- **R (Reversibility):** Can you restore original identities after LLM processing?
- **L (Language/Usability):** Does the LLM still understand and produce useful output?

Traditional evaluation only measures detection accuracy (precision/recall/F1). PRvL measures **what happens after detection** — the full redact → LLM → restore pipeline.

---

## Why PRvL?

Existing PII tools report F1 scores, but users care about different questions:

| What tools measure | What users need to know |
|-------------------|------------------------|
| "We detect 95% of phone numbers" | "Will my phone number appear in ChatGPT's response?" |
| "F1=0.97 on benchmark X" | "Can AI still help me after my data is encrypted?" |
| "Supports 50 PII types" | "Can I get my original data back after AI processes it?" |

PRvL answers the user's questions, not the developer's.

---

## Three Axes

### P — Privacy (0-100%)

**Question:** Does PII from the original text appear in the LLM's response?

**Measurement:**
1. Redact a text containing known PII
2. Send the redacted text to an LLM with a task prompt
3. Check if any original PII strings appear in the LLM's response

```
P = 1 - (PII tokens found in LLM output / total PII tokens in original)
```

**Target:** P ≥ 99%. Any PII leak is a failure.

### U — Usability (0-100%)

**Question:** Does the LLM still understand the redacted text?

**Measurement:**
1. Redact a text
2. Check that non-PII semantic tokens (verbs, context words) survive redaction
3. Optionally: compare LLM response quality before/after redaction

```
U = semantic tokens preserved in redacted text / total semantic tokens
```

**Target:** U ≥ 95%. Trigger words like "diagnosed", "salary", "住在" must survive.

**Key principle:** Only the PII content should be redacted, not the surrounding context. "确诊糖尿病" → "确诊MED-51675" (✓) not "MED-51675" (✗).

### R — Reversibility (0-100%, per task type)

**Question:** Do pseudonym tokens survive LLM processing so restore() works?

**Measurement:**
1. Redact a text (producing pseudonyms like P-83811, MED-51675)
2. Send to LLM with a specific task
3. Check how many pseudonyms appear in the LLM's response

```
R = pseudonym tokens in LLM output / total pseudonym tokens in redacted text
```

**Critical insight:** R depends on task type, not tool quality:

| Task Type | Example | Expected R | Why |
|-----------|---------|:----------:|-----|
| **Reference** | Summarize, translate | ≥ 90% | LLM must reference original tokens |
| **Extract** | QA, data extraction | ≥ 50% | LLM answers questions, may not quote |
| **Creative** | Advice, writing | ~0% | LLM generates new content, doesn't quote |

**A tool should NOT be penalized for low R on creative tasks.** When you ask "give health advice for MED-51675", the LLM correctly says "manage your diet" without repeating MED-51675.

---

## Test Methodology

### Minimum test corpus

A PRvL evaluation requires at least:
- 10 texts with known PII across multiple types (L1 direct identifiers + L3 sensitive attributes)
- 4 task prompts covering reference, extract, and creative tasks
- 3 LLMs (at least 1 commercial + 1 open-source)

### Test protocol

```
For each (text, task_prompt, llm) combination:
  1. redacted, key = redact(text)
  2. prompt = task_prompt.format(text=redacted)
  3. llm_output = query_llm(prompt)
  4. restored = restore(llm_output, key)
  5. Measure P: count PII tokens in llm_output
  6. Measure U: count semantic tokens in redacted
  7. Measure R: count pseudonym tokens in llm_output
```

### Reporting format

PRvL scores should be reported as:

```
PRvL v1.0 Evaluation
Tool: [name] v[version]
Date: [date]
Corpus: [N] texts, [M] task prompts

Fast Mode (no LLM):
  P = [score]%
  U = [score]%
  R = [score]% (direct restore)

Through-LLM (per model):
  [Model Name]:
    P = [score]%
    R-reference = [score]%
    R-extract = [score]%
    R-creative = [score]%
    Response quality: [pass/fail]
```

---

## Scoring Thresholds

| Level | P | U | R-reference | Description |
|-------|:-:|:-:|:-----------:|-------------|
| **Gold** | 100% | ≥ 98% | ≥ 90% | Production-ready for sensitive data |
| **Silver** | ≥ 99% | ≥ 90% | ≥ 70% | Suitable for most use cases |
| **Bronze** | ≥ 95% | ≥ 80% | ≥ 50% | Minimum viable protection |
| **Fail** | < 95% | < 80% | < 50% | Not recommended |

R-extract and R-creative are informational only, not part of the grade.

---

## Reference Implementation

The reference PRvL benchmark is implemented in argus-redact:

```bash
# Fast PRvL (no LLM required)
pytest tests/benchmark/test_prvl.py -v -s

# Through-LLM PRvL (requires Ollama)
pytest tests/benchmark/test_prvl.py -v -s -m semantic

# Multi-LLM PRvL (requires Poe API key)
export POE_API_KEY=your_key
pytest tests/benchmark/test_prvl_multi_llm.py -v -s -m semantic
```

Source code: `tests/benchmark/test_prvl.py`, `tests/benchmark/test_prvl_multi_llm.py`

---

## argus-redact v0.1.13 Results

### Fast Mode

| Axis | Score | Grade |
|------|:-----:|:-----:|
| P (Privacy) | 100% | Gold |
| U (Usability) | 100% | Gold |
| R (Direct restore) | 100% | Gold |

### Through-LLM

| Model | P | R-reference | R-extract | R-creative |
|-------|:-:|:-----------:|:---------:|:----------:|
| GPT-4o | 100% | 100% | 50% | 0% |
| Claude-3.7-Sonnet | 100% | 100% | 50% | 0% |
| Gemini-2.0-Flash | 100% | 100% | 0% | 0% |
| qwen3:8b (local) | 86% | 100% | 50% | 0% |

**Overall Grade: Gold** (P=100%, U=100%, R-reference=100%)

---

## Design Principles

1. **Measure what users care about**, not what's easy to measure
2. **Task-aware evaluation** — don't penalize correct LLM behavior
3. **Multi-LLM testing** — results vary significantly across models
4. **Reproducible** — all tests are automated with fixed seeds
5. **Open** — anyone can run the benchmark on their own tool

---

## Contributing

PRvL is an open standard. To propose changes:
- Open an issue at [argus-redact/issues](https://github.com/wan9yu/argus-redact/issues)
- Tag with `prvl-standard`
- Include rationale and test data supporting the change

---

## Citation

```
@standard{prvl2026,
  title={PRvL: Privacy-Reversibility-Language Evaluation Standard for PII Redaction},
  author={argus-redact project},
  year={2026},
  version={1.0},
  url={https://github.com/wan9yu/argus-redact/blob/main/docs/prvl-standard.md}
}
```
