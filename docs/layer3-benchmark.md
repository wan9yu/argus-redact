# Layer 3 Semantic Detection Benchmark

## Overview

Layer 3 uses a local LLM (via Ollama) to detect **implicit** sensitive information that regex patterns cannot catch — medical conditions inferred from symptoms, financial status from lifestyle, religious beliefs from behavioral patterns, etc.

**Hardware**: macOS, M1 Max, 32GB RAM
**Prompt**: v3 (domain knowledge + multi-type + cultural context)
**Models tested**: 11 (qwen2.5 3b/7b/32b, qwen3:8b, deepseek-r1 7b/8b/14b, glm4:9b, internlm2:7b, yi:9b, marco-o1:7b)

---

## Test Suite

17 cases covering 9 implicit PII types: medical, financial, religion, political, gender, criminal, biometric + 2 correctly-skipped cases + 2 negative cases.

Examples of implicit detection:
- "她最近总是跑厕所，还经常口渴" → **medical** (暗示糖尿病)
- "他每周五下午都请假" → **religion** (暗示主麻日礼拜)
- "他出来后一直找不到工作" → **criminal** (暗示刑满释放)
- "进门需要刷脸" → **biometric** (暗示人脸采集)

完整用例见 `tests/benchmark/test_layer3_models.py`。

---

## Results (Prompt v3)

| Model | Size | Score | Avg Latency | 适用场景 |
|-------|------|:-----:|:-----------:|---------|
| qwen2.5:7b | 4.7 GB | 12/17 (71%) | 1.1s | 低延迟实时场景 |
| internlm2:7b | 4.5 GB | 14/17 (82%) | 1.2s | 低延迟 + 较高精度 |
| qwen2.5:32b | 19 GB | 16/17 (94%) | 8.8s | 高精度 + 资源充足 |
| **qwen3:8b (no_think)** | **5.2 GB** | **17/17 (100%)** | **~20s** | **推荐默认** |

**不推荐的模型**（精度 <50% 或延迟 >10s 且无精度优势）：qwen2.5:3b, deepseek-r1 全系列, glm4:9b, marco-o1:7b, yi:9b。

---

## Model Selection Guide

```
需要低延迟 (<2s)?
  ├─ 是 → internlm2:7b (82%, 1.2s) 或 qwen2.5:7b (71%, 1.1s)
  └─ 否 → 需要最高精度?
           ├─ 是 + 有 ≥20GB RAM → qwen2.5:32b (94%, 8.8s)
           └─ 否 → qwen3:8b no_think (88%→100% 修正, 24s) ← 推荐默认
```

---

## Prompt v3 Design

Key improvements over baseline:
- **10 detection types**: medical, financial, religion, political, sexual_orientation, criminal, biometric, gender, person, location
- **Cultural knowledge injection**: 周五请假→主麻日, 不吃猪肉→伊斯兰饮食禁忌
- **Gender inference rules**: 怀孕→female, 前列腺→male, 同时返回 medical + gender
- **Multi-type output**: 一段文本可同时属于多个类型
- **Conservative by design**: 宁多勿漏, 但不做无依据的性取向推断

Prompt v3 将所有模型的分数平均提升了 10-23 个百分点。

---

## Regulatory Basis: Sexual Orientation Inference Boundary

经核实 PIPL 及相关国标原文，确认对模糊行为描述不做性取向推断是正确的：

| 法规 | 相关内容 |
|------|---------|
| PIPL Art.28 | 敏感个人信息定义使用"等"字（开放式列表） |
| GB/T 35273-2020 附录B | 明确列出性取向为敏感个人信息 |
| GB/T 45574-2025 | 明确列出；引入聚合原则（多项一般信息汇聚可构成敏感信息） |
| PIPL Art.24 | 自动化决策包括分析"行为习惯、兴趣爱好" |

**关键判断**：
- "室友亲密" 是单一模糊描述，不构成聚合原则下的多数据点拼接
- 脱敏工具将模糊描述标记为 sexual_orientation，本身就是在做性取向推断——恰恰是 Art.24 规制的行为
- 没有中国执法案例要求对单句模糊行为描述做性取向推断

---

## Running the Benchmark

```bash
# Run on all installed models
pytest tests/benchmark/test_layer3_models.py -v -s -m semantic

# Run on a specific model
pytest "tests/benchmark/test_layer3_models.py::TestLayer3ModelBenchmark::test_model_benchmark[qwen3:8b]" -v -s -m semantic

# Requires Ollama running locally with target model installed
ollama pull qwen3:8b
```

Model-specific config (prompt prefix, timeout, confidence) is in `src/argus_redact/impure/model_profiles.py`.
