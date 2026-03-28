# Layer 3 Semantic Detection Benchmark

## Overview

Layer 3 uses a local LLM (via Ollama) to detect **implicit** sensitive information that regex patterns cannot catch. This document records benchmark results across models.

**Test date**: 2026-03-28
**Test setup**: macOS, M1 Max, Ollama local

---

## Test Cases (17 total)

15 positive cases (implicit PII) + 2 negative cases (no PII).

| # | Input | Expected Type | Description |
|---|-------|:------------:|-------------|
| 1 | 她最近总是跑厕所，还经常口渴 | medical | 暗示糖尿病症状 |
| 2 | 他每天要吃好几种药片 | medical | 暗示长期服药 |
| 3 | 自从上次住院回来他瘦了很多 | medical | 暗示住院/疾病 |
| 4 | 他最近经济压力很大，房子快要断供了 | financial | 暗示财务困难/断供 |
| 5 | 她开的是保时捷，住在汤臣一品 | financial | 暗示高收入 |
| 6 | 他每周五下午都请假 | religion | 可能暗示主麻日礼拜 |
| 7 | 她不吃猪肉，斋月期间白天不进食 | religion | 暗示穆斯林 |
| 8 | 他的立场比较偏左 | political | 暗示政治倾向 |
| 9 | 她经常在网上发表对政策的不满 | political | 暗示政治观点 |
| 10 | 他和室友关系特别亲密，经常一起出去旅行 | sexual_orientation | 可能暗示同性关系 |
| 11 | 她从来没有交过男朋友 | sexual_orientation | 可能暗示 |
| 12 | 她怀孕了，下个月预产期 | gender | 暗示女性 |
| 13 | 他最近刚做了前列腺检查 | gender | 暗示男性 |
| 14 | 他出来后一直找不到工作 | criminal | 可能暗示刑满释放 |
| 15 | 进门需要刷脸 | biometric | 暗示人脸采集 |
| 16 | 今天天气不错 | none | 无隐私信息 |
| 17 | 项目进度正常 | none | 无隐私信息 |

---

## Results

### qwen2.5:3b (1.9 GB)

| Metric | Value |
|--------|-------|
| **Score** | **6/17 (35%)** |
| **Avg latency** | 304ms |
| **Detection pattern** | 只能检测显式程度较高的医疗/金融场景 |

**Detail:**

| # | Input | Expected | Detected | Result |
|---|-------|----------|----------|:------:|
| 1 | 总是跑厕所，经常口渴 | medical | medical | ✓ |
| 2 | 每天吃好几种药片 | medical | medical | ✓ |
| 3 | 住院回来瘦了很多 | medical | medical | ✓ |
| 4 | 经济压力大，房子断供 | financial | financial | ✓ |
| 5 | 保时捷，汤臣一品 | financial | — | ✗ |
| 6 | 每周五请假 | religion | — | ✗ |
| 7 | 不吃猪肉，斋月不进食 | religion | — | ✗ |
| 8 | 立场偏左 | political | — | ✗ |
| 9 | 发表对政策不满 | political | — | ✗ |
| 10 | 室友亲密，一起旅行 | sexual_orientation | — | ✗ |
| 11 | 没交过男朋友 | sexual_orientation | — | ✗ |
| 12 | 怀孕，预产期 | gender | — | ✗ |
| 13 | 前列腺检查 | gender | medical | ✗ |
| 14 | 出来后找不到工作 | criminal | — | ✗ |
| 15 | 进门刷脸 | biometric | — | ✗ |
| 16 | 天气不错 | none | none | ✓ |
| 17 | 项目进度正常 | none | none | ✓ |

**结论**：3b 仅能检测症状明显的医疗和直接的财务压力。对宗教、政治、性取向、犯罪等需要深层推理的场景完全无能力。不适合作为 Layer 3 的主力模型。

---

### qwen2.5:32b (19 GB)

| Metric | Value |
|--------|-------|
| **Score** | **12/17 (71%)** |
| **Avg latency** | 5,648ms |
| **Detection pattern** | 医疗/金融/宗教/政治/性取向/生物特征均可检测，性别/犯罪推断仍弱 |

**Detail:**

| # | Input | Expected | Detected | Result |
|---|-------|----------|----------|:------:|
| 1 | 总是跑厕所，经常口渴 | medical | medical | ✓ |
| 2 | 每天吃好几种药片 | medical | medical | ✓ |
| 3 | 住院回来瘦了很多 | medical | medical | ✓ |
| 4 | 经济压力大，房子断供 | financial | financial | ✓ |
| 5 | 保时捷，汤臣一品 | financial | financial | ✓ |
| 6 | 每周五请假 | religion | — | ✗ |
| 7 | 不吃猪肉，斋月不进食 | religion | religion | ✓ |
| 8 | 立场偏左 | political | political | ✓ |
| 9 | 发表对政策不满 | political | political | ✓ |
| 10 | 室友亲密，一起旅行 | sexual_orientation | — | ✗ |
| 11 | 没交过男朋友 | sexual_orientation | sexual_orientation | ✓ |
| 12 | 怀孕，预产期 | gender | — | ✗ |
| 13 | 前列腺检查 | gender | medical | ✗ |
| 14 | 出来后找不到工作 | criminal | — | ✗ |
| 15 | 进门刷脸 | biometric | biometric | ✓ |
| 16 | 天气不错 | none | none | ✓ |
| 17 | 项目进度正常 | none | none | ✓ |

**结论**：32b 在大部分隐式场景表现良好，但对极度隐含的场景（每周五请假→宗教、出来后找不到工作→犯罪）仍然保守。性别推断弱——将"怀孕"和"前列腺检查"归类为医疗而非性别。

---

## Failure Analysis

### 两个模型都失败的 5 个 case:

| Case | 原因 | 改进方向 |
|------|------|---------|
| 每周五请假 → 宗教 | 推断链太长（请假→周五→主麻日→穆斯林），需要文化知识 | 领域 prompt 补充宗教日历知识 |
| 怀孕 → 性别 | 模型将其归类为医疗而非性别（两者都合理） | prompt 明确指示：怀孕=gender+medical |
| 前列腺检查 → 性别 | 同上，归类为医疗 | prompt 补充性别推断规则 |
| 出来后找不到工作 → 犯罪 | "出来"太隐晦，多义词 | 可能需要更强的上下文理解，或者接受此类极端隐含场景的漏检 |
| 室友亲密 → 性取向 | 32b 正确地保守——亲密不等于性关系 | 可接受的 false negative |

---

## Multi-Model Comparison

All models tested on same 17 cases, same prompt, temperature=0.0.

| Model | Size | Score | Avg Latency | Notes |
|-------|------|:-----:|:-----------:|-------|
| qwen2.5:3b | 1.9 GB | 6/17 (35%) | 435ms | 只抓显式医疗/金融 |
| **qwen2.5:7b** | 4.7 GB | **11/17 (65%)** | **902ms** | **性价比最佳** |
| deepseek-r1:7b | 4.7 GB | 7/17 (41%) | 11,733ms | 链式推理太慢，JSON 输出不稳定 |
| glm4:9b | 5.5 GB | 8/17 (47%) | 1,025ms | 中规中矩 |
| qwen2.5:32b | 19 GB | 12/17 (71%) | 5,648ms | 最准但资源需求高 |

### Key Findings

- **qwen2.5:7b 是推荐默认模型**：65% 准确率 + <1s 延迟，实用性最强
- deepseek-r1 的 chain-of-thought 在结构化输出任务上反而是劣势（thinking tokens 干扰 JSON）
- glm4 中文能力不错但隐式推理弱于 qwen2.5 同尺寸
- 32b 仅在需要最高精度且延迟可接受时使用

---

## Recommendations

1. **默认模型推荐 qwen2.5:7b**：65% 检测率 + <1s 延迟，适合生产部署
2. **高精度场景用 32b**：71% 检测率，5.6s 延迟在异步/批处理可接受
3. **3b 仅适合快速预筛**：35% 太低，不建议做主力
4. **Prompt 优化空间大**：通过领域知识注入（宗教日历、性别推断规则）可提升 7b 到 75%+
5. **极端隐含场景**（"出来后"→犯罪）可能需要多轮推理或更大模型
