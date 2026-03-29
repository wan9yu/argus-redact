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

All models tested on same 17 cases, same prompt, temperature=0.0. Hardware: M1 Max, 32GB RAM.

| Model | Size | Score | Avg Latency | Notes |
|-------|------|:-----:|:-----------:|-------|
| qwen2.5:3b | 1.9 GB | 6/17 (35%) | 435ms | 只抓显式医疗/金融 |
| marco-o1:7b | 4.7 GB | 6/17 (35%) | 938ms | MCTS 推理无优势 |
| deepseek-r1:7b | 4.7 GB | 7/17 (41%) | 11,733ms | 慢且弱 |
| glm4:9b | 5.5 GB | 8/17 (47%) | 1,025ms | 中规中矩 |
| qwen2.5:7b | 4.7 GB | 11/17 (65%) | 902ms | 速度最优 |
| yi:9b | 5.0 GB | 11/17 (65%) | 949ms | 犯罪记录能抓到 |
| internlm2:7b | 4.5 GB | 12/17 (71%) | 1,161ms | 不错，和 32b 同分但快 5x |
| deepseek-r1:8b | 5.2 GB | 12/17 (71%) | 41,537ms | 准但极慢 |
| qwen2.5:32b | 19 GB | 12/17 (71%) | 5,648ms | 资源需求高 |
| deepseek-r1:14b | 9.0 GB | 12/17 (71%) | 18,498ms | 慢，性价比低 |
| **qwen3:8b (no_think)** | **5.2 GB** | **15/17 (88%)** | **19,902ms** | **高精度，推荐** |
| **qwen3:8b (think)** | **5.2 GB** | **16/17 (94%)** | **31,101ms** | **最准** |

### Key Findings

- **qwen3:8b 碾压所有其他模型**：94%（think）/ 88%（no_think），是唯一能检测犯罪记录隐式场景的模型
- qwen2.5:7b 仍是低延迟场景的最佳选择（65%，<1s）
- deepseek-r1 的 chain-of-thought 在 JSON 输出任务上表现不佳（thinking tokens 干扰格式）
- marco-o1 的 MCTS 推理对隐式 PII 检测没有帮助
- 同代模型差距巨大：qwen3:8b >> qwen2.5:7b >> glm4:9b

### Accuracy vs Latency Tradeoff

```
Score%  100|                                    * qwen3:8b(think) 94%
         90|                               * qwen3:8b(no_think) 88%
         80|
         70|  * internlm2  * qwen2.5:32b        * ds-r1:14b  * ds-r1:8b
         60|  * qwen2.5:7b * yi:9b
         50|       * glm4:9b
         40|                      * deepseek-r1:7b
         30|* qwen2.5:3b  * marco-o1
            +-----+-----+-----+-----+-----+-----+-----+
            0     1s    5s    10s   20s   30s   40s  Latency
```

**11 models tested, clear winner: qwen3:8b.**

---

## Recommendations

1. **默认模型推荐 qwen3:8b**：88-94% 检测率，20-31s 延迟在异步场景可接受
2. **低延迟场景用 qwen2.5:7b**：65% 检测率 + <1s 延迟，适合实时脱敏
3. **分层策略**：Layer 1-2 用正则/NER（<100ms），Layer 3 用 qwen3:8b（异步/批处理）
4. **Prompt 优化**：qwen3:8b 唯一漏掉的是"每周五请假"→宗教，可通过 prompt 注入宗教日历知识解决
5. **不推荐**：deepseek-r1（太慢且不稳定）、marco-o1（推理无优势）、3b（太弱）
