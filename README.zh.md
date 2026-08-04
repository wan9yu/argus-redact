# argus-redact

[English](README.md) · 中文说明

[![PyPI](https://img.shields.io/pypi/v/argus-redact)](https://pypi.org/project/argus-redact/) [![crates.io](https://img.shields.io/badge/crates.io-v0.8.6-orange)](https://crates.io/crates/argus-redact-core) [![Tests](https://github.com/wan9yu/argus-redact/actions/workflows/test.yml/badge.svg)](https://github.com/wan9yu/argus-redact/actions/workflows/test.yml) [![codecov](https://codecov.io/gh/wan9yu/argus-redact/graph/badge.svg)](https://codecov.io/gh/wan9yu/argus-redact) [![Demo](https://img.shields.io/badge/🤗-Demo-yellow)](https://huggingface.co/spaces/wan9yu/argus-redact)

**只加密 PII，不加密含义。在你本地。**

夹在你和 AI 之间的隐私层。你的身份信息留在本地设备上 — AI 拿到含义，但拿不到你是谁。

在本项目自有的 PRvL 参考测试集上评为 **[PRvL-Gold](docs/prvl-standard.md)**（`default` profile 配置）— 具体衡量范围及完整的分 profile 矩阵见规范文档。

<!-- pin -->
```python
from argus_redact import redact

redacted, key = redact("张三的电话是13812345678，身份证号110101199003074610", names=["张三"], lang="zh", salt=42)
print(redacted)
# expected: P-83811的电话是138****5678，身份证号ID-03292

print(sorted(key.items()))
# expected: [('138****5678', '13812345678'), ('ID-03292', '110101199003074610'), ('P-83811', '张三')]
```

```bash
pip install argus-redact
```

## 三个承诺

| | 承诺 | 实现方式 |
|-|------|---------|
| 🛡️ | **保护** — PII 永远不离开你的设备 | 三层本地检测：regex → NER → 本地 LLM |
| 🧠 | **可用** — AI 仍然能理解你的意图 | 假名替换保留语义和上下文 |
| 🔄 | **可逆** — 字符串级逆替换, 按消息独立 key | LLM 原样引用假名时一行 `restore()` 还原; LLM 改写 / 称谓变体由 [compose 层](docs/architecture-layers.md) best-effort 处理 |

其他工具会**永久销毁** PII；argus-redact 是用一次性密钥**加密**它。[ETH Zurich 研究](https://arxiv.org/abs/2602.16800)显示，当假名固定时，LLM 可以以每人 $1-4 的成本去匿名化用户。我们**每次调用生成新随机密钥** — 云端每次看到的假名都不相关。

## 默认替换效果

`redact()` 输出**按类型的假名编码**，不是中文标签字面量：

```python
>>> redact("员工张三，身份证110101199003074610，电话13812345678", mode='fast', lang='zh')
('员工P-83811，身份证ID-89732，电话138****5678',
 {'P-83811': '张三', 'ID-89732': '110101199003074610', '138****5678': '13812345678'})
```

| 类型 | 默认输出 | 策略 | 可逆 |
|---|---|---|:---:|
| `person` / `organization` | `P-NNNNN` / `O-NNNNN` | `pseudonym` 假名 | ✓ |
| `phone` / `email` / `bank_card` | `138****5678` (留尾号) | `mask` 掩码 | ✗ |
| `id_number` / `medical` / `ssn` ... | `ID-NNNNN` / `MED-NNNNN` ... | `remove` → 类型化编码 | ✓ |
| `self_reference` | `我` / `我妈` (原样保留) | `keep` | ✓ |

要将所有可逆类型**统一到一个前缀**（向 LLM 隐藏 PII 类型）：

<!-- pin -->
```python
from argus_redact import redact

text = "员工张三，身份证110101199003074610，电话13812345678"
result, key = redact(
    text,
    lang="zh",
    salt=42,
    unified_prefix="R",
    config={
        "phone": {"strategy": "remove"},
        "email": {"strategy": "remove"},
    },
)
print(result)
# expected: 员工R-83811，身份证R-03292，电话R-68060
```

`<TYPE_N>` 一位数序号风格（`R-1`、`R-2`）列入后续版本候选（无承诺时间表）。详见 [docs/configuration.md](docs/configuration.md#unified-prefix-hide-pii-type)。

## 隐私等级评估

argus-redact 从**你的视角**评估文本，不是监管者视角：

```
🟢 安全     — 没有暴露你的信息
🟡 注意     — 包含个人信息，单独不致命
🟠 危险     — 可以缩窄到具体到你
🔴 暴露     — 直接识别到你
```

```python
report = redact("身份证110101199003074610，手机13812345678，确诊糖尿病", report=True)
report.risk.level    # "critical"
report.risk.score    # 1.0
report.risk.reasons  # ("id_number (critical)", "phone (high)", "medical (critical)", ...)
```

合规框架不会告诉你的核心问题：**这段文本，发给 AI 有多危险？**

## 三层检测，协同工作

```
Layer 1  Rust+Regex   电话/身份证/银行卡/邮箱/自指/...        <0.2ms
             │
         produce_hints() → text_intent / pii_density / self_reference_tier
             │
Layer 2  NER ← hints   位置/机构/独立人名                    10-100ms
Layer 3  本地 LLM       隐式 PII — 症状→疾病、行为→信仰         ~20s
```

层与层之间不是独立的 — L1 把**语境提示**（hints）传给 L2，让协同检测成为可能。指令文本（"帮我看看这段代码"）会跳过 NER；高 PII 密度会降低 NER 阈值；跨层一致性会提升置信度。

Unicode 加固：NFKC 规范化、零宽字符剥离、西里尔/希腊伪装字防御、中文数字识别（一三八零零一三八零零零 → 检测为电话）。

核心引擎（regex 匹配、实体合并、还原、假名生成）用 **Rust + PyO3** 写，追求极致性能；Python 负责编排、NER 模型、LLM 集成。

**74 类 PII，覆盖 3 层**（完整清单见[类型目录](docs/pii-types.md)，由注册表自动生成）— 从电话号码到医疗诊断、宗教信仰、政治立场。默认 `mode="fast"`（仅 L1，零依赖，亚毫秒）；可选 `mode="ner"`（+ NER 模型）→ `mode="auto"`（全部 3 层）。

**部署位置很重要** — 三种 mode 的延迟差三个数量级，按你在请求路径中的位置选：

| Mode | 单文档延迟 | 适合做 |
|---|:---:|---|
| `fast` | <1ms | 网关 inline plugin / LLM 代理热路径 |
| `ner` | 10–100ms | sidecar / 预检中间件 |
| `auto` | ~20s（受 LLM 限制）| 异步批处理 / 离线审计队列 |

不要把 `auto` 放在交互式 LLM 调用前面。inline 用 `fast`，并行审计 lane 跑 `auto`。

## 8 种语言

| | zh | en | ja | ko | de | uk | in | br |
|-|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| 电话 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 身份证 | MOD11-2 + 15 位旧版 | SSN | My Number | RRN | Tax ID | NINO | Aadhaar | CPF/CNPJ |
| 银行卡 | Luhn | Luhn | — | — | IBAN | — | PAN | — |
| 人名 | HanLP | spaCy | spaCy | spaCy | spaCy | spaCy | spaCy | spaCy |
| 邮箱 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

混合使用：`lang=["zh", "en", "de"]`；提供已知人名：`names=["王一", "张三"]`。

**基准范围：** 只有 **zh** 和 **en** 有已提交的召回率基准。其余六个语言包（**de、uk、br、in、ja、ko**）附带 L1 模式（除 **br** 外还附带 NER 适配器），但没有实测召回率 —— 视为 **best-effort**，请通过显式 `lang="…"` 使用。它们不会在 `lang="auto"` 下被自动选中：仅凭脚本的检测会把所有拉丁字母文本判定为 `en`。详见 [language-packs.md](docs/language-packs.md#benchmark-status)。

## 性能

Rust 核心 (PyO3)，`mode="fast"` — `redact()` p50（500 次迭代），Apple M1 Max，
Python 3.11。复现命令：`python tests/benchmark/perf_profile.py`

| 文档 | en | zh |
|------|:--:|:--:|
| 短 (141 B en / 175 B zh) | 0.22 ms · ~4,500 docs/sec | 0.34 ms · ~2,900 docs/sec |
| ~1 KB (846 B / 1.4 KB) | 0.97 ms · ~1,030 docs/sec | 2.03 ms · ~490 docs/sec |
| 长 (8.5 KB / 14 KB) | 9.4 ms · ~106 docs/sec | 20.3 ms · ~49 docs/sec |

吞吐高度依赖文档大小与语种，因此这里标注具体的输入尺寸，而不给单一的头条数字。
提交的运行结果：[`perf_profile_0.7.16.json`](tests/benchmark/results/perf_profile_0.7.16.json)。

预编译 wheel 覆盖：Linux x86_64 (glibc + musl) / Linux aarch64 (含树莓派) / macOS (Apple Silicon + Intel) / Windows x64，Python 3.10–3.13，无需 Rust 工具链即可安装。

**检测精度**

| Mode | 精确率 | 召回率 | F1 |
|---|---|---|---|
| fast (regex)          | 81.6% | 31.9% | 45.8% |
| ner (+ spaCy)         | 74.8% | 42.9% | 54.5% |
| auto (+ Ollama 32B)   | _本次跳过_ | | |

_ai4privacy en，500 样本，v0.7.16 run（结果 JSON：`tests/benchmark/results/ai4privacy_0.7.16.json`）。`auto` 模式在维护者硬件上跳过 — 完整矩阵与复现命令见 [benchmark-report.md](docs/benchmark-report.md)。_

`fast` 模式设计上高精确率 / 低召回率 — 只对能校验格式的实体（Luhn、MOD11-2 等）报出。召回率由 `ner` 和 `auto` 以延迟为代价提升。按部署形态选 mode（见上方*部署位置*）。[完整基准 →](docs/benchmark-report.md) | [性能详情 →](docs/performance.md)

## 北极星

| 维度 | 当前 (v0.8.6) | 下一里程碑 |
|-----------|:----------------:|:---:|
| **保护** | 74 类 PII，L1-L3。在 [PRvL](docs/prvl-standard.md) 参考套件中（24 个用例，每个模型 42 处 PII）：**`default` profile 在四个模型上均无泄漏** —— GPT-5 / Claude-Opus-4.5 / Gemini-2.5-Pro / GLM-4.6。可逆的 profile 并不干净：`pseudonym` 在 Claude-Opus-4.5 和 GLM-4.6 上各泄漏 1/42，`realistic` 在 Claude-Opus-4.5 上泄漏 1/42。参考套件不等于对抗性输入下的保证 —— 完整矩阵见 prvl-standard.md。8 语言跨层 hints（zh/en/ja/ko/de/uk/in/br）。SHAKE-256 派生 + 全盐熵 + faker 身份通过守卫。状态导出默认省略 salt；HTTP server 拒绝无认证启动；CLI 写入 O_NOFOLLOW + key 文件 mode 0600；MCP token 存储 TTL+LRU (v0.6.2)。Windows CI + 属性测试不变量 + 变异测试核心 (v0.6.3) + 性能预算 CI 门控 (v0.6.4) + 集成层会话隔离 (v0.6.6) + README pinned-to-doctest + 版本同步 CI 守卫 (v0.6.6) + compose 命名空间 + 纯层纯净守卫 (v0.6.7) + seed→salt API rename + PIITypeDef SSOT + Presidio bridge through public redact + 3 new types (v0.6.8) + compose 辅助函数 (v0.6.9) + Layer 1 冻结守卫/KDF replay 向量/死代码精简/manylinux 摘要锁定 (v0.6.10) + 适配器编写接口（compose.register_pii_type / PIITypeDef / PatternMatch）+ Layer 2 签名快照 (v0.6.11) + 港澳通行证/公积金 zh L1 覆盖 (v0.6.12)。**v0.7.x — 100% Rust 核心 SSOT**：argus-redact-core crate + crates.io 发布，patterns/校验器/归一化/替换+还原/fakers/人名打分 + 完整 L1 redact/restore 引擎迁入 Rust (v0.7.0–v0.7.8) + fail-closed 加固与检测正确性 (v0.7.9–v0.7.10) + 浏览器内 **wasm** 构建 (v0.7.11)。**v0.7.12 — 准标识符检测广度**：证据门控的中文裸地区、职业、医疗病症/过敏、以及新类型 **hobby** 检测（经由共享的 evidence_detector 框架），加上重识别评测（PRvL+ X 轴）；移除未发布的 generalize 策略。**v0.7.18–v0.7.20 — 守卫式还原**：`restore()` 增加确定性守卫（每次调用的溯源 nonce + 作用域绑定），关闭"LLM 输出里被注入的假名会被静默还原"这一窗口 (v0.7.18)；修复真实泄漏 —— 在 `mode="fast"` 下，一个 Luhn 合法的银行卡号在八个语言包中的六个（ja/ko/de/uk/in/br，即自身不带卡号 pattern 的语言包）会原样透传，现已改为不依赖周边文字语种即可检出 (v0.7.19)；整个流程收敛为一个公开的 `guarded_restore()`，五个集成层全部包装它 (v0.7.20)。**v0.8.0（破坏性）** —— `guard=True` 现为默认（裸 restore 无 anchor 时 fail-closed）；`residual_personal_data` 对 mask 配置如实上报；修复了 `unified_prefix` 下会导致还原张冠李戴的假名撞码。**v0.8.4** —— 浏览器内 wasm 构建现在在客户端本地跑还原守卫（`restore_guarded`，不再请求服务器）；person 跨层合并改为保留更高层的 span 并把被截断的剩余部分重新插入，而不是直接丢弃，pii_bench_zh 参考套件上人名召回率从 88.0% 提升到 95.6%，其他类型无回归；批量 `restore_json`/`restore_csv`/`StreamingRestorer` 现在每次调用只编译一次替换模式，而不是逐条编译（在一个实测样例上约 555 倍提速，非普遍性能承诺） | 对抗性测试 |
| **可用** | PRvL U=100%。假名编码 + 真实模式（zh + en + RFC 共享）+ 按调用策略覆盖 + `keep` 策略（白名单）+ 可续流式会话 + 增量流式默认 + 跨语言别名还原（zh ↔ en） | 任务感知引导 |
| **可逆** | PRvL R 按任务：引用 100%，提取 50%，创意 0%（设计如此）。跨语言 LLM 改写（`张三` → `Zhang San`）通过 `result.aliases` + `restore(text, key, aliases=...)` 自动还原 | 任务感知引导 |
| **合规** | 覆盖 PIPL Art.28 敏感 PII 范畴；提供风险评估 + 合规 profiles | PIPL/GDPR/HIPAA（副产品） |
| **覆盖** | 8 语言，4 个 LLM 基准，6 个框架 | 浏览器扩展 |

## 风险评估

```python
# 发送给 AI 前先评估风险
report = redact(text, report=True)
report.risk.level         # "critical"
report.risk.pipl_articles # ("PIPL Art.28", "PIPL Art.51", ...)
report.entities           # 检测到的 PII 详情
report.stats              # 各层计时
```

```bash
# CLI
argus-redact assess <<< "身份证110101199003074610"
```

合规 profiles：`redact(text, profile="pipl")` / `"gdpr"` / `"hipaa"`。这些只是策略覆盖预设，不是覆盖范围保证 —— 它们改变的是已检测类型"如何"被脱敏，而不是"哪些"类型会被检测到；选用某个 profile 本身并不能让流水线自动合规。[详情 →](docs/configuration.md#profile-strategy-overrides)
类型过滤：`redact(text, types=["phone", "id_number"])` / `types_exclude=["address"]`。

## 真实化替换 (`pseudonym-llm` profile)

默认 redact 输出占位标签（`[TEL-79329]`、`P-164`），审计清晰但下游 LLM 看不懂消息结构。`pseudonym-llm` profile 把 PII 换成**看起来真实但属于保留段**的假值（如 `19999...` 手机、`999...` 身份证、`999999...` 银行卡）。LLM 推理正常，懂规则的人也能一眼看出是合成的。

每次调用返回**三种文本形式**共享同一个 key：

| 形式 | 示例 | 用途 |
|------|------|------|
| `audit_text` | `请拨打 [TEL-79329] 联系 P-164` | 合规归档 — 占位标签可审计 |
| `downstream_text` | `请拨打 19999123456 联系张明` | 喂给 LLM — 语义结构保留 |
| `display_text` | `请拨打 19999123456ⓕ 联系张明ⓕ` | UI 渲染 — `ⓕ` 标记防混淆 |

realistic 策略要求显式 `salt`（下面用 `salt=42` 让输出可复现；生产请用真实密钥）。

<!-- pin -->
```python
from argus_redact import redact_pseudonym_llm, restore

# 中文
zh = redact_pseudonym_llm("请拨打 13912345678 联系王建国", lang="zh", salt=42)
zh.downstream_text  # "请拨打 19999946823 联系毕马温"    → LLM
zh.display_text     # "请拨打 19999946823ⓕ 联系毕马温ⓕ" → UI

# 英文
en = redact_pseudonym_llm("Call (415) 555-1234, SSN 123-45-6789", lang="en", salt=42)
en.downstream_text  # "Call (555) 555-0123, SSN 999-47-9373" → LLM
en.audit_text       # "Call PHON-68060, SSN SSN-54474"       → 合规归档

# 混合（自动检测）
mx = redact_pseudonym_llm("客户Wang at user@company.com", lang="auto", salt=42)

# 三种形式均可完整还原，跨语言通用。
# 这里用 guard=False：还原的是库自己刚产出的文本，不是 LLM 的回复 ——
# 真正的 LLM 往返请看"安全地还原 LLM 输出"一节的守卫式还原。
print(restore(zh.downstream_text, zh.key, guard=False))
# expected: 请拨打 13912345678 联系王建国
print(restore(en.downstream_text, en.key, guard=False))
# expected: Call (415) 555-1234, SSN 123-45-6789
print(restore(mx.downstream_text, mx.key, guard=False))
# expected: 客户Wang at user@company.com
```

```bash
# CLI 以 JSON 输出三种形式
echo "Call (415) 555-1234" | \
  argus-redact redact -k key.json --profile pseudonym-llm -l en | \
  jq .downstream_text
# "Call (555) 555-0142"
```

**保留段**：
- **中文**：`199-99-XXXXXX` 手机（工信部未分配子段）、`099-` 座机（无此区号）、`999XXX` 身份证地址码（GB/T 2260 未分配）、`999999` 银联 BIN（未分配）、滨海市（虚构城市）。
- **英文**：`(555) 555-01XX` 电话（FCC 永久虚构保留）、`999-XX-XXXX` SSN（SSA 永不分配 9XX 段）、`999999` 信用卡 BIN、John Doe / Jane Roe 人名、1313 Mockingbird Lane 地址。
- **共享 (RFC)**：`example.com/.org/.net` 邮箱 (RFC 2606)、`192.0.2.0/24` 等 IPv4 (RFC 5737)、`2001:db8::/32` IPv6 (RFC 3849)、`00:00:5E:00:53:xx` MAC (RFC 7042)。

**Argus Gateway 集成**：响应 header 应包含 `X-Argus-Redact-Profile: pseudonym-llm`；UI 客户端渲染 `display_text`，LLM 客户端消费 `downstream_text`。将 `downstream_text` 作为业务真值存储是不安全的 — 它本质是合成数据。

**真实用户与典型假名同名**（如真实客户名为 `张三` 或 `John Doe`）：传入 `reserved_names={"person_zh": ()}` （或 `person_en`）可禁用该语种典型名污染检测，使真实用户名走正常 redact 流程。

### 流式

聊天会话 / 长文本分块输入用 `StreamingRedactor`（输入端）和 `StreamingRestorer`（输出端）。两者都要求**每个分块是完整的逻辑单元**（句子 / 段落 / 一轮对话）— 跨块切分的实体不处理。

```python
from argus_redact.streaming import StreamingRedactor, StreamingRestorer

r = StreamingRedactor(salt=b"my-secret-salt", lang="zh")
for chunk in input_stream:
    res = r.feed(chunk)
    send_to_llm(res.downstream_text)

restorer = StreamingRestorer(r.aggregate_key())
for chunk in llm_output_stream:
    restored = restorer.feed(chunk)
    if restored:
        print(restored, end="")
print(restorer.flush(), end="")
```

真正的字节级流式（实体跨 chunk 边界）需要完整增量检测，已列入后续路线图。

> ⚠️ 真实模式输出**不可二次 redact**（会损坏 key dict）。`redact_pseudonym_llm` 在已假名化输入上调用会抛出 `PseudonymPollutionError` — 请先调用 `restore()`。

[完整 API →](docs/api-reference.md#redact_pseudonym_llm) · [设计约束 →](docs/known-issues.md#design-constraints)

## 局限性

argus-redact 是 PII **数据最小化辅助工具**，不是匿名化或合规认证：

- **L1 fast (regex)** 匹配定义良好的格式；新型或混淆变种、跨字段推断攻击会漏过。
- **L2 NER** 是统计推断；分布外文本（口语、错字、少数民族姓名）漏检率更高。
- **不保证对抗性输入** — 攻击者可以构造规避检测的文本。
- **消除显式 PII 不等于匿名。** LLM agent 可以把残留的、单独看不具身份指向性的线索与公开数据组合，从而重新识别出个人 —— 即使在已脱敏的文本上，即使在良性任务中（[Ko et al. 2026](https://arxiv.org/abs/2603.18382)）。可逆替换保护的是显式标识符、并保留 LLM 的可用性；它**不能**防御基于推断的重识别，而这是单文档级别的 redactor 无法完全阻止的 —— 残留风险来自准标识符的*组合*，而非单个字段（[为什么把单个字段泛化并不能解决问题](docs/design-quasi-identifier-generalization.md)；[以及为什么扩大英文准标识符检测范围也没能降低重识别率](docs/design-english-detection-breadth.md)）。
- **不是 GDPR/PIPL 匿名化框架** — 匿名化是合规过程决策，不是单一库的输出。
- **restore 是一次替换，不是一次鉴权。** 未守卫的还原（`guard=False`）会把原文替换进**任何**带有对应假名的文本 —— 包括攻击者诱导模型产出的回复。自 v0.8.0 起默认 `guard=True`，无有效 anchor 时 fail-closed；请用[守卫式还原](#安全)把一次 restore 绑定到产生该 key 的那次交互。

**适合用 argus-redact**：LLM 流水线里需要 `redact() → LLM → guarded_restore()`，零 PII 跨过网络边界的可逆假名化。

**考虑替代品**：单向英文 PII 掩码 + 单次模型调用 → [OpenAI Privacy Filter](https://huggingface.co/openai/privacy-filter) 等基于模型的方案可能更适合。argus-redact 最强的地方是**可逆假名化 + 按消息独立 key**；中文支持最深（HanLP + 本土校验器），其他七种语言里有六种（en、ja、ko、de、uk、in）走 regex + spaCy NER，`br` 只有 regex、没有 NER 适配器。按工作负载选，不按排他性选。

## 集成

| | 安装 |
|-|------|
| [LangChain / LlamaIndex / FastAPI](docs/integration-frameworks.md) | 核心包 |
| [Presidio 桥接](docs/integration-frameworks.md) | `pip install argus-redact[presidio]` |
| [MCP Server](docs/cli-reference.md#mcp-server) (Claude Desktop / Cursor) | `pip install argus-redact[mcp]` |
| [HTTP API Server](docs/cli-reference.md) | `pip install argus-redact[serve]` |
| 结构化数据 (JSON / CSV) | 核心包 |
| [流式还原](docs/api-reference.md) | 核心包 |
| [Docker](Dockerfile) | slim 157MB / full 5GB |

## 安全

PII 永不离开你的设备。按消息独立 key 防止跨请求画像。[完整安全模型 →](docs/security-model.md)

**守卫式还原。** `guarded_restore()` 把一次 restore 绑定到产生该 key 的那次交互。两项确定性检查：回复必须回显本次调用的 nonce（**溯源**），且只替换本次调用产出的假名（**作用域**）。两者都 fail-closed —— 原样返回假名并发出 `SecurityWarning`，而不是把 PII 替换进一段被攻击者塑形的回复。此外还有一个注入启发式检查，默认仅告警。

```python
from argus_redact import redact, guarded_restore, make_anchor
from argus_redact.compose import prompt_anchor

redacted, key = redact("张三的电话是13812345678", names=["张三"], lang="zh")
anchor = make_anchor(key)          # 本次调用的 nonce + 假名作用域

system = prompt_anchor(key, lang="zh", anchor=anchor)   # 要求模型回显该 nonce
reply = call_llm(redacted, system=system)

restored = guarded_restore(reply, key, redacted=redacted, anchor=anchor)
# strict=True 则抛 RestoreGuardError，而不是返回未还原的文本
```

自 v0.8.0 起，`restore(text, key)` 默认 `guard=True`，无有效 anchor 时 fail-closed；传 `guard=False` 使用旧的无守卫替换，或用带 anchor 的守卫式还原。[守卫式还原 →](docs/security-model.md#guarded-restore)

提供 **PIPL** 跨境传输、**GDPR** 第 25 条数据最小化、**HIPAA** 去标识化流程所需的本地去标识化技术控制 — 是技术控制手段，不是合规认证。[详情 →](docs/security-model.md#regulatory-context)

## 文档

详细文档（英文）：

| | |
|-|-|
| [Getting Started](docs/getting-started.md) | 安装、首次 redact/restore、key 管理 |
| [API Reference](docs/api-reference.md) | 所有参数、返回类型、流式、结构化数据 |
| [CLI Reference](docs/cli-reference.md) | 命令、flags、serve、MCP server |
| [Configuration](docs/configuration.md) | 按类型策略、企业掩码规则、误报控制 |
| [Sensitive Info](docs/sensitive-info.md) | 敏感信息分类、隐私等级、路线图 |
| [PII Type Catalog](docs/pii-types.md) | 全部 PII 类型 — 策略、敏感度、PIPL/GDPR/HIPAA 映射（自动生成）|
| [Architecture](docs/architecture.md) | 三层引擎、跨层 hints、pure/impure 分离 |
| [Language Packs](docs/language-packs.md) | 新增语言包指南 |
| [Security Model](docs/security-model.md) | 威胁模型、合规、按消息 key |
| [**PRvL Standard**](docs/prvl-standard.md) | **开放评估标准：隐私 × 可逆性 × 语言** |
| [Layer 3 Benchmark](docs/layer3-benchmark.md) | LLM 模型对比、提示词设计、法规分析 |
| [Benchmarks](tests/benchmark/README.md) | 9 个公开 PII 数据集评估 |
| [Performance](docs/performance.md) | 延迟、吞吐、基准结果 |

## 贡献

[CONTRIBUTING.md](CONTRIBUTING.md) — 语言包、测试场景、框架集成欢迎提交。

## 贡献者

| 贡献者 | 贡献内容 |
|--------|---------|
| [@aiedwardyi](https://github.com/aiedwardyi) | 巴西葡萄牙语语言包（CPF、CNPJ、电话）|

## License

[Apache 2.0](LICENSE)

—— 反馈与贡献：[GitHub Issues](https://github.com/wan9yu/argus-redact/issues) · [CONTRIBUTING.md](CONTRIBUTING.md)
