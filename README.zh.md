# argus-redact

[English](README.md) · 中文说明

[![PRvL](https://img.shields.io/badge/PRvL-Gold-brightgreen)](docs/prvl-standard.md) [![PyPI](https://img.shields.io/pypi/v/argus-redact)](https://pypi.org/project/argus-redact/) [![Demo](https://img.shields.io/badge/🤗-Demo-yellow)](https://huggingface.co/spaces/wan9yu/argus-redact)

**只加密 PII，不加密含义。在你本地。**

夹在你和 AI 之间的隐私层。你的身份信息留在本地设备上 — AI 拿到含义，但拿不到你是谁。

```python
from argus_redact import redact, restore

redacted, key = redact("王五在协和医院做了体检，手机13812345678", names=["王五"])
# "P-83811在[LOCATION]做了体检，手机138****5678"

llm_output = call_llm(redacted)        # LLM 看不到任何真实身份
restored = restore(llm_output, key)    # 一行代码原样恢复
```

```bash
pip install argus-redact
```

## 三个承诺

| | 承诺 | 实现方式 |
|-|------|---------|
| 🛡️ | **保护** — PII 永远不离开你的设备 | 三层本地检测：regex → NER → 本地 LLM |
| 🧠 | **可用** — AI 仍然能理解你的意图 | 假名替换保留语义和上下文 |
| 🔄 | **可逆** — 你能完整拿回原文 | 每条消息独立的 key，一行 restore |

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

**56 类 PII，覆盖 3 层** — 从电话号码到医疗诊断、宗教信仰、政治立场。默认 `mode="fast"`（仅 L1，零依赖，亚毫秒）；可选 `mode="ner"`（+ NER 模型）→ `mode="auto"`（全部 3 层）。

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

## 性能

Rust 核心 (PyO3) — M1 Max 上 `mode="fast"`：

| 文本 | redact() | restore() | 吞吐 |
|------|:--------:|:---------:|:----:|
| 短 (17 字) | 0.07ms | 0.04ms | 13,036 docs/sec |
| 中 (770 字) | 1.00ms | 0.05ms | 1,031 docs/sec |
| 长 (10K 字) | 22.2ms | 0.05ms | 45 docs/sec |

预编译 wheel 覆盖：Linux x86_64 (glibc + musl) / Linux aarch64 (含树莓派) / macOS (Apple Silicon + Intel) / Windows x64，Python 3.10–3.13，无需 Rust 工具链即可安装。

## 真实化替换 (`pseudonym-llm` profile)

默认 redact 输出占位标签（`[TEL-79329]`、`P-164`），审计清晰但下游 LLM 看不懂消息结构。`pseudonym-llm` profile 把 PII 换成**看起来真实但属于保留段**的假值（如 `19999...` 手机、`999...` 身份证、`999999...` 银行卡）。LLM 推理正常，懂规则的人也能一眼看出是合成的。

每次调用返回**三种文本形式**共享同一个 key：

| 形式 | 示例 | 用途 |
|------|------|------|
| `audit_text` | `请拨打 [TEL-79329] 联系 P-164` | 合规归档 — 占位标签可审计 |
| `downstream_text` | `请拨打 19999123456 联系张明` | 喂给 LLM — 语义结构保留 |
| `display_text` | `请拨打 19999123456ⓕ 联系张明ⓕ` | UI 渲染 — `ⓕ` 标记防混淆 |

```python
from argus_redact import redact_pseudonym_llm, restore

zh = redact_pseudonym_llm("请拨打 13912345678 联系王建国", lang="zh")
zh.downstream_text  # "请拨打 19999123456 联系张明"     → LLM
zh.display_text     # "请拨打 19999123456ⓕ 联系张明ⓕ"  → UI

restore(zh.downstream_text, zh.key)  # → 原文
```

**保留段**：
- **中文**：`199-99-XXXXXX` 手机（工信部未分配子段）、`099-` 座机（无此区号）、`999XXX` 身份证地址码（GB/T 2260 未分配）、`999999` 银联 BIN（未分配）、滨海市（虚构城市）。
- **英文**：`(555) 555-01XX` 电话（FCC 永久虚构保留）、`999-XX-XXXX` SSN（SSA 永不分配 9XX 段）、`999999` 信用卡 BIN、John Doe / Jane Roe 人名。
- **共享 (RFC)**：`example.com/.org/.net` 邮箱 (RFC 2606)、`192.0.2.0/24` 等 IPv4 (RFC 5737)、`2001:db8::/32` IPv6 (RFC 3849)、`00:00:5E:00:53:xx` MAC (RFC 7042)。

## 流式

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

## 局限性

argus-redact 是 PII **数据最小化辅助工具**，不是匿名化或合规认证：

- **L1 fast (regex)** 匹配定义良好的格式；新型或混淆变种、跨字段推断攻击会漏过。
- **L2 NER** 是统计推断；分布外文本（口语、错字、少数民族姓名）漏检率更高。
- **不保证对抗性输入** — 攻击者可以构造规避检测的文本。
- **不是 GDPR/PIPL 匿名化框架** — 匿名化是合规过程决策，不是单一库的输出。

**适合用 argus-redact**：LLM 流水线里需要 `redact() → LLM → restore()`，零 PII 跨过网络边界的可逆假名化。

**考虑替代品**：单向英文 PII 掩码 + 单次模型调用 → [OpenAI Privacy Filter](https://huggingface.co/openai/privacy-filter) 等基于模型的方案可能更适合。argus-redact 最强的地方是**可逆假名化 + 按消息独立 key**；中文支持最深（HanLP + 本土校验器），其他 7 种语言走 regex + spaCy NER。按工作负载选，不按排他性选。

## 集成

| | 安装 |
|-|------|
| [LangChain / LlamaIndex / FastAPI](docs/integration-frameworks.md) | 核心包 |
| [Presidio 桥接](docs/integration-frameworks.md) | `pip install argus-redact[presidio]` |
| [MCP Server](docs/cli-reference.md#mcp-server) (Claude Desktop / Cursor) | `pip install argus-redact[mcp]` |
| [HTTP API Server](docs/cli-reference.md) | `pip install argus-redact[serve]` |
| 结构化数据 (JSON / CSV) | 核心包 |
| Docker | slim 157MB / full 5GB |

## 文档

详细文档（英文）：

| | |
|-|-|
| [Getting Started](docs/getting-started.md) | 安装、首次 redact/restore、key 管理 |
| [API Reference](docs/api-reference.md) | 所有参数、返回类型、流式、结构化数据 |
| [CLI Reference](docs/cli-reference.md) | 命令、flags、serve、MCP server |
| [Configuration](docs/configuration.md) | 按类型策略、企业掩码规则、误报控制 |
| [Architecture](docs/architecture.md) | 三层引擎、跨层 hints、pure/impure 分离 |
| [Security Model](docs/security-model.md) | 威胁模型、合规、按消息 key |
| [PRvL Standard](docs/prvl-standard.md) | 开放评估标准：隐私 × 可逆性 × 语言 |

## License

[Apache 2.0](LICENSE)

—— 反馈与贡献：[GitHub Issues](https://github.com/wan9yu/argus-redact/issues) · [CONTRIBUTING.md](CONTRIBUTING.md)
