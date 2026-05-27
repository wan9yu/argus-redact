# 本地 CLI 隐私代理 / Local CLI privacy proxy

[English](local-cli-proxy.md) · 中文说明

> **Layer 说明**: 本 recipe 是 **OSS cookbook 示例** — 150 行单机透明代理,
> 给 dev / 极客单用户场景 (`aider` / `llm` / cursor terminal 等 CLI 工具).
> 企业级 multi-tenant + 审计日志 + RBAC + 中文 PII 全栈 = sibling 商业产品
> **[Argus Gateway](https://gateway.agilist.cn/)**. 两者不同 layer, 不是
> 替代关系: 本 recipe 是 cookbook 代码 (copy/改/跑); Argus Gateway 是产品化
> SKU. 互不替代.

> ~150 行 Python 写一个本地 OpenAI 兼容代理，给任意上游 LLM API (DeepSeek /
> 通义千问 / Kimi / 智谱 GLM / OpenAI ...) 加一层 argus-redact PII 守门。
> 本地 CLI 工具不动一行代码，发往 `localhost`，代理在 forward 之前 redact
> PII，response 回来时 restore。

## 30 秒说明

你本地有含 PII 的文件 (笔记、日记、文档、客户资料)。你想用 CLI 工具
(`llm`、`aider`、`cursor`、或自己写的 Python 脚本) 调远端 LLM 查询/处理这些
文件。你**不希望** PII 离开本机。

这个 recipe 给你一个 Python 文件 (~150 行), 跑起来是个本地 HTTP 代理。
**CLI 工具零改动** — `OPENAI_API_BASE` 指向 `http://localhost:11434/v1`,
现有 setup 立刻变成 PII-aware。

---

## 架构

```
本地敏感文件 (~/notes/*.md, ~/journal/*)
       │
       ▼
你的 CLI 工具 (llm / aider / cursor / openai-python)
       │
       │ POST /v1/chat/completions
       ▼
[argus-redact 本地代理 localhost:11434]
       ├ 提取 messages[].content
       ├ argus_redact.redact()   (per-call 临时 key)
       ├ 把脱敏后的内容塞回 request body
       ├ httpx.post → 上游 (DeepSeek / OpenAI / ...)
       ├ 收 response / SSE stream
       ├ 用 key 逐 chunk argus_redact.restore()
       └ 流式返回给 CLI
       │
       ▼
你的 CLI 收到的是还原后的原文
但上游 LLM 从未看过你的原始 PII
```

---

## 谁该用 / 谁不该用

✅ **适合:**
- 单机单用户 setup
- 本地 CLI 工具调远端 LLM (DeepSeek / OpenAI / 等)
- 中等敏感度数据 (笔记 / 日记 / 草稿 / 客户记录)
- demo / 个人生产力实验 / 本地知识库探索

❌ **不适合:**
- 多用户场景 (要用 Argus Gateway 那种企业网关)
- 生产环境 / SLA / 高可用 / 可观测性要求
- 审计日志 / 合规存档要求
- tool_use / function calling (本 recipe 直接拒绝, 见限制段)
- 不同 app 要不同 PII 策略

需求落在 ❌ 里 → 关注 [Argus Gateway](https://gateway.agilist.cn/)
路线图, 或在本 recipe 留 +1 (见底部 *Graduation signals*).

---

## 三步跑起来

```bash
# 1. 安装
pip install argus-redact[serve]

# 2. 设置上游 API key (默认 DeepSeek)
export UPSTREAM_API_KEY=sk-deepseek-...

# 3. 启动代理
python docs/recipes/local-cli-proxy.py
```

你会看到:

```
argus-redact local CLI proxy
  upstream:  https://api.deepseek.com/v1
  mode:      fast
  langs:     ['zh', 'en']
  listening: http://localhost:11434

Point any OpenAI-compatible client at this proxy:
  export OPENAI_API_BASE=http://localhost:11434/v1
  export OPENAI_API_KEY=anything
```

另开 terminal, 任意 OpenAI 兼容客户端指向代理:

```bash
export OPENAI_API_BASE=http://localhost:11434/v1
export OPENAI_API_KEY=anything   # 这个值被忽略, 代理用 UPSTREAM_API_KEY

# 然后正常用你的 CLI 工具
```

---

## 具体例子

### `llm` CLI (simonw/llm) + DeepSeek

```bash
llm install llm-openai-plugin   # 如果没装过
llm -m deepseek-chat "用一句话总结 ~/journal/2026-05.md 的核心要点"
```

DeepSeek 看到的是 `P-83811 的核心要点...`, 不是 `黄芳的核心要点...`。

### `aider` + DeepSeek (本地知识库典型场景)

```bash
aider --openai-api-base http://localhost:11434/v1 \
      --openai-api-key anything \
      --model deepseek-chat \
      ~/sensitive-docs/*.md
```

aider 读你的文件, 把文件内容拼进 prompt, POST 到代理。PII 在到达 DeepSeek
之前已经 redact。

### openai-python SDK

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:11434/v1",
    api_key="anything",
)

resp = client.chat.completions.create(
    model="deepseek-chat",
    messages=[
        {"role": "user", "content": "黄芳的电话13912345678 ，住在北京。她最近怎么样？"}
    ],
)
print(resp.choices[0].message.content)
# 注意: LLM 回复里可能出现 "黄芳" (代理 restore 回来), 因为 DeepSeek 看到的是
# 假名版本, 但代理在 response 流上做了还原。
```

### curl 直接调

```bash
curl http://localhost:11434/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "deepseek-chat",
    "messages": [{"role": "user", "content": "我是黄芳，电话13912345678"}]
  }'
```

---

## 切换上游

代理是 upstream-agnostic 的 — 任何 OpenAI 兼容 API 都能用:

| 上游 | `UPSTREAM_BASE` |
|---|---|
| **DeepSeek** (默认) | `https://api.deepseek.com/v1` |
| OpenAI | `https://api.openai.com/v1` |
| Kimi (月之暗面) | `https://api.moonshot.cn/v1` |
| 智谱 GLM | `https://open.bigmodel.cn/api/paas/v4` |
| 通义千问 (DashScope OpenAI 兼容模式) | `https://dashscope.aliyuncs.com/compatible-mode/v1` |
| Groq | `https://api.groq.com/openai/v1` |
| Together | `https://api.together.xyz/v1` |
| OpenRouter | `https://openrouter.ai/api/v1` |
| 你的自定义 endpoint | 随便 |

```bash
# 例: 切到 OpenAI
export UPSTREAM_BASE=https://api.openai.com/v1
export UPSTREAM_API_KEY=sk-openai-...
python docs/recipes/local-cli-proxy.py

# 例: 切到通义千问
export UPSTREAM_BASE=https://dashscope.aliyuncs.com/compatible-mode/v1
export UPSTREAM_API_KEY=sk-dashscope-...
python docs/recipes/local-cli-proxy.py
```

---

## 限制 (诚实承认)

| # | 限制 | 原因 |
|---|---|---|
| 1 | **不支持 tool_use / function calling**。带 `tools` / `functions` 的请求会被 HTTP 400 拒绝。 | 多轮 tool_use 的 redact/restore 是状态机问题。recipe 范围不解决。 |
| 2 | **流式: 逐 chunk restore, 不做句子缓冲**。一个长假名跨两个 SSE chunk 可能漏 restore。 | recipe 追求简洁。要严格保证, 换成 `argus_redact.streaming.StreamingRestorer` (参考 [api-reference.md](../api-reference.md) §Streaming, 约 30 行改动)。 |
| 3 | **临时 session key**。进程重启 → key 丢。跨会话"同名 → 同假名"不成立。 | 设计如此 (recipe 是一次性工具)。 |
| 4 | **单用户, 无认证**。监听 `127.0.0.1`, 本机任何进程都能 hit。 | 要鉴权 → `argus_redact[serve]` 的 `ARGUS_API_KEY` 模式。 |
| 5 | **上游 API key 明文存在进程内存里**。Bearer 转发给上游。 | 进程结束就清了。别 log, 别暴露。 |
| 6 | **无审计日志 / metric / 可观测性**。 | 自己加。 |
| 7 | **无 per-app PII 策略**。一个 redact 模式对所有 incoming 请求生效。 | 要细粒度 → Argus Gateway。 |
| 8 | **不支持 vision / audio / file_upload**。只支持 ChatCompletions 纯文本。 | recipe 范围。多模态 redact 是另一个问题。 |

---

## FAQ

**Q: CLI 工具调用失败, 报 "unsupported_in_recipe", 怎么回事?**
A: 你的客户端在 request body 里发了 `tools` / `functions`。本 recipe v1 拒绝这种。
解法: (a) 客户端关掉 tool_use; (b) 这个会话直接打上游, 绕过代理; (c) 等 graduation。

**Q: 流式感觉略不对劲, 有时电话号码被还原一半。**
A: 限制 #2。逐 chunk restore 在长假名跨 chunk 时会漏。修复办法: 把
`_restore_sse_line` 换成基于 `argus_redact.streaming.StreamingRestorer` 的
句子缓冲版本 (~30 行改动)。recipe 保持简单, 你按需升级。

**Q: 跟 Argus Gateway 是什么关系?**
A: Argus Gateway 是企业级网关 (多租户 / 策略 / 审计 / RBAC)。本 recipe 是单
用户单机临时方案。两个产品, 互补。

**Q: 我能同时跑多个实例对接不同上游吗?**
A: 可以。一个 terminal `PORT=11434 UPSTREAM_BASE=...DeepSeek... python ...`,
另一个 terminal `PORT=11435 UPSTREAM_BASE=...OpenAI...`。

**Q: 为什么默认端口 11434?**
A: 跟 Ollama 默认端口对齐, 本地 LLM 习惯。⚠️ **如果你本机有 Ollama 在跑,
11434 被占, 代理会启动失败**。用 `PORT=11435` 或其他端口覆盖。

**Q: 我能不能监听 `0.0.0.0` 让局域网设备也用?**
A: **不能**。代理没鉴权。任何在你网络上的人都能用你的上游 API key + 看 PII
流。坚持 `127.0.0.1` (默认)。要对外暴露 → 用 `argus_redact[serve]` 带认证
模式, 或上 Argus Gateway。

**Q: 本地知识库怎么搭? recipe 帮我做 RAG 吗?**
A: **不做**。recipe 只是 PII 守门员, 不管 RAG。如果你要本地知识库:
1. 用 chromadb / sqlite-vss / llamaindex 之类的本地向量库自己建索引
2. retrieve 时把 retrieved chunks 拼进 prompt
3. CLI 工具 (aider / llm / 自己的 Python) 发 prompt
4. 经过本代理 → PII redact → 上游 LLM

RAG 的部分用社区现成工具, 代理只在第 4 步插一脚。

---

## Graduation signals / 升级触发条件

这个 recipe 在 `docs/recipes/` 里以 cookbook 代码形式存在 — 复制、改、跑。
它**不是**一个维护的产品。如果这个 use case 变重要, 考虑:

1. **独立成 `argus-proxy` repo**, `pip install argus-proxy`, 有完整 release
   流程、CI 等。触发条件: ≥5 个 GitHub issue 要求把它做成维护中的工具,
   或有可观察的 fork 数据。

2. **交给 Argus Gateway 做 "Lite" SKU**。触发条件: Gateway 团队把它纳入
   路线图 (v1.6+)。

3. **保持 recipe 形态**。如果 (1)、(2) 都没发生, 这是默认结局。recipe 足够
   小, argus-redact 主仓内联维护没问题。

要表达兴趣: 在 GitHub 上开 issue, tag `[recipe-proxy]`, 简短说明你的 use
case。我们追踪这些信号。

---

## 相关文档

- **`local-cli-proxy.py`** — 跟本文档配套的可执行脚本
- **[`docs/api-reference.md`](../api-reference.md)** — `redact()` / `restore()` / 流式
- **[`docs/sensitive-info.md`](../sensitive-info.md)** — PII 类型分类
- **[Argus Gateway](https://gateway.agilist.cn/)** — 企业级 sibling
  (多租户、RBAC、审计、策略)
