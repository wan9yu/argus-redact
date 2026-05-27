# Local CLI privacy proxy / 本地 CLI 隐私代理

English · [中文说明](local-cli-proxy.zh.md)

> **Layer note**: this recipe is an **OSS cookbook pattern** — a 150-line
> single-machine transparent proxy for dev / hacker single-user scenarios
> (CLI tools like `aider`, `llm`, cursor terminal). For enterprise-grade
> multi-tenant + audit log + RBAC + full Chinese PII stack, see the sibling
> commercial product **[Argus Gateway](https://gateway.agilist.cn/)**. The
> two are different layers, not competitors: this recipe is cookbook code
> (copy, modify, run); Argus Gateway is a productized SKU. Neither
> replaces the other.

> A ~150-line OpenAI-compatible HTTP proxy that wraps argus-redact around any
> upstream LLM API (DeepSeek / OpenAI / Kimi / Zhipu / Qwen / Together / ...).
> Your local CLI tools send to `localhost`, this proxy redacts PII before
> forwarding, restores PII on the response.

## 30-second pitch / 30 秒说明

You have local files with PII (notes, journals, docs, customer data). You want
to query them with a CLI tool like `llm`, `aider`, `cursor`, or your own Python
script that hits an LLM API. You don't want the PII to leave your machine.

This recipe gives you a single Python file (~150 lines) that runs a local HTTP
proxy. **Zero code change to your CLI tools** — set `OPENAI_API_BASE` to
`http://localhost:11434/v1` and your existing setup is now PII-aware.

---

## Architecture / 架构

```
your local files (~/notes/*.md, ~/journal/*)
         │
         ▼
your CLI tool (llm / aider / cursor / openai-python)
         │
         │ POST /v1/chat/completions
         ▼
[argus-redact local proxy on localhost:11434]
         ├ extract messages[].content
         ├ argus_redact.redact()       (per-call session key)
         ├ swap redacted content into request body
         ├ httpx.post → upstream (DeepSeek / OpenAI / ...)
         ├ stream/return response
         ├ argus_redact.restore() each chunk
         └ return to CLI
         │
         ▼
your CLI sees the restored original answer
upstream LLM never saw the original PII
```

---

## When to use this recipe / 何时用

✅ **用:**
- single-user, single-machine setup
- local CLI tools calling remote LLM (DeepSeek / OpenAI / etc.)
- 中等敏感度数据 (notes, journals, draft docs)
- demo / experiment / personal productivity

❌ **不用:**
- multi-user (use Argus Gateway for this)
- production SLA / HA / observability requirements
- audit log / compliance archive required
- tool_use / function calling (recipe rejects these requests — see Limitations)
- you need different PII policies per app

For the ❌ list, watch [Argus Gateway](https://gateway.agilist.cn/)
roadmap or upvote this recipe (see *Graduation signals* below).

---

## Quickstart / 三步跑起来

```bash
# 1. Install
pip install argus-redact[serve]

# 2. Set your upstream API key (DeepSeek by default)
export UPSTREAM_API_KEY=sk-deepseek-...

# 3. Run the proxy
python docs/recipes/local-cli-proxy.py
```

You should see:

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

In another terminal, point any OpenAI-compatible client at the proxy:

```bash
export OPENAI_API_BASE=http://localhost:11434/v1
export OPENAI_API_KEY=anything   # ignored; proxy uses UPSTREAM_API_KEY

# Then use your favorite OpenAI-compatible CLI
```

---

## Concrete examples / 具体例子

### `llm` CLI (simonw/llm) + DeepSeek

```bash
llm install llm-openai-plugin   # if not already
llm -m deepseek-chat "用一句话总结 ~/journal/2026-05.md 的核心要点"
```

DeepSeek sees `P-83811 的核心要点...`, not `黄芳的核心要点...`.

### `aider` + DeepSeek (本地知识库 use case)

```bash
aider --openai-api-base http://localhost:11434/v1 \
      --openai-api-key anything \
      --model deepseek-chat \
      ~/sensitive-docs/*.md
```

`aider` reads your files, builds a prompt including the file contents, POSTs
to the proxy. PII gets redacted before reaching DeepSeek.

### `openai-python` SDK

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:11434/v1",
    api_key="anything",
)

resp = client.chat.completions.create(
    model="deepseek-chat",
    messages=[
        {"role": "user", "content": "黄芳的电话13912345678 ，住在北京。她最近怎么样?"}
    ],
)
print(resp.choices[0].message.content)
# Note: the LLM's reply may reference "黄芳" (restored by proxy),
# because DeepSeek saw the redacted form but the proxy restored on the way back.
```

### curl direct

```bash
curl http://localhost:11434/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "deepseek-chat",
    "messages": [{"role": "user", "content": "我是黄芳，电话13912345678"}]
  }'
```

---

## Switching upstream / 切换上游

The proxy is upstream-agnostic — any OpenAI-compatible API works:

| Upstream | `UPSTREAM_BASE` |
|---|---|
| **DeepSeek** (default) | `https://api.deepseek.com/v1` |
| OpenAI | `https://api.openai.com/v1` |
| Kimi (Moonshot) | `https://api.moonshot.cn/v1` |
| Zhipu GLM | `https://open.bigmodel.cn/api/paas/v4` |
| Qwen (DashScope OpenAI mode) | `https://dashscope.aliyuncs.com/compatible-mode/v1` |
| Groq | `https://api.groq.com/openai/v1` |
| Together | `https://api.together.xyz/v1` |
| OpenRouter | `https://openrouter.ai/api/v1` |
| Your custom endpoint | whatever |

```bash
# Example: swap to OpenAI
export UPSTREAM_BASE=https://api.openai.com/v1
export UPSTREAM_API_KEY=sk-openai-...
python docs/recipes/local-cli-proxy.py
```

---

## Limitations / 限制 (诚实)

| # | Limitation | Why |
|---|---|---|
| 1 | **No tool_use / function calling**. Requests with `tools` / `functions` are rejected with HTTP 400. | Multi-turn tool_use is a stateful redact/restore problem. Recipe scope doesn't cover it. |
| 2 | **Streaming: per-chunk restore, not sentence-buffered**. A long pseudonym split across two SSE chunks could slip restore. | Recipe simplicity. For stricter guarantees, swap in `argus_redact.streaming.StreamingRestorer` — see [api-reference.md](../api-reference.md) §Streaming. |
| 3 | **Ephemeral session key**. Process restart → key dict lost. Cross-session "same pseudonym for same name" doesn't hold. | No persistence by design (recipe is one-shot tool). |
| 4 | **Single-user, no auth**. Listens on `127.0.0.1`. Any local process can hit it. | If you need auth, see `argus_redact[serve]` mode with `ARGUS_API_KEY`. |
| 5 | **Plaintext upstream API key in process memory**. Forwarded as Bearer to upstream. | Stops being a concern when the process stops. Don't log. Don't expose. |
| 6 | **No audit log / metric / observability**. | Add yourself if you need it. |
| 7 | **No per-app PII policy**. One redact mode applies to all incoming requests. | Gateway-grade need: use Argus Gateway. |
| 8 | **No vision / audio / file_upload support**. ChatCompletions text only. | Recipe scope. Multimodal redact is its own problem. |

---

## FAQ

**Q: My CLI tool calls fail with "unsupported_in_recipe" — what gives?**
A: Your client is sending `tools` / `functions` in the request body. This recipe v1 rejects those. Workarounds: (a) disable tool_use in your client, (b) hit the upstream directly for tool-using sessions, (c) wait for graduation.

**Q: Streaming feels slightly off — sometimes a phone number is half-restored.**
A: Limitation #2. Per-chunk restore can split a pseudonym across two SSE chunks. To fix: swap `_restore_sse_line` for a sentence-buffered version using `argus_redact.streaming.StreamingRestorer` (~30 lines change). The recipe stays simple; you upgrade when you need it.

**Q: How does this relate to Argus Gateway?**
A: Argus Gateway is an enterprise gateway with multi-tenant, policy, audit, RBAC. This recipe is single-user single-machine ephemeral. Different products, complementary.

**Q: Can I run multiple instances on different ports for different upstreams?**
A: Yes. `PORT=11434 UPSTREAM_BASE=...DeepSeek... python local-cli-proxy.py` in one terminal, `PORT=11435 UPSTREAM_BASE=...OpenAI...` in another.

**Q: Why port 11434?**
A: Matches Ollama's default local-LLM port for muscle memory. ⚠️ If you have Ollama running, port 11434 is taken — the proxy will fail to bind. Override with `PORT=11435` or similar.

**Q: Should I run this on `0.0.0.0` so my LAN devices can use it?**
A: **No.** It has no auth. Anyone on your network would have access to your upstream API key + the PII flow. Stick to `127.0.0.1` (the default). If you need network exposure, wrap with `argus_redact[serve]`'s auth mode or use Argus Gateway.

---

## Graduation signals / 升级触发条件

This recipe lives in `docs/recipes/` as cookbook code — copy, modify, run. It's
NOT a maintained product. If the use case becomes load-bearing, we'd consider:

1. **Spin out as `argus-proxy` standalone repo** with `pip install argus-proxy`,
   release pipeline, CI, etc. Trigger: ≥5 GitHub issues asking for it as a
   maintained tool, or measurable signal that this recipe is being forked.

2. **Hand off to Argus Gateway** as a "Lite" SKU. Trigger: Gateway team picks
   it up in their roadmap (v1.6+).

3. **Stay as recipe**. Default outcome if neither (1) nor (2) materializes.
   Recipe is small enough to maintain inline with argus-redact itself.

To register interest: open a GitHub issue with `[recipe-proxy]` tag and a brief
description of your use case. We track these.

---

## See also

- **`local-cli-proxy.py`** — the runnable script (alongside this doc)
- **[`docs/api-reference.md`](../api-reference.md)** — `redact()` / `restore()` / streaming
- **[`docs/sensitive-info.md`](../sensitive-info.md)** — PII type taxonomy
- **[Argus Gateway](https://gateway.agilist.cn/)** — the enterprise sibling
  (multi-tenant, RBAC, audit, policy)
