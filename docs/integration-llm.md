# LLM Pipeline Integration

## Core Pattern

Every LLM integration follows the same three-step pattern:

```
plaintext → redact() → redacted text → LLM → LLM output → restore() → plaintext
```

```python
from argus_redact import redact, restore

redacted, key = redact(user_input)
llm_output = call_any_llm(redacted)
result = restore(llm_output, key)
```

The middle step — `call_any_llm` — is whatever you already use. argus-redact doesn't care which provider, model, or SDK.

---

## OpenAI

### Chat Completions

```python
from argus_redact import redact, restore
from openai import OpenAI

client = OpenAI()

def safe_chat(text: str, system: str = "You are a helpful assistant.") -> str:
    redacted, key = redact(text)

    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": redacted},
        ],
    )

    return restore(response.choices[0].message.content, key)

answer = safe_chat(
    "王五在协和医院做了体检，结果显示血压偏高",
    system="You are a health advisor. Give brief advice.",
)
# LLM sees: "P-037在[医院]做了体检，结果显示血压偏高"
# LLM responds about P-037
# restore() returns advice with 王五 and 协和医院 restored
```

### Streaming

```python
def safe_chat_stream(text: str, system: str) -> str:
    redacted, key = redact(text)

    stream = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": redacted},
        ],
        stream=True,
    )

    # Collect full response, then restore
    chunks = []
    for chunk in stream:
        content = chunk.choices[0].delta.content or ""
        chunks.append(content)

    full_output = "".join(chunks)
    return restore(full_output, key)
```

**Why collect-then-restore?** Streaming chunks may split a pseudonym across chunks (`P-0` in one chunk, `37` in the next). Restore needs the complete text to match pseudonyms reliably.

If you need to stream restored text to the user in real-time, buffer until you see a word boundary:

```python
def safe_stream_to_user(text: str, system: str):
    redacted, key = redact(text)

    stream = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "system", "content": system}, {"role": "user", "content": redacted}],
        stream=True,
    )

    buffer = ""
    for chunk in stream:
        content = chunk.choices[0].delta.content or ""
        buffer += content

        # Flush on sentence boundaries
        while "\n" in buffer or "。" in buffer or ". " in buffer:
            boundary = max(buffer.find("\n"), buffer.find("。"), buffer.find(". "))
            if boundary == -1:
                break
            sentence, buffer = buffer[:boundary + 1], buffer[boundary + 1:]
            yield restore(sentence, key)

    if buffer:
        yield restore(buffer, key)
```

### Multi-turn Conversations

Each turn gets its own key (default behavior):

```python
# Turn 1
redacted1, key1 = redact("王五在协和医院体检了")
response1 = call_llm(redacted1)
restored1 = restore(response1, key1)

# Turn 2 — new key, new pseudonyms
redacted2, key2 = redact("他的同事张三也去了")
response2 = call_llm(redacted2)
restored2 = restore(response2, key2)
```

If turns need to reference each other, share the key:

```python
# Turn 1
redacted1, key = redact("王五在协和医院体检了")
response1 = call_llm(redacted1)

# Turn 2 — same key, 王五 stays P-037
redacted2, key = redact("他的同事张三也去了同一家医院", key=key)
response2 = call_llm(f"Context: {redacted1}\nNew: {redacted2}")
restored2 = restore(response2, key)
```

**Security tradeoff:** Sharing keys across turns makes them linkable. The cloud provider can see that turns 1 and 2 involve the same P-037. Use only when cross-turn coherence is needed.

---

## Anthropic (Claude)

```python
from argus_redact import redact, restore
import anthropic

client = anthropic.Anthropic()

def safe_claude(text: str, system: str) -> str:
    redacted, key = redact(text)

    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        system=system,
        messages=[{"role": "user", "content": redacted}],
    )

    return restore(message.content[0].text, key)
```

### With tool use

When Claude returns tool calls, redact the tool input too:

```python
def safe_claude_with_tools(text: str, tools: list) -> dict:
    redacted, key = redact(text)

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        messages=[{"role": "user", "content": redacted}],
        tools=tools,
    )

    # Restore PII in tool call arguments
    for block in response.content:
        if block.type == "tool_use":
            for arg_key, arg_value in block.input.items():
                if isinstance(arg_value, str):
                    block.input[arg_key] = restore(arg_value, key)

    return response
```

---

## Local LLMs (Ollama, llama.cpp, vLLM)

With local LLMs, redaction is technically unnecessary — data never leaves your device. But it's still useful for:

1. **Defense in depth** — if your local LLM server is misconfigured and logs prompts
2. **Consistent pipeline** — same code works for local and cloud LLMs
3. **Testing** — validate redaction quality before switching to a cloud model

### Ollama

```python
from argus_redact import redact, restore
import requests

def safe_ollama(text: str, model: str = "qwen2.5:7b") -> str:
    redacted, key = redact(text)

    response = requests.post("http://localhost:11434/api/generate", json={
        "model": model,
        "prompt": redacted,
        "stream": False,
    })

    return restore(response.json()["response"], key)
```

### llama.cpp (via llama-cpp-python)

```python
from argus_redact import redact, restore
from llama_cpp import Llama

llm = Llama(model_path="./models/qwen2.5-7b-q4.gguf")

def safe_local(text: str) -> str:
    redacted, key = redact(text)
    output = llm(redacted, max_tokens=512)
    return restore(output["choices"][0]["text"], key)
```

---

## System Prompts

**Don't redact system prompts** — they don't contain user PII:

```python
system = "You are a career coach. Give specific, actionable advice."
redacted, key = redact(user_input)  # only redact user input

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[
        {"role": "system", "content": system},       # plaintext — no PII
        {"role": "user", "content": redacted},        # redacted
    ],
)
```

If your system prompt contains entity names the LLM should know about, include them in the redacted form:

```python
redacted, key = redact(user_input)

# Reference pseudonyms in system prompt
system = f"The user is {key.get('P-037', 'the user')}... "
# Wait — this defeats the purpose. Don't do this.
```

**Rule: System prompts should be generic. Entity-specific instructions belong in the user message (and get redacted).**

---

## Redacting LLM Output Before Logging

If you log LLM interactions and the restored output contains PII, redact the log:

```python
redacted, key = redact(user_input)
llm_output = call_llm(redacted)
restored = restore(llm_output, key)

# Show user the restored version
print(restored)

# Log the redacted version (no PII in logs)
log.info(f"Input: {redacted}")
log.info(f"Output: {llm_output}")  # still contains pseudonyms, safe to log
```

---

## Error Handling

```python
from argus_redact import redact, restore

try:
    redacted, key = redact(user_input)
except ValueError as e:
    # Language pack not installed
    # Fall back to fast mode (regex only)
    redacted, key = redact(user_input, mode="fast")

llm_output = call_llm(redacted)

# restore() is pure string replacement — unlikely to fail
restored = restore(llm_output, key)

# If the LLM output doesn't contain any pseudonyms,
# restore() returns the input unchanged — not an error.
```

---

## Batch / Multiple Documents

Process multiple documents with the same key for cross-document consistency:

```python
documents = [
    "王五的季度报告：业绩良好",
    "张三对王五的评价：团队协作优秀",
    "王五的下季度目标",
]

# First document generates the key
redacted_docs = []
text, key = redact(documents[0])
redacted_docs.append(text)

# Subsequent documents reuse the key
for doc in documents[1:]:
    text, key = redact(doc, key=key)
    redacted_docs.append(text)

# Send all to LLM
combined = "\n---\n".join(redacted_docs)
llm_output = call_llm(f"Summarize these reviews:\n{combined}")

# Restore
summary = restore(llm_output, key)
```
