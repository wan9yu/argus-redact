# LLM Pipeline Integration

## Core Pattern

Every LLM integration follows the same round-trip:

```
plaintext → redact() → redacted text → LLM → LLM reply → guarded_restore() → plaintext
```

```python
from argus_redact import redact, guarded_restore, make_anchor
from argus_redact.compose import prompt_anchor

# 1. Redact the user input. `key` maps pseudonym → original and never leaves your process.
redacted, key = redact(user_input)

# 2. Mint a per-call anchor: a fresh random nonce + the set of pseudonyms this call owns.
anchor = make_anchor(key)

# 3. Put the anchor instruction in the system prompt. It asks the model to keep the
#    pseudonyms verbatim AND to echo the nonce back on its own line at the end.
system = my_system_prompt + "\n\n" + prompt_anchor(key, lang="zh", anchor=anchor)

# 4. Call whatever LLM you already use.
llm_reply = call_any_llm(redacted, system=system)

# 5. Restore under the guard.
result = guarded_restore(llm_reply, key, redacted=redacted, anchor=anchor)
```

The middle step — `call_any_llm` — is whatever you already use. argus-redact doesn't care which provider, model, or SDK. Steps 2, 3 and 5 are the part that is easy to skip and worth not skipping; the rest of this section explains why.

### Why the guard exists

The naive pipeline restores every model reply automatically. That turns `restore()` into an oracle sitting at the end of your pipeline: it will substitute a real name, phone number or address into *any* text that happens to contain the right pseudonym.

A prompt injection — hidden in a retrieved document, a pasted email, a web page your agent fetched — can exploit that. The model is told to emit `P-037` inside a URL, a footnote or a "please confirm your details" line, your pipeline restores it into the real value, and the plaintext lands wherever that reply goes next: a chat window, a log, a tool call, an outbound HTTP request. The redaction did its job on the way *in*; the un-guarded restore undoes it on the way *out*.

`guarded_restore()` runs three checks, in order:

| | Check | What it does | Default |
|---|---|---|---|
| **H** | Injection heuristic | Flags suspicious pseudonym usage in the reply (frequency amplification, pseudonyms next to URLs/emails/exfiltration verbs). | **Advisory** — warns, does not block. `strict=True` makes it fail closed. Runs only if you pass `redacted=`. |
| **P** | Provenance | The nonce from `make_anchor(key)` must appear in the reply. No nonce → no restore. | Fail-closed |
| **S** | Scope binding | Only the pseudonyms belonging to *this* call are restored. A pseudonym from another call or another user is withheld. | Fail-closed |

**P and S are the deterministic guarantee. H is a heuristic and is treated as one** — it is advisory by default and is never promoted to the guarantee. None of this makes the pipeline injection-proof; it removes the automatic restore-anything oracle at the end of it.

When P or S trips, `guarded_restore()` **returns the text un-restored** (pseudonyms intact) and emits a `SecurityWarning`. It does not raise — unless you pass `strict=True`, which raises `RestoreGuardError` instead, on any event including H.

```python
from argus_redact import RestoreGuardError, guarded_restore

try:
    result = guarded_restore(llm_reply, key, redacted=redacted, anchor=anchor, strict=True)
except RestoreGuardError as e:
    handle_guard_failure(e.events)   # e.events: list of {"reason_code", "count", "detail"}
```

Or inspect the events without raising:

```python
result, details = guarded_restore(
    llm_reply, key, redacted=redacted, anchor=anchor, detailed=True
)
for event in details["security_events"]:
    log.warning("restore guard: %s (%s)", event["reason_code"], event["detail"])
```

### The nonce must reach the model

`prompt_anchor(key, lang=..., anchor=anchor)` is not optional decoration. It is what puts the nonce in the model's context so the model can echo it back. **Skip it and provenance (P) fails, so `guarded_restore()` fail-closes and hands you back un-restored pseudonyms.** If your restored output suddenly still contains `P-037`, that is the first thing to check.

`lang` accepts `"zh"` (default) or `"en"`; unknown values fall back to English. It returns an empty string when the key is empty (nothing was detected — nothing to anchor).

### `guard=True` is the default — a bare restore fails closed

**Since v0.8.0, `guard=True` is the default.** A bare `restore(text, key)` with no
`anchor` now fails closed: it returns the text **un-restored** and reports a
`guard_no_anchor` security event, instead of the pre-v0.8.0 behavior of a plain,
unchecked substitution plus a `DeprecationWarning`. Two ways forward:

```python
from argus_redact import guarded_restore, restore

# Recommended: the guarded round-trip.
result = guarded_restore(llm_reply, key, redacted=redacted, anchor=anchor)

# Explicit legacy opt-out — plain, unchecked string substitution, no warning, no
# guard. Appropriate when the text did not come back from an untrusted model at
# all (offline batch de-pseudonymisation, tests, fixtures).
result = restore(some_text, key, guard=False)
```

Do not leave bare `restore(text, key)` calls in an LLM pipeline: without an anchor
they now silently do nothing (fail closed) rather than silently restoring
unchecked.

---

## OpenAI

### Chat Completions

```python
from argus_redact import redact, guarded_restore, make_anchor
from argus_redact.compose import prompt_anchor
from openai import OpenAI

client = OpenAI()

def safe_chat(text: str, system: str = "You are a helpful assistant.") -> str:
    redacted, key = redact(text)
    anchor = make_anchor(key)

    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": system + "\n\n" + prompt_anchor(key, anchor=anchor)},
            {"role": "user", "content": redacted},
        ],
    )

    return guarded_restore(
        response.choices[0].message.content, key, redacted=redacted, anchor=anchor
    )

answer = safe_chat(
    "王五在协和医院做了体检，结果显示血压偏高",
    system="You are a health advisor. Give brief advice.",
)
# LLM sees: "P-037在[医院]做了体检，结果显示血压偏高" plus the anchor instruction
# LLM responds about P-037 and echoes the nonce on the last line
# guarded_restore() verifies the nonce, strips it, and returns advice with
# 王五 and 协和医院 restored
```

### Streaming

```python
def safe_chat_stream(text: str, system: str) -> str:
    redacted, key = redact(text)
    anchor = make_anchor(key)

    stream = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": system + "\n\n" + prompt_anchor(key, anchor=anchor)},
            {"role": "user", "content": redacted},
        ],
        stream=True,
    )

    # Collect full response, then restore
    chunks = []
    for chunk in stream:
        content = chunk.choices[0].delta.content or ""
        chunks.append(content)

    full_reply = "".join(chunks)
    return guarded_restore(full_reply, key, redacted=redacted, anchor=anchor)
```

**Why collect-then-restore?** Two reasons. Streaming chunks may split a pseudonym across chunks (`P-0` in one chunk, `37` in the next), so restore needs the complete text to match pseudonyms reliably. And the guard is defined over the whole reply: the model echoes the nonce at the end, so provenance can only be decided once the reply is complete.

That means **you cannot run the guard on a per-sentence basis while streaming.** If you want live output, stream the *redacted* text to the user — pseudonyms are safe to display and to log — and swap in the restored version once the reply finishes:

```python
def safe_stream_to_user(text: str, system: str):
    redacted, key = redact(text)
    anchor = make_anchor(key)

    stream = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": system + "\n\n" + prompt_anchor(key, anchor=anchor)},
            {"role": "user", "content": redacted},
        ],
        stream=True,
    )

    chunks = []
    for chunk in stream:
        content = chunk.choices[0].delta.content or ""
        chunks.append(content)
        yield {"partial": content}       # still pseudonymised — no PII on this path

    full_reply = "".join(chunks)
    # One guarded restore over the complete reply; the UI replaces the streamed
    # placeholder text with this final value.
    yield {"final": guarded_restore(full_reply, key, redacted=redacted, anchor=anchor)}
```

Two things to know about that shape. The streamed chunks carry the echoed verification token at the end of the reply (it is not secret, but it is not meant for the user either — `guarded_restore()` strips it from the value it returns, so only the streamed view shows it). And if you restore sentence-by-sentence instead, you are back to the un-guarded oracle: every fragment gets substituted with no provenance check. Restoring incrementally and guarding the round-trip are mutually exclusive — pick which one you need.

### Multi-turn Conversations

Each turn gets its own key (default behavior) — and its own anchor. **Mint a fresh anchor per LLM call, even when the key is shared:** the nonce is what binds a reply to the call that produced it, so reusing one across turns would let an earlier reply's nonce vouch for a later one.

```python
# Turn 1
redacted1, key1 = redact("王五在协和医院体检了")
anchor1 = make_anchor(key1)
reply1 = call_llm(redacted1, system=prompt_anchor(key1, anchor=anchor1))
restored1 = guarded_restore(reply1, key1, redacted=redacted1, anchor=anchor1)

# Turn 2 — new key, new pseudonyms, new anchor
redacted2, key2 = redact("他的同事张三也去了")
anchor2 = make_anchor(key2)
reply2 = call_llm(redacted2, system=prompt_anchor(key2, anchor=anchor2))
restored2 = guarded_restore(reply2, key2, redacted=redacted2, anchor=anchor2)
```

If turns need to reference each other, share the key — but still take a fresh anchor each turn:

```python
# Turn 1
redacted1, key = redact("王五在协和医院体检了")
anchor1 = make_anchor(key)
reply1 = call_llm(redacted1, system=prompt_anchor(key, anchor=anchor1))

# Turn 2 — same key, 王五 stays P-037; new anchor over the (now larger) key
redacted2, key = redact("他的同事张三也去了同一家医院", key=key)
anchor2 = make_anchor(key)
prompt2 = f"Context: {redacted1}\nNew: {redacted2}"
reply2 = call_llm(prompt2, system=prompt_anchor(key, anchor=anchor2))

# `redacted=` is the text this reply is being judged against — pass the prompt the
# model actually saw, so the H heuristic compares like with like.
restored2 = guarded_restore(reply2, key, redacted=prompt2, anchor=anchor2)
```

`make_anchor(key)` snapshots the key's pseudonyms as the call's scope, so build it *after* the `redact()` call that grew the key — an anchor minted too early scopes out the new entities and the guard withholds them.

**Security tradeoff:** Sharing keys across turns makes them linkable. The cloud provider can see that turns 1 and 2 involve the same P-037. Use only when cross-turn coherence is needed.

---

## Anthropic (Claude)

```python
from argus_redact import redact, guarded_restore, make_anchor
from argus_redact.compose import prompt_anchor
import anthropic

client = anthropic.Anthropic()

def safe_claude(text: str, system: str) -> str:
    redacted, key = redact(text)
    anchor = make_anchor(key)

    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        system=system + "\n\n" + prompt_anchor(key, anchor=anchor),
        messages=[{"role": "user", "content": redacted}],
    )

    return guarded_restore(message.content[0].text, key, redacted=redacted, anchor=anchor)
```

### With tool use

When the model returns tool calls, the tool arguments need restoring too — and they are the *most* injection-sensitive surface in the whole pipeline, because a restored value there does not go to a human who might notice it, it goes straight into an outbound action (an HTTP call, a database write, an email).

The guard is defined over the reply as a whole, so run it once over the concatenated text blocks (that is where the model echoes the nonce), and only proceed to substitute into the tool arguments if that restore was not withheld. `strict=True` is a reasonable default here — a failed guard on an outbound tool call should stop the pipeline, not warn into a log.

```python
from argus_redact import RestoreGuardError, restore

def safe_claude_with_tools(text: str, tools: list) -> dict:
    redacted, key = redact(text)
    anchor = make_anchor(key)

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        system=prompt_anchor(key, anchor=anchor),
        messages=[{"role": "user", "content": redacted}],
        tools=tools,
    )

    # Verify provenance over the whole reply first. Raises RestoreGuardError if the
    # nonce is absent, an out-of-scope pseudonym showed up, or H flagged the reply.
    reply_text = "".join(b.text for b in response.content if b.type == "text")
    guarded_restore(reply_text, key, redacted=redacted, anchor=anchor, strict=True)

    # Provenance holds — now substitute inside the tool arguments. The guard has
    # already run for this reply; guard=False here is the explicit opt-out, not a
    # forgotten one.
    for block in response.content:
        if block.type == "tool_use":
            for arg_key, arg_value in block.input.items():
                if isinstance(arg_value, str):
                    block.input[arg_key] = restore(arg_value, key, guard=False)

    return response
```

Note what this does *not* give you: the guard verifies the reply came from this call and restores only this call's pseudonyms. It does not judge whether the tool call itself is a good idea. A model that has been talked into calling `send_email` will still call `send_email` — with the real address restored, because that address is legitimately in scope. Treat tool arguments as untrusted regardless.

---

## Local LLMs (Ollama, llama.cpp, vLLM)

With local LLMs, redaction is technically unnecessary — data never leaves your device. But it's still useful for:

1. **Defense in depth** — if your local LLM server is misconfigured and logs prompts
2. **Consistent pipeline** — same code works for local and cloud LLMs
3. **Testing** — validate redaction quality before switching to a cloud model

4. **The guard still applies** — a local model can be prompt-injected just as easily as a hosted one; the injection usually arrives in the *content* (a retrieved document, a pasted email), not from the provider.

### Ollama

```python
from argus_redact import redact, guarded_restore, make_anchor
from argus_redact.compose import prompt_anchor
import requests

def safe_ollama(text: str, model: str = "qwen2.5:7b") -> str:
    redacted, key = redact(text)
    anchor = make_anchor(key)

    response = requests.post("http://localhost:11434/api/generate", json={
        "model": model,
        "system": prompt_anchor(key, anchor=anchor),
        "prompt": redacted,
        "stream": False,
    })

    return guarded_restore(response.json()["response"], key, redacted=redacted, anchor=anchor)
```

### llama.cpp (via llama-cpp-python)

**Note:** `llama-cpp-python` is not a dependency of argus-redact — install it separately (`pip install llama-cpp-python`) if you use this local-LLM example.

```python
from argus_redact import redact, guarded_restore, make_anchor
from argus_redact.compose import prompt_anchor
from llama_cpp import Llama

llm = Llama(model_path="./models/qwen2.5-7b-q4.gguf")

def safe_local(text: str) -> str:
    redacted, key = redact(text)
    anchor = make_anchor(key)

    prompt = prompt_anchor(key, anchor=anchor) + "\n\n" + redacted
    output = llm(prompt, max_tokens=512)

    return guarded_restore(
        output["choices"][0]["text"], key, redacted=redacted, anchor=anchor
    )
```

**Small models and the nonce.** Provenance depends on the model reliably echoing a 32-character hex token on its own line. Larger instruction-tuned models do this consistently; small quantized ones sometimes drop or mangle it, and the guard then fail-closes on a perfectly honest reply. If you see that, the fix is to make the instruction more prominent for that model (or to raise `max_tokens` so the reply is not truncated before the token) — not to drop the guard. Verify the round-trip against the specific model you deploy.

---

## System Prompts

**Don't redact system prompts** — they don't contain user PII. But the system prompt *is* where the anchor addendum goes:

```python
system = "You are a career coach. Give specific, actionable advice."
redacted, key = redact(user_input)  # only redact user input
anchor = make_anchor(key)

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[
        # plaintext — no PII — plus the anchor instruction (keep pseudonyms
        # verbatim; echo the nonce back)
        {"role": "system", "content": system + "\n\n" + prompt_anchor(key, anchor=anchor)},
        {"role": "user", "content": redacted},        # redacted
    ],
)
```

`prompt_anchor()` returns the addendum as a plain string, so append it wherever your framework puts system instructions — a `system=` kwarg, a system message, a prompt-template variable. It does not have to be a *separate* message.

Do not put the real identities in the system prompt to "help" the model:

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
anchor = make_anchor(key)
llm_reply = call_llm(redacted, system=prompt_anchor(key, anchor=anchor))
restored = guarded_restore(llm_reply, key, redacted=redacted, anchor=anchor)

# Show user the restored version
print(restored)

# Log the redacted version (no PII in logs)
log.info(f"Input: {redacted}")
log.info(f"Output: {llm_reply}")  # still contains pseudonyms, safe to log
```

The raw reply is the safe thing to log precisely *because* it has not been through restore. Log it before the restore, not after.

---

## Error Handling

```python
from argus_redact import RestoreGuardError, guarded_restore, make_anchor, redact
from argus_redact.compose import prompt_anchor

try:
    redacted, key = redact(user_input)
except ValueError:
    # Language pack not installed — fall back to fast mode (regex only)
    redacted, key = redact(user_input, mode="fast")

anchor = make_anchor(key)
llm_reply = call_llm(redacted, system=prompt_anchor(key, anchor=anchor))

restored = guarded_restore(llm_reply, key, redacted=redacted, anchor=anchor)
```

The substitution itself is plain string replacement and does not fail. **The guard can, and that is the point** — so `guarded_restore()` has two failure modes you should handle deliberately:

- **Fail-closed (default).** The nonce is missing, or a pseudonym from outside this call showed up. You get the text back **un-restored** (pseudonyms intact) plus a `SecurityWarning`. No exception. If your code assumes the return value is always plaintext, this is where it will quietly show `P-037` to a user.
- **`strict=True`.** The same conditions — plus a suspected injection flagged by H — raise `RestoreGuardError` instead. `e.events` carries the reason codes.

Pick one on purpose:

```python
# Fail-closed, keep serving: the user sees pseudonyms rather than nothing.
restored = guarded_restore(llm_reply, key, redacted=redacted, anchor=anchor)
if any(p in restored for p in key):
    log.warning("restore withheld — serving pseudonymised reply")

# Or: stop the pipeline.
try:
    restored = guarded_restore(llm_reply, key, redacted=redacted, anchor=anchor, strict=True)
except RestoreGuardError as e:
    return error_response(e.events)
```

If the reply simply contains no pseudonyms, that is not an error — the guard still checks provenance, and a clean reply comes back unchanged.

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

# Anchor AFTER the last redact() call — the key is only complete now, and the
# anchor's scope is a snapshot of the key it was built from.
anchor = make_anchor(key)

# Send all to LLM
combined = "\n---\n".join(redacted_docs)
prompt = f"Summarize these reviews:\n{combined}"
llm_reply = call_llm(prompt, system=prompt_anchor(key, anchor=anchor))

# Restore
summary = guarded_restore(llm_reply, key, redacted=prompt, anchor=anchor)
```
