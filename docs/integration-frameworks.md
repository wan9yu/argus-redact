# Framework Integration

## LangChain

### Built-in Runnables

argus-redact provides `RedactRunnable` and `RestoreRunnable` that implement the LangChain Runnable protocol. `RestoreRunnable` routes through `guarded_restore()` internally — **you must wire `make_prompt_addendum()` into your LLM system message** so the provenance nonce reaches the response; without it, restore fail-closes (returns pseudonyms unchanged + UserWarning, no exception).

`RestoreRunnable(redact_r, strict=True)` opts into fail-closed: a suspected injection or a failed deterministic guard then raises `RestoreGuardError` instead of warning. `strict` is a constructor kwarg, not a per-call one — construct a `RestoreRunnable` per desired strictness.

```python
from argus_redact.integrations.langchain import RedactRunnable, RestoreRunnable
from langchain_core.runnables import RunnableLambda
from langchain_openai import ChatOpenAI

redact_r = RedactRunnable(mode="fast", lang="zh")
restore_r = RestoreRunnable(redact_r)

# Build the chain. The nonce-echo instruction must reach the LLM system prompt.
# With a standalone LLM call you inject it via make_prompt_addendum() (see below).
# In a chain where you control the prompt template, add it to the system message.
chain = (
    redact_r
    | ChatOpenAI(model="gpt-4o")
    | RunnableLambda(lambda msg: msg.content)
    | restore_r
)

result = chain.invoke("张三的电话是13812345678")
```

For standalone usage (without LangChain installed) or when you control the system prompt:

```python
from argus_redact.integrations.langchain import RedactRunnable, RestoreRunnable

redact_r = RedactRunnable(mode="fast", lang="zh")
restore_r = RestoreRunnable(redact_r)

redacted = redact_r.invoke("张三的电话是13812345678")

# Inject the anchor prompt into your LLM system message BEFORE calling the LLM.
# This embeds the nonce so the guard can verify the response came from this session.
anchor_prompt = redact_r.make_prompt_addendum()
llm_output = call_llm(redacted, system=anchor_prompt)

restored = restore_r.invoke(llm_output)
```

```python
# Fail-closed instead of warning, on either a suspected injection (H) or a
# failed deterministic guard (P/S):
from argus_redact import RestoreGuardError

strict_restore_r = RestoreRunnable(redact_r, strict=True)
try:
    restored = strict_restore_r.invoke(llm_output)
except RestoreGuardError as e:
    handle_guard_failure(e.events)
```

### With retrieval (RAG)

In RAG pipelines, redact the user query AND the retrieved documents:

```python
from argus_redact import redact, guarded_restore, make_anchor
from argus_redact.compose import prompt_anchor

def safe_rag(query: str, retriever, llm) -> str:
    # Redact user query
    redacted_query, key = redact(query)

    # Retrieve documents (using original query for best retrieval)
    docs = retriever.invoke(query)

    # Redact retrieved documents with the SAME key
    redacted_docs = []
    for doc in docs:
        rdoc, key = redact(doc.page_content, key=key)
        redacted_docs.append(rdoc)

    # Anchor AFTER the last redact() — the key is only complete now, and the
    # anchor's scope is a snapshot of the key it was built from.
    anchor = make_anchor(key)

    # LLM sees only redacted content
    context = "\n\n".join(redacted_docs)
    prompt = f"Context:\n{context}\n\nQuestion: {redacted_query}"
    llm_output = llm.invoke(
        [("system", prompt_anchor(key, anchor=anchor)), ("human", prompt)]
    ).content

    return guarded_restore(llm_output, key, redacted=prompt, anchor=anchor)
```

**Note:** The retriever uses the ORIGINAL query (for semantic matching accuracy), but the LLM only sees redacted documents. This is a conscious tradeoff — the retriever is local/trusted, the LLM may not be.

RAG is also where the guard earns its keep: retrieved documents are attacker-reachable in a way the user's own query is not. A poisoned document that instructs the model to emit pseudonyms into a URL is exactly the case `guarded_restore()`'s scope binding (S) and injection heuristic (H) are looking at. Consider `strict=True` here.

---

## LlamaIndex

### As a query transform

argus-redact ships `RedactTransform` and `RestoreTransform` in `argus_redact.integrations.llamaindex`. `RestoreTransform` routes through `guarded_restore()` internally — **you must inject `make_prompt_addendum()` into the LLM system message**; without it, restore fail-closes (returns pseudonyms unchanged + UserWarning, no exception).

`RestoreTransform(redact_t, strict=True)` opts into fail-closed: a suspected injection or a failed deterministic guard then raises `RestoreGuardError` instead of warning. Like `RestoreRunnable`, `strict` is a constructor kwarg — construct a separate `RestoreTransform` for the strictness you want.

```python
from argus_redact.integrations.llamaindex import RedactTransform, RestoreTransform

redact_t = RedactTransform(mode="fast", lang="zh")
restore_t = RestoreTransform(redact_t)

redacted = redact_t("王五在协和医院做了体检")

# Inject the anchor prompt into the LLM system message BEFORE calling the LLM.
anchor_prompt = redact_t.make_prompt_addendum()
llm_output = call_llm(redacted, system=anchor_prompt)

restored = restore_t(llm_output)
```

```python
# Fail-closed instead of warning, on either a suspected injection (H) or a
# failed deterministic guard (P/S):
from argus_redact import RestoreGuardError

strict_restore_t = RestoreTransform(redact_t, strict=True)
try:
    restored = strict_restore_t(llm_output)
except RestoreGuardError as e:
    handle_guard_failure(e.events)
```

If you build a bare pipeline (without the built-in transforms), the guard flow with `make_anchor` and `prompt_anchor` looks like:

```python
from argus_redact import redact, guarded_restore, make_anchor
from argus_redact.compose import prompt_anchor
from llama_index.core import VectorStoreIndex

index = VectorStoreIndex.from_documents(documents)
query_engine = index.as_query_engine()

def safe_query(question: str) -> str:
    redacted, key = redact(question)
    anchor = make_anchor(key)
    system = prompt_anchor(key, anchor=anchor)
    response = query_engine.query(redacted, system_prompt=system)
    return guarded_restore(str(response), key, redacted=redacted, anchor=anchor)
```

Passing `redacted=` is what enables the supplementary injection heuristic (H). `restore(..., guard=True, anchor=anchor)` gives you the deterministic P+S guard but silently runs no H check at all, because it has nothing to compare the reply against — `guarded_restore()` is the one call that wires up the whole flow.

---

## FastAPI

### Middleware

Automatically redact request bodies and restore response bodies:

```python
from argus_redact import redact, restore
from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
import json

app = FastAPI()

class RedactBodyMiddleware(BaseHTTPMiddleware):
    """Redact PII in request body, restore in response body."""

    async def dispatch(self, request: Request, call_next):
        # Read and redact request body
        body = await request.body()
        if body:
            text = body.decode("utf-8")
            try:
                data = json.loads(text)
                if "text" in data:
                    redacted, key = redact(data["text"])
                    data["text"] = redacted
                    data["_redact_key"] = key  # pass key through
                    # Reconstruct request with redacted body
                    request._body = json.dumps(data).encode()
            except (json.JSONDecodeError, KeyError):
                pass

        response = await call_next(request)
        return response

app.add_middleware(RedactBodyMiddleware)
```

**Limitations and future directions:** The `messages` helper requires each message to be a `dict` with a string `content` key. It fails closed (raises `TypeError`) on other shapes — bare-string elements, dicts without a `content` key (such as OpenAI tool/function-call messages whose payload lives in `tool_calls` or `arguments`), and dicts with a list `content` (multimodal messages). Recursive redaction of text parts inside multimodal `content` arrays and tool-call argument strings is a future direction.

### Endpoint-level (simpler)

If middleware is too broad, redact at the endpoint. Use the guard flow so injected pseudonyms in LLM output do not silently restore:

```python
from argus_redact import redact, guarded_restore, make_anchor
from argus_redact.compose import prompt_anchor
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class AnalyzeRequest(BaseModel):
    text: str
    system_prompt: str = "You are a helpful assistant."

class AnalyzeResponse(BaseModel):
    result: str

@app.post("/analyze")
async def analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    redacted, key = redact(req.text)
    anchor = make_anchor(key)

    # Append the nonce-echo instruction to the system prompt
    system = req.system_prompt + "\n\n" + prompt_anchor(key, anchor=anchor)

    llm_output = await call_llm(redacted, system)

    restored = guarded_restore(llm_output, key, redacted=redacted, anchor=anchor)
    return AnalyzeResponse(result=restored)
```

If a fail-closed restore should be a failed request rather than a response full of pseudonyms, pass `strict=True` and map `RestoreGuardError` to an HTTP error:

```python
from argus_redact import RestoreGuardError
from fastapi import HTTPException

try:
    restored = guarded_restore(
        llm_output, key, redacted=redacted, anchor=anchor, strict=True
    )
except RestoreGuardError as e:
    raise HTTPException(status_code=502, detail=[ev["reason_code"] for ev in e.events])
```

### With request-scoped key management

For multi-step endpoints where redact and restore happen in different functions:

```python
from contextvars import ContextVar
from argus_redact import redact, guarded_restore, make_anchor
from argus_redact.compose import prompt_anchor

_request_key: ContextVar[dict] = ContextVar("redact_key")
_request_anchor: ContextVar[object] = ContextVar("redact_anchor")
_request_redacted: ContextVar[str] = ContextVar("redact_prompt")

def redact_for_request(text: str) -> tuple[str, str]:
    redacted, key = redact(text)
    anchor = make_anchor(key)
    _request_key.set(key)
    _request_anchor.set(anchor)
    # Stash the redacted prompt too — guarded_restore needs it to run the H check,
    # and it holds pseudonyms only, so it is strictly less sensitive than the key
    # already in this context.
    _request_redacted.set(redacted)
    # Caller appends the returned addendum to the LLM system prompt
    return redacted, prompt_anchor(key, anchor=anchor)

def restore_for_request(text: str) -> str:
    return guarded_restore(
        text,
        _request_key.get(),
        redacted=_request_redacted.get(),
        anchor=_request_anchor.get(),
    )
```

---

## Flask

```python
from argus_redact import redact, guarded_restore, make_anchor
from argus_redact.compose import prompt_anchor
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/analyze", methods=["POST"])
def analyze():
    text = request.json["text"]

    redacted, key = redact(text)
    anchor = make_anchor(key)

    llm_output = call_llm(redacted, system=prompt_anchor(key, anchor=anchor))
    restored = guarded_restore(llm_output, key, redacted=redacted, anchor=anchor)

    return jsonify({"result": restored})
```

The key and anchor live for the duration of one request. Do not park them in a module-level dict keyed by session id and reuse the anchor across requests — a fresh nonce per LLM call is what makes provenance mean anything.

---

## MCP server

argus-redact ships an MCP server that exposes `redact`, `restore`, `assess` and `info` as tools:

```bash
python -m argus_redact.integrations.mcp_server
```

```json
{
  "mcpServers": {
    "argus-redact": {
      "command": "python",
      "args": ["-m", "argus_redact.integrations.mcp_server"]
    }
  }
}
```

Requires the MCP extra: `pip install argus-redact[mcp]`.

### The round-trip across the tool boundary

The raw key never crosses into the model's context. `redact` returns a **`key_token`** instead — a short-lived handle to a process-local entry holding the key, the anchor and the redacted prompt. `restore` takes the token back. Tokens are scoped to the server process (a restart invalidates them), expire on an idle timeout, and the store is LRU-bounded, so an old token cannot be replayed indefinitely.

`redact` returns three fields:

| Field | Meaning |
|---|---|
| `redacted` | The redacted text. |
| `key_token` | Pass to `restore`. The key itself never enters the model's context. |
| `anchor_prompt` | **The system-prompt addendum you must inject before the LLM call.** Empty string when no PII was detected. |

**`anchor_prompt` is not optional.** It carries the nonce-echo instruction, and `restore` is guard-by-default: if the reply does not contain the nonce, restore fail-closes and hands back the **un-restored** text plus a `security_events` field. An MCP client that ignores `anchor_prompt` will find that restore never restores anything. Inject it as a system message for the call that consumes the redacted text.

### The `restore` tool

```
restore(text: str, key_token: str, strict: bool = False) -> JSON
```

- **Guard-by-default.** Provenance (P) and scope (S) are always enforced: the nonce from `anchor_prompt` must be present, and only the pseudonyms from that `redact` call are restored.
- **Runs the injection heuristic (H)** (new in v0.7.20). The server retains the redacted prompt alongside the token — pseudonyms only, no originals — which is what H needs to compare the reply against. H is **advisory**: it reports, it does not block.
- **`strict`.** When true, the tool raises instead of returning on *any* security event — the deterministic guard (P/S) *and* a suspected injection (H) — before any original is substituted. The failure surfaces as an MCP tool error rather than a normal-looking payload.
- **`security_events`.** The JSON payload is `{"restored": ...}`, plus a `security_events` list whenever the guard or the heuristic had something to say. Each event carries a `reason_code`, a `count` and a `detail`. An empty/absent list means a clean round-trip.

A client should treat a `security_events` field as a signal to *not* forward the result onward unexamined — it means either something was withheld, or something looked wrong.

An expired or unknown `key_token` is an error, not a silent no-op: re-run `redact` to obtain a fresh one.

---

## General Integration Pattern

For any framework not listed above, use the guard flow: redact → build prompt with the nonce-echo addendum → LLM → guarded restore.

```python
from argus_redact import redact, guarded_restore, make_anchor
from argus_redact.compose import prompt_anchor

# 1. Intercept user input
user_input = get_input_from_framework()

# 2. Redact
redacted, key = redact(user_input)

# 3. Build a per-call anchor and embed its nonce in the LLM system prompt.
#    The LLM echoes the nonce back, which is how the guard verifies the reply
#    came from this call (and not from an injected pseudonym in another context).
#    Mint a fresh anchor per LLM call — never reuse one across turns.
anchor = make_anchor(key)
system = your_system_prompt + "\n\n" + prompt_anchor(key, anchor=anchor)

# 4. Pass redacted text and the annotated system prompt through the LLM
llm_output = your_llm(redacted, system=system)

# 5. Restore under the guard. Fail-closes (returns pseudonyms intact + a
#    SecurityWarning) if the nonce is missing or an out-of-scope pseudonym shows
#    up. Passing redacted= also enables the advisory injection heuristic (H).
#    strict=True raises RestoreGuardError instead of returning.
result = guarded_restore(llm_output, key, redacted=redacted, anchor=anchor)

# 6. Return to user
return_to_framework(result)
```

The key insight: `redact()`, `make_anchor()`, `prompt_anchor()`, and `guarded_restore()` are plain functions that take and return strings. They slot into any framework at any point. The guard adds deterministic provenance and scope verification without requiring framework-specific adapters.

**`guarded_restore()`:** every integration this project ships (LangChain, LlamaIndex, Presidio, FastAPI, the MCP server) routes its restore step through `guarded_restore()` rather than calling `restore()` directly — it is the one place the whole flow (H → fail-closed-if-strict → P+S guard → merged events → surfaced warning) is assembled, instead of copy-pasted per integration. If you're wiring a framework not listed above, prefer `guarded_restore()` over composing `restore()` yourself; see its entry in [`api-reference.md`](api-reference.md#guarded_restore-v0720).
