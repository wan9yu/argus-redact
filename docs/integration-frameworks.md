# Framework Integration

## LangChain

### Built-in Runnables

argus-redact provides `RedactRunnable` and `RestoreRunnable` that implement the LangChain Runnable protocol. `RestoreRunnable` runs `restore()` with `guard=True` internally — **you must wire `make_prompt_addendum()` into your LLM system message** so the provenance nonce reaches the response; without it, restore fail-closes (returns pseudonyms unchanged + UserWarning, no exception).

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

### With retrieval (RAG)

In RAG pipelines, redact the user query AND the retrieved documents:

```python
from argus_redact import redact, restore

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

    # LLM sees only redacted content
    context = "\n\n".join(redacted_docs)
    prompt = f"Context:\n{context}\n\nQuestion: {redacted_query}"
    llm_output = llm.invoke(prompt).content

    return restore(llm_output, key)
```

**Note:** The retriever uses the ORIGINAL query (for semantic matching accuracy), but the LLM only sees redacted documents. This is a conscious tradeoff — the retriever is local/trusted, the LLM may not be.

---

## LlamaIndex

### As a query transform

argus-redact ships `RedactTransform` and `RestoreTransform` in `argus_redact.integrations.llamaindex`. `RestoreTransform` runs `restore()` with `guard=True` internally — **you must inject `make_prompt_addendum()` into the LLM system message**; without it, restore fail-closes (returns pseudonyms unchanged + UserWarning, no exception).

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

If you build a bare pipeline (without the built-in transforms), the guard flow with `make_anchor` and `prompt_anchor` looks like:

```python
from argus_redact import redact, restore, make_anchor
from argus_redact.compose import prompt_anchor
from llama_index.core import VectorStoreIndex

index = VectorStoreIndex.from_documents(documents)
query_engine = index.as_query_engine()

def safe_query(question: str) -> str:
    redacted, key = redact(question)
    anchor = make_anchor(key)
    system = prompt_anchor(key, anchor=anchor)
    response = query_engine.query(redacted, system_prompt=system)
    return restore(str(response), key, guard=True, anchor=anchor)
```

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
from argus_redact import redact, restore, make_anchor
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

    restored = restore(llm_output, key, guard=True, anchor=anchor)
    return AnalyzeResponse(result=restored)
```

### With request-scoped key management

For multi-step endpoints where redact and restore happen in different functions:

```python
from contextvars import ContextVar
from argus_redact import redact, restore, make_anchor
from argus_redact.compose import prompt_anchor

_request_key: ContextVar[dict] = ContextVar("redact_key")
_request_anchor: ContextVar[object] = ContextVar("redact_anchor")

def redact_for_request(text: str) -> tuple[str, str]:
    redacted, key = redact(text)
    anchor = make_anchor(key)
    _request_key.set(key)
    _request_anchor.set(anchor)
    # Caller appends the returned addendum to the LLM system prompt
    return redacted, prompt_anchor(key, anchor=anchor)

def restore_for_request(text: str) -> str:
    return restore(text, _request_key.get(), guard=True, anchor=_request_anchor.get())
```

---

## Flask

```python
from argus_redact import redact, restore
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/analyze", methods=["POST"])
def analyze():
    text = request.json["text"]

    redacted, key = redact(text)
    llm_output = call_llm(redacted)
    restored = restore(llm_output, key)

    return jsonify({"result": restored})
```

---

## General Integration Pattern

For any framework not listed above, use the guard flow: redact → build prompt with the nonce-echo addendum → LLM → guarded restore.

```python
from argus_redact import redact, restore, make_anchor
from argus_redact.compose import prompt_anchor

# 1. Intercept user input
user_input = get_input_from_framework()

# 2. Redact
redacted, key = redact(user_input)

# 3. Build a per-session anchor and embed its nonce in the LLM system prompt.
#    The LLM will echo the nonce back, allowing restore() to verify the response
#    came from this session (not an injected pseudonym from another context).
anchor = make_anchor(key)
system = your_system_prompt + "\n\n" + prompt_anchor(key, anchor=anchor)

# 4. Pass redacted text and the annotated system prompt through the LLM
llm_output = your_llm(redacted, system=system)

# 5. Restore with guard — fail-closes (returns pseudonyms intact) if nonce missing
result = restore(llm_output, key, guard=True, anchor=anchor)

# 6. Return to user
return_to_framework(result)
```

The key insight: `redact()`, `make_anchor()`, `prompt_anchor()`, and `restore()` are plain functions that take and return strings. They slot into any framework at any point. The guard check adds deterministic provenance verification without requiring framework-specific adapters.
