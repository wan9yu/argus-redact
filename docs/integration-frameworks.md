# Framework Integration

## LangChain

### As a Runnable

Wrap `redact/restore` as LangChain Runnables. Since the key must be shared between the redact and restore steps, use `threading.local` for thread safety:

```python
from argus_redact import redact, restore
from langchain_core.runnables import RunnablePassthrough, RunnableLambda
from langchain_openai import ChatOpenAI
import threading

_keys = threading.local()

def redact_step(text: str) -> str:
    redacted, _keys.current = redact(text)
    return redacted

def restore_step(text: str) -> str:
    return restore(text, _keys.current)

chain = (
    RunnableLambda(redact_step)
    | ChatOpenAI(model="gpt-4o")
    | RunnableLambda(lambda msg: msg.content)
    | RunnableLambda(restore_step)
)
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

```python
from argus_redact import redact, restore
from llama_index.core.query_pipeline import QueryPipeline
from llama_index.core.bridge.pydantic import Field

class RedactTransform:
    """Redact PII before sending to LLM."""

    def __init__(self, lang="zh"):
        self.lang = lang
        self._key = {}

    def __call__(self, query_str: str, **kwargs) -> str:
        redacted, self._key = redact(query_str, lang=self.lang)
        return redacted

class RestoreTransform:
    """Restore PII in LLM output."""

    def __init__(self, redact_transform: RedactTransform):
        self._redact = redact_transform

    def __call__(self, response_str: str, **kwargs) -> str:
        return restore(response_str, self._redact._key)

# Usage
redact_t = RedactTransform(lang="zh")
restore_t = RestoreTransform(redact_t)

pipeline = QueryPipeline(chain=[redact_t, llm, restore_t])
result = pipeline.run("王五在协和医院做了体检")
```

### With index queries

```python
from argus_redact import redact, restore
from llama_index.core import VectorStoreIndex

index = VectorStoreIndex.from_documents(documents)
query_engine = index.as_query_engine()

def safe_query(question: str) -> str:
    redacted, key = redact(question)
    response = query_engine.query(redacted)
    return restore(str(response), key)
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

class RedactMiddleware(BaseHTTPMiddleware):
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

app.add_middleware(RedactMiddleware)
```

### Endpoint-level (simpler)

If middleware is too broad, redact at the endpoint:

```python
from argus_redact import redact, restore
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

    # Call your LLM here
    llm_output = await call_llm(redacted, req.system_prompt)

    restored = restore(llm_output, key)
    return AnalyzeResponse(result=restored)
```

### With request-scoped key management

For multi-step endpoints where redact and restore happen in different functions:

```python
from contextvars import ContextVar
from argus_redact import redact, restore

_request_key: ContextVar[dict] = ContextVar("redact_key")

def redact_for_request(text: str) -> str:
    redacted, key = redact(text)
    _request_key.set(key)
    return redacted

def restore_for_request(text: str) -> str:
    return restore(text, _request_key.get())
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

For any framework not listed above:

```python
from argus_redact import redact, restore

# 1. Intercept user input
user_input = get_input_from_framework()

# 2. Redact
redacted, key = redact(user_input)

# 3. Pass redacted text through your pipeline
output = your_pipeline(redacted)

# 4. Restore
result = restore(output, key)

# 5. Return to user
return_to_framework(result)
```

The key insight: argus-redact doesn't need framework-specific adapters. `redact()` and `restore()` are plain functions that take and return strings. They slot into any framework at any point.
