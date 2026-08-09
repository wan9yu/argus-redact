# Recipe: `compose.prompt_anchor`

> v0.6.9+ · part of `argus_redact.compose`

## 30-second pitch

When you send redacted text to an LLM for a *creative* task (summarize,
advise, rewrite), the LLM may abbreviate placeholders (`P-83811` → "the
person") or retitle persons (`黄芳` → "黄先生"). Your post-LLM `restore()`
then can't find the original substring.

`prompt_anchor` returns a short system-prompt addendum that explicitly
tells the LLM to preserve placeholders verbatim. Combined with
`expand_aliases` (sibling recipe), it raises R-creative without changing
your detection pipeline.

## Usage

```python
from argus_redact import redact
from argus_redact.compose import prompt_anchor, make_anchor, guarded_restore

text = "张三的电话13812345678"
redacted, key = redact(text, names=["张三"], lang="zh", salt=42)

anchor_obj = make_anchor(key)                              # fresh per-exchange nonce + scope
anchor = prompt_anchor(key, lang="zh", anchor=anchor_obj)
# Multi-line string: the 3 rules + the identifier list, plus a line asking the
# model to echo anchor_obj.nonce back verbatim.

# Prepend to your system prompt:
system_prompt = f"You are a helpful assistant.\n\n{anchor}"

# Send to LLM... receive response... then restore through the guard:
llm_output = call_llm(system_prompt, user_msg=redacted)
restored = guarded_restore(llm_output, key, anchor=anchor_obj)
# guarded_restore fails closed if the model dropped the nonce (provenance) or
# emitted an out-of-scope pseudonym (scope). Since v0.8.0 a bare restore(text,
# key) also fails closed without an anchor — see docs/security-model.md.
```

## When to use

- LLM call is a *creative* task (R-creative): summarize, advise, paraphrase,
  rewrite, translate
- You want the LLM to keep placeholders exact

## When NOT to use

- LLM call is a *reference* task (R-reference): direct quote, fact extraction.
  The LLM already echoes the placeholder verbatim; the prompt adds nothing.
- Multi-turn tool_use: the placeholder may live in tool-call args; this prompt
  doesn't address tool-call state. Use a coreference-aware downstream layer
  (e.g., Argus Gateway) for that.

## Limitations

- **The LLM may ignore the prompt.** This is not a guarantee — it's a hint.
  Empirically improves but does not eliminate retitle / abbreviate behavior.
  Combine with `expand_aliases` for output-side resilience.
- **Empty key → empty addendum.** No identifiers, no work needed.
- **The template is locked.** v0.6.9 ships a fixed 3-rule template (zh + en).
  Configurable templates are a v0.6.10+ candidate if user demand surfaces.

## Combining with `expand_aliases`

```python
from argus_redact.compose import (
    prompt_anchor, expand_aliases, make_anchor, guarded_restore,
)

key_for_restore = expand_aliases(key, lang="zh")             # output-side
anchor_obj = make_anchor(key_for_restore)                    # scope covers the aliases
anchor = prompt_anchor(key, lang="zh", anchor=anchor_obj)    # input-side

# ... LLM call with anchor in system prompt ...
restored = guarded_restore(llm_output, key_for_restore, anchor=anchor_obj)
```

Input-side reduces variant generation at the source; output-side catches
the variants that slip through.
