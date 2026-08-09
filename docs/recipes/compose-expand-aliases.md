# Recipe: `compose.expand_aliases`

> v0.6.9+ · part of `argus_redact.compose`

## 30-second pitch

When an LLM emits `黄先生` instead of the placeholder `P-83811`, your
post-LLM `restore()` can't find the substring `P-83811` in the output —
the name slips through unrestored.

`expand_aliases(key, lang)` returns a copy of your redaction key dict
with **surname + title composite aliases** added. Each alias maps to the
original name. Now `restore(llm_output, expanded_key)` resolves `黄先生`
→ `黄芳` in a single pass.

Conservative: only composite forms (e.g., `黄先生`), never bare surname
(`黄` alone is a common character). Handles compound zh surnames
(`欧阳锋` → `欧阳先生`) and multi-token en names (`John F. Smith`
→ `Mr. Smith`).

## Usage

```python
from argus_redact import redact
from argus_redact.compose import expand_aliases, make_anchor, guarded_restore

text = "黄芳的电话13912345678"
redacted, key = redact(text, names=["黄芳"], lang="zh", salt=42)
# key = {"P-83811": "黄芳", "139****5678": "13912345678"}

# expand_aliases adds surname+title variants (黄先生 → 黄芳) as extra key entries,
# so a retitle the model emits still maps back. Build the anchor from the
# EXPANDED key so those new entries are in scope.
expanded = expand_aliases(key, lang="zh")
anchor_obj = make_anchor(expanded)

# Send `redacted` to the LLM with a prompt_anchor addendum (see the sibling
# recipe). The model retitled 黄芳 → 黄先生 and echoed the anchor nonce:
llm_output = f"你好黄先生，请确认 139****5678 这个号码\n{anchor_obj.nonce}"

restored = guarded_restore(llm_output, expanded, anchor=anchor_obj)
# → "你好黄芳，请确认 13912345678 这个号码" ✓  (nonce stripped)

# Without expand_aliases, "黄先生" is not a key entry at all — nothing maps it
# back, so the phone restores but the name stays "黄先生".
```

## Titles included

| Language | Titles |
|---|---|
| `zh` | 先生 / 女士 / 总 / 老师 / 医生 |
| `en` | Mr. / Mrs. / Ms. / Dr. / Prof. |

Locked in v0.6.9. Configurable title lists are a v0.6.10+ candidate.

## When to use

- Creative LLM tasks where the LLM may use surname+title forms
- After `prompt_anchor` (input-side anchoring) — `expand_aliases` is the
  output-side safety net

## Limitations

- **No pronouns / kinship / nicknames.** "他/她" / "uncle" / "Joey" are
  out of scope per `docs/architecture-layers.md` §Layer 2. Use a
  coreference-aware downstream layer (e.g., Argus Gateway) for fuller
  semantic round-trip.
- **Conservative title list.** If your LLM commonly uses `总经理` or
  `教授` or `Sir`, current v0.6.9 does NOT cover those. Caller can
  post-process: `expanded |= {f"{surname}总经理": original ...}`.
- **Single-char zh surnames default.** "张三" → surname "张", aliases like
  "张先生". For compound surnames, the implementation includes the 10
  most common ones from《百家姓》(欧阳/司马/诸葛/上官/夏侯/公孙/皇甫/
  尉迟/东方/西门). Other compound surnames default to single-char extraction.
- **Empty key → empty dict.** No surprises.

## Combining with `prompt_anchor`

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

The `prompt_anchor` reduces variant generation at the source; the
`expand_aliases` catches the variants that slip through. Use both for
best R-creative.
