"""A minted pseudonym code must never re-issue a code already present in the
source document.

`redact("老客户P-83811推荐了新客户王芳", lang="zh", salt=42)` used to mint
`P-83811` for 王芳 — colliding with the `P-83811` the document already carried
verbatim. The restore key then held `{"P-83811": "王芳"}`, so `restore()`
rewrote BOTH the minted code AND the document's own literal `P-83811` to 王芳,
silently corrupting the pre-existing token (a wrong-identity splice).

The fix seeds the document's pre-existing `<PREFIX>-<digits>` codes into the
generator's reserved set before minting, so the minted code is forced off any
value already in the text. The CJK-adjacent boundary (`户P-83811`, no ASCII
word boundary) is exactly the case a Unicode `\\b`-style check would miss, so it
is the one pinned here.

Restore half uses `guard=False`: a bare guarded restore with no anchor fails
closed and returns the text unchanged (which would pass the survival assertion
vacuously), so the explicit opt-out is required to actually exercise the
substitution path.
"""

from argus_redact import redact, restore


def test_redact_should_not_reissue_a_code_already_in_the_document():
    text = "老客户P-83811推荐了新客户王芳"
    out, key = redact(text, lang="zh", salt=42)
    # 王芳 must NOT be minted as P-83811 (already in the document): the count of
    # P-83811 in the output must not exceed the count already in the input.
    assert out.count("P-83811") == text.count("P-83811")
    # The minted code for 王芳 must be a DIFFERENT code, still keyed to 王芳.
    minted = [k for k, v in key.items() if v == "王芳"]
    assert minted, f"王芳 must still be pseudonymized: {key}"
    assert "P-83811" not in minted, f"王芳 must not re-issue the document's own code: {key}"


def test_restore_should_not_corrupt_a_preexisting_code():
    text = "老客户P-83811推荐了新客户王芳"
    out, key = redact(text, lang="zh", salt=42)
    back = restore(out, key, guard=False)
    assert "P-83811" in back  # the document's own code survives untouched
    assert back.count("王芳") == 1  # only the minted code (≠ P-83811) restored to 王芳
