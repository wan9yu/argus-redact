"""Public-doc lock for the stream-only JWT head past the raised ceiling.

The force-flush cap is on the buffer. These checks fail while the docs still
describe an unconditional 4096 flush, or while known-issues has no Design
Constraints entry for the unredacted head and the charset-glued residual.
"""

from __future__ import annotations

import re

from tests.docs.test_doc_claims import _read

_CONFIRMED_PHRASE = "confirmed on " + "current main"
_OVERCLAIM = ("merely split", "held whole")
_WHAT_CLAIMS = (
    "cap is on the buffer, not the token",
    "past the raised ceiling",
    "unredacted head",
    "in-flight or oversized JWT",
    "carried suffix no longer matches",
    "batch still redacts the same text",
    "charset-glued",
    "text.eyJ",
    "not held",
)


def _design_constraint_entries(text: str) -> list[str]:
    marker = "## Design Constraints\n"
    start = text.find(marker)
    if start == -1:
        return []
    body = text[start + len(marker) :]
    end = body.find("\n## ")
    if end != -1:
        body = body[:end]
    return [chunk for chunk in re.split(r"(?m)^### ", body)[1:] if chunk.strip()]


def _bullet(entry: str, label: str, following: str | None) -> str:
    marker = f"**{label}**:"
    start = entry.find(marker)
    if start == -1:
        return ""
    rest = entry[start + len(marker) :]
    if following is None:
        return rest
    nxt = rest.find(f"**{following}**:")
    if nxt == -1:
        return ""
    return rest[:nxt]


def test_public_docs_should_state_stream_jwt_head_past_raised_ceiling() -> None:
    known = _read("docs/known-issues.md")
    entries = _design_constraint_entries(known)
    ledger = [entry for entry in entries if entry.startswith("`AuditLedger`")]

    assert ledger, "Design Constraints parser missed the existing AuditLedger entry"
    assert "**What**:" in ledger[0]
    assert "**Why we won't fix**:" in ledger[0]
    assert "**What you should do**:" in ledger[0]

    matches = [entry for entry in entries if "text.eyJ" in entry and "JWT" in entry]

    assert matches, (
        "docs/known-issues.md Design Constraints has no entry for the unredacted "
        "JWT head past the raised ceiling and the charset-glued text.eyJ residual"
    )
    entry = matches[0]
    what = _bullet(entry, "What", "Why we won't fix")
    why = _bullet(entry, "Why we won't fix", "What you should do")
    action = _bullet(entry, "What you should do", None)
    what_lower = what.lower()

    assert what.strip(), "JWT ceiling entry is missing **What**"
    assert why.strip(), "JWT ceiling entry is missing **Why we won't fix**"
    assert action.strip(), "JWT ceiling entry is missing **What you should do**"
    for claim in _WHAT_CLAIMS:
        assert claim.lower() in what_lower, f"What does not say {claim!r}"

    api = _read("docs/api-reference.md")
    design = _read("docs/design-streaming-incremental.md")
    step = design.split("4. If no boundary", 1)[-1].split("5. Otherwise", 1)[0]
    valve = design.split("The forced flush", 1)[-1].split("## Public API", 1)[0]

    assert "up to 4096 chars before a forced flush" not in api
    assert (
        "the same way `StreamingRedactor` does: a reply that never emits a sentence "
        "terminator is force-flushed once the buffer exceeds `max_buffer`"
    ) not in api
    assert "in-flight opener" in api
    assert "ceiling" in api
    assert "max_buffer (=4096)`: forced flush" not in design
    assert "The forced flush at `max_buffer=4096`" not in design
    assert "in-flight opener" in step
    assert "ceiling" in step
    assert "in-flight opener" in valve
    assert "ceiling" in valve

    for rel, text in (
        ("docs/known-issues.md", known),
        ("docs/api-reference.md", api),
        ("docs/design-streaming-incremental.md", design),
    ):
        lowered = text.lower()
        for phrase in _OVERCLAIM:
            assert phrase not in lowered, f"{rel} says {phrase!r}"
        assert _CONFIRMED_PHRASE not in text, f"{rel} contains the banned phrase"
