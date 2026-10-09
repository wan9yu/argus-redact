"""Public-doc lock for the stream-only JWT head past the raised ceiling.

The force-flush cap is on the buffer. These checks fail while the docs still
describe an unconditional 4096 flush, or while known-issues has no Design
Constraints entry for the unredacted head and the charset-glued residual.
"""

from __future__ import annotations

import re

from tests.docs.test_doc_claims import _read

_CONFIRMED_PHRASE = "confirmed on " + "current main"
_OVERCLAIM = ("merely split", "held whole", "never leaks")
_WHAT_CLAIMS = (
    "cap is on the buffer, not the token",
    "past the raised ceiling",
    "unredacted head",
    "in-flight or oversized JWT",
    "carried suffix no longer matches",
    "batch still redacts the same text",
    "charset-glued",
    "text.eyJ",
    "from that `eyJ`",
    "reaches end of buffer",
    "preceding letters are not held",
)
_OLD_GLUED_CLAIMS = (
    "is not an opener and is not held",
    "would hold ordinary prose",
    "not a start",
    "glued as `text.eyJ`",
)
_FIXED_IN_V0820 = (
    "fixed in v0.8.20",
    "v0.8.20 修复",
)
_V0820_CORRECTION = "**Correction:** v0.8.20 did not hold a charset-glued"


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


_WIDE_8192 = "A closed glued token longer than the carry window adds 8192."
_CARRY_CORRECTION = (
    "8192 is added when the JWT itself is longer than the carry window "
    "even if the charset run is longer."
)


def _flat(text: str) -> str:
    return " ".join(text.split())


def _v0820_section(changelog: str) -> str:
    start = changelog.find("## v0.8.20")
    end = changelog.find("## v0.8.19")
    assert start != -1 and end != -1 and start < end
    return changelog[start:end]


def _v0821_section(changelog: str) -> str:
    start = changelog.find("## v0.8.21")
    end = changelog.find("## v0.8.20")
    assert start != -1 and end != -1 and start < end
    return changelog[start:end]


def _v0821_intro_and_bullet(section: str) -> tuple[str, str]:
    fixed = section.find("### Fixed")
    intro = section[:fixed] if fixed != -1 else section
    bullet_at = section.find("- **An unclosed charset-glued JWT opener")
    assert bullet_at != -1, "v0.8.21 bullet missing"
    bullet = section[bullet_at:].split("\n", 1)[0]
    return intro, bullet


def test_docs_should_retract_the_v0_8_20_charset_glued_claim() -> None:
    """The published v0.8.20 glued claim must be marked, not left as current behavior."""
    known = _read("docs/known-issues.md")
    matches = [
        entry
        for entry in _design_constraint_entries(known)
        if "text.eyJ" in entry and "JWT" in entry
    ]
    assert matches, "JWT ceiling entry missing"
    entry = matches[0]
    why = _bullet(entry, "Why we won't fix", "What you should do")
    action = _bullet(entry, "What you should do", None)

    for claim in _OLD_GLUED_CLAIMS:
        assert claim not in entry, f"known-issues still says {claim!r}"
        assert claim not in why
        assert claim not in action

    readme = _read("README.md")
    readme_zh = _read("README.zh.md")
    changelog = _v0820_section(_read("CHANGELOG.md"))
    for phrase in _FIXED_IN_V0820:
        assert phrase not in readme, f"README.md still says {phrase!r}"
        assert phrase not in readme_zh, f"README.zh.md still says {phrase!r}"

    assert _V0820_CORRECTION in changelog, "v0.8.20 section has no marked correction"
    for rel, text in (("JWT entry", entry), ("v0.8.20", changelog)):
        lowered = text.lower()
        for phrase in _OVERCLAIM:
            assert phrase not in lowered, f"{rel} says {phrase!r}"


def test_docs_should_replace_the_wide_closed_glued_ceiling_sentence() -> None:
    """The wide 8192 sentence must not remain as the ceiling rule."""
    known = _flat(_read("docs/known-issues.md"))
    section = _v0821_section(_read("CHANGELOG.md"))
    intro, bullet = _v0821_intro_and_bullet(section)
    intro_flat = _flat(intro)
    bullet_flat = _flat(bullet)

    assert _WIDE_8192 not in known, "known-issues still has the wide 8192 sentence"
    assert _WIDE_8192 not in intro_flat, "v0.8.21 intro still has the wide 8192 sentence"
    assert _WIDE_8192 not in bullet_flat, "v0.8.21 bullet still has the wide 8192 sentence"

    assert _CARRY_CORRECTION in known, "known-issues lacks the corrected ceiling sentence"
    assert _CARRY_CORRECTION in intro_flat, "v0.8.21 intro lacks the corrected ceiling sentence"
    assert _CARRY_CORRECTION in bullet_flat, "v0.8.21 bullet lacks the corrected ceiling sentence"
    assert "**Correction:**" in _read("docs/known-issues.md")
    assert "**Correction:**" in section, "v0.8.21 section has no marked correction"
