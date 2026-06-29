"""Generate crates/argus-redact-core/data/confusables.ron — the homoglyph
confusable fold map used by `normalize_text` (Cyrillic/Greek/Coptic look-alikes
-> ASCII Latin, applied 1:1 before NFKC).

Source data
-----------
Unicode Security Mechanisms (UTS #39) confusables data, pinned version:

    https://www.unicode.org/Public/security/16.0.0/confusables.txt   (Unicode 16.0.0)

Fetched at generation time (not vendored). Terms of use:
https://www.unicode.org/terms_of_use.html — © Unicode®, Inc.

Each data line is `SOURCE ; TARGET ; TYPE # comment`.

Filter (kept entry must satisfy ALL of)
---------------------------------------
* SOURCE is a single codepoint; TARGET is a single codepoint.
* TARGET is an ASCII letter (U+0041-005A or U+0061-007A).
* SOURCE codepoint >= 0x80 (non-ASCII) and `chr(SOURCE).isalpha()`.
* SOURCE's Unicode name first token is in {LATIN, CYRILLIC, GREEK, COPTIC}.

Rationale: we deliberately EXCLUDE Mathematical / Fullwidth confusables (those
are already handled by the NFKC step in `normalize_text`, so folding them here
would be redundant), and Arabic / Hebrew / CJK / obscure-syllabic scripts
(folding those to Latin would mangle legitimate non-Latin text). We keep only
the Latin-spoofing alphabetic scripts where a look-alike fold to ASCII is safe.

Overlay
-------
`CURATED` below is the hand-verified table (the original 47 mappings that lived
in normalize.rs, plus one audit-driven correction). Curated mappings take
precedence over the Unicode table on any conflict, and curated-only entries are
added. Final map = generated ∪ curated, curated overriding.

Run: `make gen-confusables`        (writes the .ron)
CI:  `make gen-confusables-check`  (exit 1 on drift)

The parity gate (tests/architecture/test_confusables_parity.py) freezes the
resulting entry count + sha256 and fails if the embedded RON drifts.
"""

from __future__ import annotations

import sys
import unicodedata
import urllib.request
from pathlib import Path

CONFUSABLES_VERSION = "16.0.0"
CONFUSABLES_URL = f"https://www.unicode.org/Public/security/{CONFUSABLES_VERSION}/confusables.txt"

# First-token allowlist for the SOURCE codepoint's Unicode name.
ALLOW = {"LATIN", "CYRILLIC", "GREEK", "COPTIC"}

# Hand-verified mappings that take precedence over the Unicode table. The first
# 47 are transcribed verbatim from the original normalize.rs curated `match`
# (Cyrillic + Greek -> Latin). The trailing entry is an audit-driven correction:
# U+04CF CYRILLIC SMALL LETTER PALOCHKA (ӏ) — Unicode 16.0.0 folds it to "i",
# but as a bare vertical-bar glyph it spoofs lowercase "l" at least as often;
# we fold it to "l" to close that homoglyph path.
CURATED: dict[int, str] = {
    # Cyrillic -> Latin
    0x0430: "a",
    0x0435: "e",
    0x043E: "o",
    0x0440: "p",
    0x0441: "c",
    0x0443: "y",
    0x0445: "x",
    0x0456: "i",
    0x04BB: "h",
    0x0432: "b",
    0x043A: "k",
    0x043C: "m",
    0x0442: "t",
    0x043D: "h",
    0x0410: "A",
    0x0412: "B",
    0x0415: "E",
    0x041A: "K",
    0x041C: "M",
    0x041D: "H",
    0x041E: "O",
    0x0420: "P",
    0x0421: "C",
    0x0422: "T",
    0x0425: "X",
    0x0423: "Y",
    # Greek -> Latin
    0x03BF: "o",
    0x03B1: "a",
    0x03B5: "e",
    0x03B9: "i",
    0x03BA: "k",
    0x03BD: "v",
    0x03C1: "p",
    0x03C4: "t",
    0x039F: "O",
    0x0391: "A",
    0x0392: "B",
    0x0395: "E",
    0x0397: "H",
    0x0399: "I",
    0x039A: "K",
    0x039C: "M",
    0x039D: "N",
    0x03A1: "P",
    0x03A4: "T",
    0x03A7: "X",
    0x0396: "Z",
    # audit-driven correction (see module docstring)
    0x04CF: "l",
}

# Audit examples that MUST be covered by the final map (sanity self-check).
AUDIT_EXAMPLES: dict[int, str] = {
    0x0405: "S",
    0x0408: "J",
    0x0455: "s",
    0x0458: "j",
    0x0501: "d",
    0x04CF: "l",
    0x03F3: "j",
}

_OUT = (
    Path(__file__).resolve().parents[3]
    / "crates"
    / "argus-redact-core"
    / "data"
    / "confusables.ron"
)


def _is_ascii_letter(cp: int) -> bool:
    return (0x41 <= cp <= 0x5A) or (0x61 <= cp <= 0x7A)


def fetch_confusables() -> str:
    """Fetch the pinned confusables.txt. Raises on network failure."""
    req = urllib.request.Request(CONFUSABLES_URL, headers={"User-Agent": "argus-redact-gen/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 (pinned https URL)
        return resp.read().decode("utf-8-sig")


def parse_generated(text: str) -> dict[int, str]:
    """Apply the filter to the raw confusables.txt body."""
    out: dict[int, str] = {}
    for line in text.splitlines():
        body = line.split("#", 1)[0]
        if not body.strip():
            continue
        parts = [p.strip() for p in body.split(";")]
        if len(parts) < 2:
            continue
        src_cps = parts[0].split()
        tgt_cps = parts[1].split()
        if len(src_cps) != 1 or len(tgt_cps) != 1:
            continue
        try:
            src = int(src_cps[0], 16)
            tgt = int(tgt_cps[0], 16)
        except ValueError:
            continue
        if not _is_ascii_letter(tgt):
            continue
        if src < 0x80:
            continue
        sc = chr(src)
        if not sc.isalpha():
            continue
        try:
            name = unicodedata.name(sc)
        except ValueError:
            continue  # unnamed codepoint
        if name.split()[0] not in ALLOW:
            continue
        out[src] = chr(tgt)
    return out


def build_map(text: str) -> dict[int, str]:
    """Generated ∪ curated, curated overriding. Asserts the invariants."""
    final = parse_generated(text)
    final.update(CURATED)

    # Invariant 1: every curated source maps to its curated target.
    for src, tgt in CURATED.items():
        assert final.get(src) == tgt, f"curated U+{src:04X} -> {final.get(src)!r}, expected {tgt!r}"
    # Invariant 2: every audit example is covered with its expected target.
    for src, tgt in AUDIT_EXAMPLES.items():
        assert final.get(src) == tgt, f"audit U+{src:04X} -> {final.get(src)!r}, expected {tgt!r}"
    return final


def _ron_char(cp_or_str) -> str:
    """RON char literal. Sources are alphabetic non-ASCII (\\u escape); targets
    are bare ASCII letters. Neither can be a quote or backslash, so no escaping
    of those is needed."""
    if isinstance(cp_or_str, int):
        return f"'\\u{{{cp_or_str:04X}}}'"
    # single ASCII letter target
    return f"'{cp_or_str}'"


def build_ron(text: str) -> tuple[str, dict[int, str]]:
    final = build_map(text)
    lines: list[str] = []
    lines.append("// GENERATED by argus_redact.specs.gen_confusables — do not edit by hand.")
    lines.append(
        f"// Source: Unicode {CONFUSABLES_VERSION} confusables (UTS #39) + curated overlay."
    )
    lines.append("// Regenerate: make gen-confusables")
    lines.append("(")
    lines.append("    mappings: [")
    for src in sorted(final):
        lines.append(f"        ({_ron_char(src)}, {_ron_char(final[src])}),")
    lines.append("    ],")
    lines.append(")")
    return "\n".join(lines) + "\n", final


def main() -> int:
    text = fetch_confusables()
    ron, final = build_ron(text)
    if "--check" in sys.argv:
        current = _OUT.read_text(encoding="utf-8") if _OUT.exists() else ""
        if current != ron:
            print(
                "confusables.ron is out of sync. Run: make gen-confusables",
                file=sys.stderr,
            )
            return 1
        print("confusables.ron is in sync")
        return 0
    _OUT.parent.mkdir(parents=True, exist_ok=True)
    _OUT.write_text(ron, encoding="utf-8")
    rel = _OUT.relative_to(Path(__file__).resolve().parents[3])
    print(f"Wrote {rel}")
    print(f"  total entries:   {len(final)}")
    print(f"  curated:         {len(CURATED)} (all present, curated-overriding)")
    print(f"  audit examples:  {len(AUDIT_EXAMPLES)} (all present)")
    print("  invariants:      PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
