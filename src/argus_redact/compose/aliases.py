"""compose.expand_aliases — surname+title composite alias expansion.

For each Person entry (P-NNNNN) in a redaction key, generates composite
aliases like "黄先生" / "黄总" / "Mr. Brown" / "Dr. Brown" and maps them
to the original name so literal substring restore() catches them.

Conservative: only composite forms (surname + title), never bare surname.
Skips entries whose pseudonym is not Person-coded (P- prefix).

Known limitations (out of scope per docs/architecture-layers.md §Layer 2):
- Pronouns ("他/她", "they") — use coref-aware downstream layer
- Kinship terms ("阿姨", "uncle")
- Honorifics outside the title list (5 zh + 5 en core titles)
"""

from __future__ import annotations

_ZH_TITLES = ("先生", "女士", "总", "老师", "医生")
_EN_TITLES = ("Mr.", "Mrs.", "Ms.", "Dr.", "Prof.")

# Compound Chinese surnames (2-char). When original starts with one of these,
# use 2 chars as surname; otherwise use 1 char. Coverage: top compound surnames
# from《百家姓》— not exhaustive, conservative.
_ZH_COMPOUND_SURNAMES = frozenset(
    {
        "欧阳",
        "司马",
        "诸葛",
        "上官",
        "夏侯",
        "公孙",
        "皇甫",
        "尉迟",
        "东方",
        "西门",
    }
)


def _extract_surname_zh(name: str) -> str | None:
    """Extract Chinese surname. Returns None if input can't be parsed safely."""
    if not name or len(name) < 2:
        return None
    if len(name) >= 2 and name[:2] in _ZH_COMPOUND_SURNAMES:
        return name[:2]
    return name[:1]


def _extract_surname_en(name: str) -> str | None:
    """Extract English surname (last whitespace-delimited token > 1 char)."""
    if not name or not name.strip():
        return None
    tokens = name.strip().split()
    if not tokens:
        return None
    # Skip single-letter trailing initials (e.g., "F." in "John F.")
    last = tokens[-1].rstrip(".,")
    if len(last) <= 1:
        if len(tokens) >= 2:
            last = tokens[-2].rstrip(".,")
        if len(last) <= 1:
            return None
    return last


def expand_aliases(key: dict, lang: str = "zh") -> dict:
    """Expand the key dict with surname+title composite aliases.

    Args:
        key: redaction key dict (pseudonym → original) from redact().
        lang: "zh" or "en". Unknown values fall back to "en".

    Returns:
        A new dict containing all original (pseudonym → original) entries
        PLUS additional (alias → original) entries. The original dict is
        not mutated.

        Directionality note: alias → original (NOT alias → pseudonym).
        When restore() iterates key.items() and substring-replaces, the
        text fragment "黄先生" maps directly to "黄芳" in a single pass.
        This is independent of restore's internal iteration order over key
        entries — a safer contract than chaining alias→pseudonym→original.

    Edge cases:
        - Empty key → empty dict
        - Non-Person pseudonyms (e.g., MED-NNNNN, O-NNNNN) — skipped
        - Originals from which no surname can be extracted — skipped
        - Compound zh surnames (欧阳/司马/...) — handled
        - Multi-token en names with trailing initial — handled
        - Alias collisions (alias already in key) — not overwritten
    """
    if not key:
        return {}
    expanded = dict(key)
    titles = _ZH_TITLES if lang == "zh" else _EN_TITLES
    extract = _extract_surname_zh if lang == "zh" else _extract_surname_en

    # First pass: which surnames are shared by ≥2 DISTINCT Person originals? A bare
    # {surname}{title} alias for a shared surname is ambiguous — it cannot restore to
    # one identity — so it must not be emitted at all. Emitting it would silently bind
    # the alias to the first-iterated Person = a confident wrong-identity restore.
    surname_originals: dict[str, set[str]] = {}
    for pseudonym, original in key.items():
        if not pseudonym.startswith("P-"):
            continue
        surname = extract(original)
        if surname:
            surname_originals.setdefault(surname, set()).add(original)

    for pseudonym, original in key.items():
        if not pseudonym.startswith("P-"):
            continue
        surname = extract(original)
        if not surname:
            continue
        if len(surname_originals.get(surname, ())) > 1:
            continue  # ambiguous: ≥2 Persons share this surname — skip its aliases
        for title in titles:
            alias = f"{surname}{title}" if lang == "zh" else f"{title} {surname}"
            if alias not in expanded:
                # alias → original (single-pass restore semantics)
                expanded[alias] = original
    return expanded
