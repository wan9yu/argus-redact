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

from argus_redact.pure.lang_detect import detect_languages

_ZH_TITLES = ("先生", "女士", "总", "老师", "医生")
_EN_TITLES = ("Mr.", "Mrs.", "Ms.", "Dr.", "Prof.")

# Trailing generational suffixes stripped before surname extraction. Jr/Sr are
# matched case-insensitively; the Roman numerals are matched uppercase only
# (per the documented convention — "ii"/"iii" are not recognized).
_EN_GENERATIONAL_JR_SR = frozenset({"JR", "SR"})
_EN_GENERATIONAL_ROMAN = frozenset({"II", "III", "IV"})

# Compound Chinese surnames (2-char). When original starts with one of these,
# use 2 chars as surname; otherwise use 1 char. Coverage: top compound surnames
# from《百家姓》— not exhaustive, conservative.
#
# Intentional divergence (do NOT auto-sync): the Rust ``person_zh`` DETECTOR owns
# its own compound-surname RON pool (reachable as ``_core.person_compound_surnames_zh()``)
# used for name-CANDIDATE generation. This alias-EXPANSION pool serves a different
# purpose (deciding how many leading chars of an already-known name are the
# surname) and the two have drifted in content — this pool carries 夏侯 the core
# pool lacks, and omits several the core pool carries. They are NOT equal, so this
# is not a drop-in duplicate: unifying to one SSOT would change ``expand_aliases``
# output and must be a deliberate, separately-reviewed change, not a refactor.
# Until then, hand-sync consciously if this list changes.
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
    """Extract English surname (last whitespace-delimited token > 1 char).

    Trailing generational suffixes (Jr, Sr, II, III, IV — with or without a
    trailing period) are stripped first, so "Robert Smith Jr." extracts
    "Smith", not "Jr". This matters for the shared-surname ambiguity guard in
    expand_aliases: an under-extracted surname (e.g. "Jr") can't collide with
    anyone else's, so the guard silently misses a real collision.
    """
    if not name or not name.strip():
        return None
    tokens = name.strip().split()
    if not tokens:
        return None
    while tokens:
        candidate = tokens[-1].rstrip(".,")
        if candidate.upper() in _EN_GENERATIONAL_JR_SR or candidate in _EN_GENERATIONAL_ROMAN:
            tokens.pop()
            continue
        break
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


def _detect_name_lang(name: str) -> str:
    """Auto-detect zh vs en script for a SINGLE Person original name, so the
    documented en use case (``expand_aliases({"P-1": "John Smith"})``)
    doesn't silently fall back to zh-style aliases (e.g. "J先生"), and a
    MIXED-language key (one zh name + one Latin name) routes each name
    through its own script instead of one whole-key decision."""
    detected = detect_languages(name)
    return "zh" if "zh" in detected else "en"


def _titles_and_extract(lang_code: str) -> tuple[tuple[str, ...], object]:
    """Resolve the (titles, surname-extractor) pair for a lang code. Unknown
    codes fall back to en, matching the documented explicit-lang contract."""
    if lang_code == "zh":
        return _ZH_TITLES, _extract_surname_zh
    return _EN_TITLES, _extract_surname_en


def expand_aliases(key: dict, lang: str | None = None) -> dict:
    """Expand the key dict with surname+title composite aliases.

    Args:
        key: redaction key dict (pseudonym → original) from redact().
        lang: "zh" or "en". Unknown explicit values fall back to "en", applied
            uniformly to every Person in ``key``. If None (the default), each
            Person's own original name is auto-detected independently —
            Latin-script names resolve to "en", otherwise "zh" — so a MIXED
            key (some zh names, some Latin names) expands each Person through
            its own script instead of one whole-key decision.

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

    # Single walk over every Person pseudonym. Resolve its (titles, extract): under
    # explicit `lang`, one shared decision for the whole key (unchanged behavior — do
    # not detect per-name here); under auto (lang=None), each Person's OWN original
    # name picks its own script, so a MIXED-language key (e.g. one zh name + one Latin
    # name) doesn't force every name through the same extractor/titles. Extraction is
    # pure (same original → same surname), so the surname is extracted ONCE here and
    # stored in `person_config` for the emit pass to reuse — one extract() per Person.
    #
    # surname_originals records which surnames are shared by ≥2 DISTINCT Person
    # originals: a bare {surname}{title} alias for a shared surname is ambiguous — it
    # cannot restore to one identity — so the emit pass must not emit it at all.
    # Emitting it would silently bind the alias to the first-iterated Person = a
    # confident wrong-identity restore. Surnames are extracted with each Person's OWN
    # extractor, so a zh surname and an en surname never spuriously collide.
    person_config: dict[str, tuple[str, tuple[str, ...], str]] = {}
    surname_originals: dict[str, set[str]] = {}
    for pseudonym, original in key.items():
        if not pseudonym.startswith("P-"):
            continue
        lang_code = lang if lang is not None else _detect_name_lang(original)
        titles, extract = _titles_and_extract(lang_code)
        surname = extract(original)
        person_config[pseudonym] = (lang_code, titles, surname)
        if surname:
            surname_originals.setdefault(surname, set()).add(original)

    for pseudonym, original in key.items():
        config = person_config.get(pseudonym)
        if config is None:
            continue
        lang_code, titles, surname = config
        if not surname:
            continue
        if len(surname_originals.get(surname, ())) > 1:
            continue  # ambiguous: ≥2 Persons share this surname — skip its aliases
        for title in titles:
            alias = f"{surname}{title}" if lang_code == "zh" else f"{title} {surname}"
            if alias not in expanded:
                # alias → original (single-pass restore semantics)
                expanded[alias] = original
    return expanded
