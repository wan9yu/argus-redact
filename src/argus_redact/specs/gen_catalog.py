"""Generate docs/pii-types.md from the type registry.

Single source of truth for "which PII types does argus-redact cover, and
what are their compliance classifications". Downstream consumers (Gateway
docs, Whitepaper) link to the generated file rather than mirroring it.

Run via:
    python -m argus_redact.specs.gen_catalog > docs/pii-types.md
or:
    make catalog

The catalog is committed; CI's `tests/architecture/test_catalog_drift.py`
fails when the registry diverges from the committed file. After changing
typedefs or compliance rules, run `make catalog` and commit the result.
"""

from __future__ import annotations

# Importing the spec modules registers their typedefs as a side effect.
from argus_redact.pure.replacer import is_strategy_reversible
from argus_redact.specs import en as _en  # noqa: F401
from argus_redact.specs import shared as _shared  # noqa: F401
from argus_redact.specs import zh as _zh  # noqa: F401
from argus_redact.specs.registry import list_types

# Types explicitly out of scope for v0.5.x. Listed here so the catalog
# documents the gap and the Landing claim retraction is auditable.
_OUT_OF_SCOPE = (
    ("hk_id", "HKID 香港身份证", r"8 char `A123456(7)` format with check digit"),
    ("tw_id", "台湾身份证", r"`[A-Z]\d{9}` 1 letter + 9 digits"),
    ("macau_id", "澳门身份证", r"`\d/\d{6}/\d` format"),
    ("taiwan_arc", "台湾居留证 (ARC)", "1 letter + 9 chars"),
)

_LANG_LABELS = (
    ("zh", "Chinese (zh) — 28 types"),
    ("en", "English (en) — 15 types"),
    ("shared", "Shared (cross-lang) — 9 types"),
)


def _render_type(td) -> list[str]:
    out = [f"### `{td.name}`", ""]
    out.append("| Field | Value |")
    out.append("|---|---|")
    out.append(f"| Default strategy | `{td.strategy}` |")
    out.append(f"| Sensitivity | {td.sensitivity} |")
    out.append(f"| Reversible | {'✓' if is_strategy_reversible(td.strategy) else '✗'} |")
    if td.pipl_articles:
        out.append(f"| PIPL articles | {', '.join(td.pipl_articles)} |")
    if td.gdpr_special_category:
        out.append("| GDPR Art.9 special category | ✓ |")
    if td.hipaa_phi_category:
        out.append(f"| HIPAA Safe Harbor | `{td.hipaa_phi_category}` |")
    if td.checksum:
        out.append(f"| Checksum | {td.checksum} |")
    if td.examples:
        # Markdown table cells can't span lines; collapse multi-line examples.
        rendered = ", ".join(
            f"`{e.replace(chr(10), ' / ').replace(chr(13), '')}`"
            for e in td.examples[:3]
        )
        out.append(f"| Examples | {rendered} |")
    if td.source:
        out.append(f"| Source | {td.source} |")
    if td.description:
        out.append("")
        out.append(td.description)
    out.append("")
    return out


def render_catalog() -> str:
    types = list_types()
    by_lang: dict[str, list] = {"zh": [], "en": [], "shared": []}
    for td in types:
        by_lang.setdefault(td.lang, []).append(td)

    lines: list[str] = []
    lines.append("# PII Type Catalog")
    lines.append("")
    lines.append("Auto-generated from `argus_redact.specs.list_types()`. Do not hand-edit.")
    lines.append("Regenerate via: `make catalog`")
    lines.append("")
    lines.append(
        f"Total: {len(types)} types ({len(by_lang['zh'])} zh / "
        f"{len(by_lang['en'])} en / {len(by_lang['shared'])} shared)"
    )
    lines.append("")

    for lang_code, lang_label in _LANG_LABELS:
        bucket = sorted(by_lang.get(lang_code, []), key=lambda t: t.name)
        if not bucket:
            continue
        lines.append(f"## {lang_label}")
        lines.append("")
        for td in bucket:
            lines.extend(_render_type(td))

    lines.append("## Out of scope (v0.5.x)")
    lines.append("")
    lines.append("Roadmapped for v0.6.x. Do not configure `lang=\"zh\"` expecting these")
    lines.append("types to redact. Use explicit `names=[...]` patterns or wait for v0.6.x.")
    lines.append("")
    for name, label, fmt in _OUT_OF_SCOPE:
        lines.append(f"- **`{name}` — {label}**: {fmt}")
    lines.append("")

    return "\n".join(lines) + "\n"


def main() -> None:
    import sys

    sys.stdout.write(render_catalog())


if __name__ == "__main__":
    main()
