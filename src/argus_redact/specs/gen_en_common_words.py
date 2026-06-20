"""Generate crates/argus-redact-core/data/en_common_words.ron — the
pool-INDEPENDENT common-word lexicon used by the English person detector's
"name-like leading token" corroboration signal.

What it is
----------
A bare-surname candidate (a capitalized leading token that is NOT in the SSA
given-name pool, followed by a pooled surname) is evidence-gated. One signal is
"the leading token is name-like": alphabetic, length >= 2, and its lowercased
form is NOT in this lexicon. ``Marco``/``Wei``/``Mohammed`` are not common words
-> name-like -> corroborate; ``Central``/``Lake``/``Apple`` ARE common / place
words -> not name-like -> stay suppressed. This removes the SSA pool's Anglo bias
from the gate (it recovers non-Anglo ``Given Surname`` names) WITHOUT reviving
the place / noise false positives.

Source of truth
---------------
**The committed RON (``data/en_common_words.ron``) is hand-maintained and is the
source of truth.** It was authored by hand (curated common words + place / geo /
directional terms — the FP drivers) so it is reproducible offline. This generator
is PROVENANCE + a future-refresh path: when network is available it fetches a
pinned public word-frequency list, lowercases it, and UNIONS it with the curated
place/geo supplement below. Run it to refresh, then review the diff by hand
before committing — do not let an unreviewed fetch silently widen the gate.

Pinned source
-------------
A pinned commit of the public-domain ``first20hours/google-10000-english`` word
list (the 10k most frequent English words from the Google Trillion Word Corpus,
MIT-licensed). The commit is pinned so a refresh is reproducible:

    https://raw.githubusercontent.com/first20hours/google-10000-english/
        {COMMIT}/google-10000-english-no-swears.txt

``TOP_N`` caps how many of the most-frequent words are taken (the file is already
frequency-ordered). Keeping it a few hundred avoids pulling rare words that are
also legitimate names (the union with the curated supplement is what guarantees
the place/geo FP drivers are present regardless of the fetched list).

Alternatively, ``wordfreq.top_n_list('en', TOP_N)`` can be substituted as the
frequency source (also public); the curated supplement and write logic are
unchanged.

Run:   python -m argus_redact.specs.gen_en_common_words
Check: python -m argus_redact.specs.gen_en_common_words --check   (exit 1 on drift)
"""

from __future__ import annotations

import sys
import urllib.request
from pathlib import Path

# Pinned commit of first20hours/google-10000-english (frequency-ordered, MIT).
GOOGLE_10K_COMMIT = "d0736d492489198e4f9d650c7ab4143bc14c1e9e"
GOOGLE_10K_URL = (
    "https://raw.githubusercontent.com/first20hours/google-10000-english/"
    f"{GOOGLE_10K_COMMIT}/google-10000-english-no-swears.txt"
)
# How many of the most-frequent words to take (file is frequency-ordered).
TOP_N = 500

# ── Curated supplement: place / geo / directional / temporal terms that collide
# with surnames (the FP drivers), plus a few function words the frequency cut may
# miss. These MUST be present regardless of the fetched list — they are why the
# name-like signal stays OFF for place pairs ("Central Park", "Lake Park"). All
# lowercase. Overlap with the fetched top-N is fine (union dedupes).
# The final line ("media selection dancing community instagram nuevo") closes
# lexicon gaps surfaced by the kaggle_piilo FP diagnosis: common English words
# plus the brand "instagram" and the Spanish place-prefix "nuevo" ("Nuevo León")
# — none is a pooled surname or an en given name, so suppressing the leading
# token kills FPs like "Media Page" / "Selection Jordan" without losing a name.
CURATED_SUPPLEMENT: frozenset[str] = frozenset(
    """
    north south east west northeast northwest southeast southwest central upper
    lower middle inner outer left right top bottom front rear
    new old great little big small grand royal national international
    mount mountain mountains saint santa san fort port lake lakes river rivers
    hill hills bay valley springs forest woods wood field fields stone
    brook glen dale beach grove park green oak pine maple birch cedar elm ridge
    creek falls heights gardens garden square street avenue road lane drive court
    place boulevard highway alley terrace circle crossing junction crossroads
    city town village county state country province district region zone area
    neighborhood suburb downtown uptown ward borough parish prefecture
    island islands peninsula cape coast shore harbor harbour pier dock canal dam
    reservoir pond marsh swamp desert prairie plain plateau cliff cave canyon
    gorge gulf strait sound channel reef
    station airport terminal depot market mall plaza center centre tower hall
    palace castle cathedral church temple mosque chapel abbey monastery shrine
    museum gallery library theater theatre stadium arena zoo aquarium
    union liberty freedom independence memorial victory
    today tomorrow yesterday tonight week weeks month months year years day days
    hour hours minute minutes morning afternoon evening night noon midnight
    first second third fourth fifth next last final previous many most some few
    several none all both each every much more less least number amount total
    hyde
    media selection dancing community instagram nuevo
    """.split()
)

# ── Predominantly-name exclusions: words that ARE frequent enough to land in the
# fetched top-N but are PREDOMINANTLY person given names, so they must NOT enter
# the suppression lexicon (that would kill the name-like signal and LEAK the
# "Given Surname" pair). This is the curation principle made durable: without it
# a refresh would silently re-add e.g. "summer"/"winter" from the frequency list
# and revert the hand curation. The rare place FP these omissions allow (e.g.
# "Spring Lake", needing a pooled 2nd token) is the accepted residual. Words that
# are BOTH a name and an ultra-high-frequency common word ("will", "major",
# "drew", "art", "guy", "rich", "royal", "river", "lane", "case", "true",
# "count") are deliberately NOT here — they stay suppressed, with the fast-L1
# recall miss recovered by L2 NER. See the RON header for the full design tension.
NAME_EXCLUSIONS: frozenset[str] = frozenset(
    """
    summer autumn winter spring
    april may june august
    """.split()
)

_OUT = (
    Path(__file__).resolve().parents[3]
    / "crates"
    / "argus-redact-core"
    / "data"
    / "en_common_words.ron"
)


def fetch_top_words() -> list[str]:
    """Fetch the pinned frequency list and return the lowercased top-N words."""
    req = urllib.request.Request(
        GOOGLE_10K_URL, headers={"User-Agent": "argus-redact-gen/1.0"}
    )
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 (pinned https URL)
        body = resp.read().decode("utf-8")
    words = [w.strip().lower() for w in body.splitlines() if w.strip()]
    return words[:TOP_N]


def build_word_set(top_words: list[str]) -> list[str]:
    """Union the fetched top-N with the curated supplement; sorted, deduped.

    Only alphabetic (with internal hyphen) lowercase tokens are kept — the
    name-like guard only ever tests such tokens, so non-alphabetic frequency-list
    entries (rare, but possible) would be dead weight.
    """

    def ok(w: str) -> bool:
        return len(w) >= 1 and all(c.isalpha() or c == "-" for c in w)

    union = {w for w in top_words if ok(w)} | {w for w in CURATED_SUPPLEMENT if ok(w)}
    # Subtract the predominantly-name words even if the frequency fetch supplied
    # them — keeps the hand curation durable across a refresh.
    union -= NAME_EXCLUSIONS
    return sorted(union)


def _ron_str(s: str) -> str:
    """RON/serde string literal — backslash + quote escaped (words have neither)."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_ron(words: list[str]) -> str:
    lines: list[str] = []
    lines.append(
        "// en common-words lexicon (SSOT) — pool-INDEPENDENT corroboration for the"
    )
    lines.append("// person detector's name-like leading-token signal.")
    lines.append("//")
    lines.append(
        "// A bare-surname candidate's leading token (the given-name slot) is treated as"
    )
    lines.append(
        '// "name-like" when its lowercase form (trailing dot stripped) is NOT in this'
    )
    lines.append(
        "// set, it is alphabetic, and its length is >= 2. Name-like adds W_NAME_LIKE"
    )
    lines.append(
        "// evidence, so a real Given+Surname pair whose given name is outside the SSA"
    )
    lines.append(
        '// pool ("Marco Rossi", "Wei Chen") still corroborates, while a place / common-'
    )
    lines.append('// word pair ("Central Park", "Lake Park") does not. This removes the SSA')
    lines.append("// pool's Anglo bias from the gate WITHOUT reviving the place/noise FPs.")
    lines.append("//")
    lines.append(
        "// Hand-maintained curated set: the most frequent English words plus place /"
    )
    lines.append("// geographic / directional terms that collide with surnames (the FP drivers).")
    lines.append("// Regenerate / refresh from a pinned word-frequency source via:")
    lines.append("//   python -m argus_redact.specs.gen_en_common_words")
    lines.append("// (the committed file is the source of truth; the generator is provenance +")
    lines.append("// future refresh, and unions the fetched top-N with the curated supplement.)")
    lines.append("//")
    lines.append("// ── Design tension: this list does DOUBLE DUTY ──")
    lines.append("//")
    lines.append('// It is BOTH (1) the place / common-word FP-suppression set (a leading "Central"')
    lines.append('// in "Central Park" must not look name-like) AND (2) the name-like NEGATIVE')
    lines.append("// filter (any leading token in this set is declared NOT-a-name). A token that is")
    lines.append("// genuinely BOTH a real given name AND a common/place word is therefore")
    lines.append("// irreducibly ambiguous in this single-list design — including it suppresses a")
    lines.append("// real name, omitting it revives a place / prose FP. There is no curation that")
    lines.append("// makes both correct at once.")
    lines.append("//")
    lines.append("// Curation principle (applied consistently):")
    lines.append("//   - PREDOMINANTLY a person name -> OMIT (treat as name-like). Season names")
    lines.append('//     ("summer", "autumn", "winter", "spring") and predominantly-name month')
    lines.append('//     names ("april", "may", "june", "august") are omitted; the rare')
    lines.append('//     "Spring Lake"-style place FP (needs a pooled 2nd token) is the accepted')
    lines.append("//     residual.")
    lines.append("//   - PREDOMINANTLY a common / function / place word -> INCLUDE (suppress).")
    lines.append('//     Ultra-high-frequency words that are ALSO occasionally a name ("will",')
    lines.append('//     "major", "drew", "art", "guy", "rich", "royal", "river", "lane", "case",')
    lines.append('//     "true", "count") stay in: removing them would fire name-like on ordinary')
    lines.append('//     prose. The fast-L1 recall miss ("Will Smith" suppressed) is an ACCEPTED')
    lines.append("//     trade — L2 NER (ner / auto mode) recovers it.")
    lines.append("//   - Curated place / geo / temporal terms (forest, brook, glen, dale, ridge,")
    lines.append("//     liberty, victory, march, july, ...) stay in as FP drivers even when they")
    lines.append("//     are an occasional name; the rare-name reading is the residual.")
    lines.append("//")
    lines.append("// FUTURE WORK: split this into TWO lists — a place / function FP-SUPPRESSION set")
    lines.append('//   (used only to keep "Central Park" non-name-like) and a strictly')
    lines.append("//   NOT-A-NAME set (used only as the name-like negative filter). A token could")
    lines.append("//   then suppress a place FP WITHOUT also vetoing a real given name, dissolving")
    lines.append("//   the ambiguity above. Until then the principle is: predominantly-name -> omit;")
    lines.append("//   predominantly-common-word -> include and accept the L2-recovered recall miss.")
    lines.append("EnCommonWords(")
    lines.append("    words: [")
    for w in words:
        lines.append(f"        {_ron_str(w)},")
    lines.append("    ],")
    lines.append(")")
    return "\n".join(lines) + "\n"


def main() -> int:
    top = fetch_top_words()
    words = build_word_set(top)
    ron = build_ron(words)
    if "--check" in sys.argv:
        current = _OUT.read_text(encoding="utf-8") if _OUT.exists() else ""
        if current != ron:
            print(
                "en_common_words.ron is out of sync. Review the diff, then run: "
                "python -m argus_redact.specs.gen_en_common_words",
                file=sys.stderr,
            )
            return 1
        print("en_common_words.ron is in sync")
        return 0
    _OUT.parent.mkdir(parents=True, exist_ok=True)
    _OUT.write_text(ron, encoding="utf-8")
    rel = _OUT.relative_to(Path(__file__).resolve().parents[3])
    print(f"Wrote {rel}")
    print(f"  fetched top-N:   {len(top)} (TOP_N={TOP_N})")
    print(f"  curated supp.:   {len(CURATED_SUPPLEMENT)}")
    print(f"  total entries:   {len(words)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
