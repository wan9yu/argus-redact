# Embedded data (SSOT)

The `.ron` files in this directory are the single source of truth (SSOT) for the
detection pools that ship inside `argus-redact-core`. They are embedded at build
time, so the published wheel needs no external data files.

This note covers the **person-name** pools and how to regenerate them. They are
golden-locked by `tests/detection/lang/test_person_data_parity.py` (frozen entry
counts + sha256 over each pool), so any change is a deliberate, reviewed
re-freeze — do not regenerate-and-commit casually.

## `zh_person.ron` — Chinese person names

Four pools:

| Pool                 | Provenance                                                                 |
| -------------------- | ------------------------------------------------------------------------- |
| `surnames`           | Curated single-char surname list (order-load-bearing, stored byte-for-byte). |
| `compound_surnames`  | Curated two-char compound surnames (e.g. 欧阳, 司马).                       |
| `not_names`          | Derived: surname-prefixed jieba entries NOT tagged `nr`, plus a curated override set. |
| `common_words`       | Derived: high-frequency 2-char jieba words NOT tagged `nr` (swallow detection). |

- The two **surname** pools are a curated list, carried verbatim in the
  regeneration script — they are not derived from any external dictionary.
- The two **derived** pools come from jieba's `dict.txt`
  ([fxsjy/jieba](https://github.com/fxsjy/jieba), MIT license) via a pos-filter
  plus a manually-curated `OVERRIDE_COMMON_WORDS` set. The derivation rules and
  the override set live in `scripts/build_zh_dicts.py`.

Regenerate:

```sh
pip install jieba          # pinned: jieba==0.42.1 (the version this RON was built from)
python scripts/build_zh_dicts.py --check   # verify the committed RON is up to date
python scripts/build_zh_dicts.py           # rewrite it in place
```

The script output is byte-identical to the committed RON under jieba 0.42.1. A
different jieba dict version will drift the derived pools, which would change the
golden — only do that as an intentional, reviewed re-freeze (update the frozen
counts/sha256 in the parity test in the same change).

## `en_person.ron` — English person names

Two pools, both curated from U.S. federal public-domain sources
(17 USC § 105 — works of the U.S. federal government):

| Pool          | Source                                                                                     |
| ------------- | ------------------------------------------------------------------------------------------ |
| `given_names` | U.S. Social Security Administration, [Top Names by Decade](https://www.ssa.gov/oact/babynames/decades/) — 199 most-frequent given names. |
| `surnames`    | U.S. Census Bureau, [2010 Surname File](https://www.census.gov/topics/population/genealogy/data/2010_surnames.html) — the 615 most-frequent surnames sourced from the file, which itself covers ~75% of the U.S. population. |

These are static curated lists with no scripted derivation; the long tail is
intentionally excluded (fast-mode list-match targets common names — rarer names
should be supplied via `names=[...]` or detected with NER, `mode="ner"`). To
update, edit the pools directly and re-freeze the parity test fingerprints.

## `hints.ron` — cross-layer kinship / command hint tables

Five pools, aggregated from the per-language `lang/<code>/hints.py` sources
(zh/en/ja/ko/de/uk/in_/br) the way `pure/hints.py` combines them:

| Pool               | Provenance                                                            |
| ------------------ | -------------------------------------------------------------------- |
| `kinship_exact`    | Union of each language's `KINSHIP` exact-match phrases.              |
| `kinship_prefixes` | Union of each language's `KINSHIP_PREFIXES`.                         |
| `command_prefixes` | Union of each language's `COMMAND_PREFIXES`.                         |
| `command_suffixes` | Union of each language's `COMMAND_SUFFIXES`.                         |
| `command_patterns` | Each language's `COMMAND_PATTERNS`, as `(pattern source, ignorecase)`. |

The string pools are sorted; order is irrelevant (all consumers use `any(...)`
or set membership). `command_patterns` carries the regex source plus a
per-pattern `ignorecase` flag (read from Python's `re.Pattern.flags`, not
assumed) — the loader wraps the source in `(?i:…)` IFF that flag is set,
mirroring `re.IGNORECASE`.

These feed the `text_intent` / `self_reference_tier` hint logic. They are
golden-locked by `tests/architecture/test_hints_data_parity.py` (frozen counts +
sha256 over each pool); editing a `lang/<code>/hints.py` source means
regenerating this RON from the aggregated `pure.hints` attributes and re-freezing
those fingerprints in the same reviewed change.
