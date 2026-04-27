"""Tests for v0.5.8 alias-aware restore().

When LLMs transliterate fake names (e.g. ``张三`` → ``Zhang San``), restore()
must still map the alias back to the original. Triggered by passing
``result.key_entries`` (dict[str, KeyEntry]) instead of ``result.key`` to
restore().

Backward compatibility: the legacy ``restore(text, dict[str, str])`` path
still works exactly as before.
"""

from argus_redact import KeyEntry, redact_pseudonym_llm
from argus_redact.pure.restore import restore


class TestLegacyDictStillWorks:
    def test_str_to_str_dict_unchanged(self):
        text = "P-001 phoned"
        key = {"P-001": "王建国"}
        assert restore(text, key) == "王建国 phoned"


class TestKeyEntriesShapeAcceptsKeyEntry:
    def test_restore_with_key_entries_no_alias(self):
        text = "P-001 phoned"
        entries = {"P-001": KeyEntry(original="王建国")}
        assert restore(text, entries) == "王建国 phoned"

    def test_restore_matches_alias_back_to_original(self):
        # LLM rephrased the canonical fake into a transliteration alias
        text = "Wang Wu phoned 138****8000"
        entries = {
            "王五": KeyEntry(original="王建国", aliases=("Wang Wu", "WangWu")),
            "138****8000": KeyEntry(original="13800138000"),
        }
        out = restore(text, entries)
        assert out == "王建国 phoned 13800138000"

    def test_restore_matches_canonical_fake_when_present(self):
        text = "王五 and Wang Wu both"
        entries = {
            "王五": KeyEntry(original="王建国", aliases=("Wang Wu",)),
        }
        out = restore(text, entries)
        # Both forms map back to the original
        assert out == "王建国 and 王建国 both"

    def test_restore_picks_longer_alias_first(self):
        # alternation regex sorts by length descending — longer alias matches first
        text = "Zhang Sanity is fine"
        entries = {
            "张三": KeyEntry(original="王建国", aliases=("Zhang San", "Zhang")),
        }
        out = restore(text, entries)
        # "Zhang San" matched (longer wins over "Zhang"); "ity" suffix preserved
        assert out == "王建国ity is fine"


class TestEndToEndCrossLanguage:
    def test_zh_redact_then_en_alias_in_llm_output(self):
        text = "联系王建国"
        r = redact_pseudonym_llm(text, salt=b"fixed", lang="zh")
        # Pick whichever fake the seed chose + its alias
        person_entries = {
            f: e for f, e in r.key_entries.items() if e.original == "王建国" and e.aliases
        }
        assert person_entries, "v0.5.8: realistic person fake should carry aliases"
        fake = next(iter(person_entries))
        alias = person_entries[fake].aliases[0]
        # Simulate LLM transliterating the zh fake to its alias
        llm_output = r.downstream_text.replace(fake, alias)
        # restore() with key_entries handles both fake AND alias
        restored = restore(llm_output, r.key_entries)
        assert restored == text, f"expected {text!r}, got {restored!r}"


class TestEmptyKeyEdgeCase:
    def test_empty_key_entries(self):
        assert restore("hello", {}) == "hello"
