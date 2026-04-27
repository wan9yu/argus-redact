"""Tests for v0.5.8 KeyEntry + PseudonymLLMResult.key_entries.

Backward compatibility: ``result.key`` stays str→str dict-like via
``MappingProxyType``. New ``result.key_entries`` exposes structured
``KeyEntry`` instances. v0.5.8 lands the shape; aliases are still empty
(commit 2 fills them).
"""

from argus_redact import KeyEntry, PseudonymLLMResult, redact_pseudonym_llm
from argus_redact.pure.restore import restore


class TestKeyEntryDataclass:
    def test_keyentry_default_aliases_empty_tuple(self):
        e = KeyEntry(original="王建国")
        assert e.original == "王建国"
        assert e.aliases == ()

    def test_keyentry_with_aliases(self):
        e = KeyEntry(original="王建国", aliases=("Wang Jianguo",))
        assert e.aliases == ("Wang Jianguo",)

    def test_keyentry_is_hashable(self):
        # tuple aliases keep frozen-friendly hashable
        e = KeyEntry(original="王建国", aliases=("Wang Jianguo",))
        hash(e)


class TestPseudonymLLMResultKeyView:
    def test_result_key_is_str_to_str_dict(self):
        r = redact_pseudonym_llm("电话13912345678", lang="zh")
        assert isinstance(r.key, dict)
        for k, v in r.key.items():
            assert isinstance(k, str)
            assert isinstance(v, str)

    def test_result_key_returns_fresh_copy(self):
        # Mutating the returned dict must not leak into internal state.
        r = redact_pseudonym_llm("电话13912345678", lang="zh")
        before = dict(r.key)
        r.key["evil"] = "x"  # mutate the copy
        after = dict(r.key)  # fresh copy on every property access
        assert before == after, "internal state must be unaffected by caller mutation"

    def test_result_key_compatible_with_restore(self):
        text = "请联系王建国电话13912345678"
        r = redact_pseudonym_llm(text, lang="zh", salt=b"fixed")
        restored = restore(r.audit_text, r.key)
        assert restored == text

    def test_result_key_json_serializable(self):
        # Backward-compat for v0.5.6 callers that json.dumps(result.key) directly.
        import json

        r = redact_pseudonym_llm("电话13912345678", lang="zh")
        encoded = json.dumps(r.key, ensure_ascii=False)
        assert encoded.startswith("{") and encoded.endswith("}")


class TestPseudonymLLMResultKeyEntries:
    def test_key_entries_is_str_to_keyentry_dict(self):
        r = redact_pseudonym_llm("电话13912345678", lang="zh")
        assert isinstance(r.key_entries, dict)
        for fake, entry in r.key_entries.items():
            assert isinstance(fake, str)
            assert isinstance(entry, KeyEntry)

    def test_key_entries_returns_fresh_copy(self):
        r = redact_pseudonym_llm("电话13912345678", lang="zh")
        before = dict(r.key_entries)
        r.key_entries["evil"] = KeyEntry(original="x")
        after = dict(r.key_entries)
        assert before == after

    def test_default_aliases_empty_in_v058_pre_commit2(self):
        # v0.5.8 commit 1 lands the shape only; aliases stay empty until
        # commit 2 fills them. This test will be updated in commit 2.
        r = redact_pseudonym_llm("电话13912345678", lang="zh")
        for entry in r.key_entries.values():
            assert entry.aliases == ()


class TestKeyEntriesAndKeyAreConsistent:
    def test_every_fake_in_key_appears_in_key_entries_with_same_original(self):
        r = redact_pseudonym_llm("请联系王建国电话13912345678", lang="zh", salt=b"x")
        for fake, original in r.key.items():
            assert fake in r.key_entries
            assert r.key_entries[fake].original == original
