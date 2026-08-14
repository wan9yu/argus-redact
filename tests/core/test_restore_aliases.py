"""Tests for v0.6.0 alias-aware restore().

When LLMs transliterate fake names (e.g. ``张三`` → ``Zhang San``), restore()
must still map the alias back to the original. v0.6.0 unified API: pass
``result.key`` plus the new ``aliases=`` kwarg with ``result.aliases``.
"""

import pytest

from argus_redact import make_anchor, redact_pseudonym_llm
from argus_redact.pure.restore import _normalize_aliases, restore


class TestLegacyDictStillWorks:
    def test_str_to_str_dict_unchanged(self):
        text = "P-001 phoned"
        key = {"P-001": "王建国"}
        assert restore(text, key, guard=False) == "王建国 phoned"


class TestAliasesKwargRoundTrip:
    def test_restore_with_aliases_kwarg(self):
        text = "Wang Wu phoned 138****8000"
        key = {"王五": "王建国", "138****8000": "13800138000"}
        aliases = {"王五": ("Wang Wu", "WangWu")}
        out = restore(text, key, aliases=aliases, guard=False)
        assert out == "王建国 phoned 13800138000"

    def test_restore_matches_canonical_fake_when_present(self):
        text = "王五 and Wang Wu both"
        key = {"王五": "王建国"}
        aliases = {"王五": ("Wang Wu",)}
        out = restore(text, key, aliases=aliases, guard=False)
        # Both forms map back to the original
        assert out == "王建国 and 王建国 both"

    def test_restore_picks_longer_alias_first(self):
        # alternation regex sorts by length descending — longer alias matches first
        text = "Zhang Sanity is fine"
        key = {"张三": "王建国"}
        aliases = {"张三": ("Zhang San", "Zhang")}
        out = restore(text, key, aliases=aliases, guard=False)
        # "Zhang San" matched (longer wins over "Zhang"); "ity" suffix preserved
        assert out == "王建国ity is fine"

    def test_restore_without_aliases_kwarg_no_alias_lookup(self):
        # If aliases= is not provided, only the canonical fakes match.
        text = "Wang Wu phoned"
        key = {"王五": "王建国"}
        # Without aliases=, "Wang Wu" stays unchanged (no mapping)
        out = restore(text, key, guard=False)
        assert out == "Wang Wu phoned"


class TestEndToEndCrossLanguage:
    def test_zh_redact_then_en_alias_in_llm_output(self):
        text = "联系王建国"
        r = redact_pseudonym_llm(text, salt=b"fixed", lang="zh")
        person_fakes = {f: r.key[f] for f in r.aliases if r.key.get(f) == "王建国"}
        assert person_fakes, "v0.6.0: realistic person fake should carry aliases"
        fake = next(iter(person_fakes))
        alias = r.aliases[fake][0]
        llm_output = r.downstream_text.replace(fake, alias)
        restored = restore(llm_output, r.key, aliases=r.aliases, guard=False)
        assert restored == text, f"expected {text!r}, got {restored!r}"

    def test_zh_address_redact_then_en_alias_in_llm_output(self):
        text = "我住在北京市朝阳区建国路100号"
        r = redact_pseudonym_llm(text, salt=b"fixed-addr", lang="zh")
        addr_fakes = {f: r.key[f] for f in r.aliases if r.key.get(f) == "北京市朝阳区建国路100号"}
        if not addr_fakes:
            import pytest

            pytest.skip("seed picked address w/o aliases — re-run other tests cover this")
        fake = next(iter(addr_fakes))
        alias = r.aliases[fake][0]
        llm_output = r.downstream_text.replace(fake, alias)
        restored = restore(llm_output, r.key, aliases=r.aliases, guard=False)
        assert restored == text


class TestEmptyKeyEdgeCase:
    def test_empty_key(self):
        assert restore("hello", {}, guard=False) == "hello"

    def test_empty_key_with_aliases(self):
        # No-op even if aliases are provided but key is empty
        assert restore("hello", {}, aliases={}, guard=False) == "hello"


class TestResultAliasesField:
    """v0.6.0: result.aliases replaces result.key_entries."""

    def test_result_has_aliases_dict(self):
        from argus_redact import redact_pseudonym_llm

        r = redact_pseudonym_llm("联系王建国", salt=b"x", lang="zh")
        assert hasattr(r, "aliases")
        assert isinstance(r.aliases, dict)
        # aliases values are tuples (immutable)
        for v in r.aliases.values():
            assert isinstance(v, tuple), f"aliases values must be tuple, got {type(v)}"

    def test_key_entries_attribute_removed(self):
        from argus_redact import redact_pseudonym_llm

        r = redact_pseudonym_llm("hello", salt=b"x", lang="zh")
        assert not hasattr(r, "key_entries"), "key_entries removed in v0.6.0"

    def test_keyentry_class_removed_from_public_api(self):
        import argus_redact

        assert not hasattr(argus_redact, "KeyEntry"), "KeyEntry removed in v0.6.0"


class TestNormalizeAliasesSeam:
    """`_normalize_aliases` is the ONE seam every restore face funnels an
    `aliases` argument through (`restore`, `make_structured_restorer`,
    `StreamingRestorer.__init__`). It both validates AND coerces, so no
    construction point can coerce a malformed shape without validating it
    first — pinned directly here; the faces themselves are pinned in
    `TestAliasesRejectionAtEveryFace` below.
    """

    def test_none_normalizes_to_empty_dict(self):
        assert _normalize_aliases(None) == {}

    def test_list_values_coerced_to_tuples(self):
        assert _normalize_aliases({"P-1": ["a", "b"]}) == {"P-1": ("a", "b")}

    def test_tuple_values_pass_through(self):
        assert _normalize_aliases({"P-1": ("a", "b")}) == {"P-1": ("a", "b")}

    def test_non_mapping_aliases_rejected(self):
        with pytest.raises(ValueError):
            _normalize_aliases(["not", "a", "mapping"])

    def test_bare_string_value_rejected_not_split_into_chars(self):
        # The exact footgun: pre-fix, `tuple("abc")` silently became
        # `('a', 'b', 'c')` instead of raising.
        with pytest.raises(ValueError):
            _normalize_aliases({"P-1": "abc"})

    def test_bare_bytes_value_rejected(self):
        with pytest.raises(ValueError):
            _normalize_aliases({"P-1": b"abc"})

    def test_non_str_element_rejected(self):
        with pytest.raises(ValueError):
            _normalize_aliases({"P-1": [123]})

    def test_nested_list_element_rejected(self):
        with pytest.raises(ValueError):
            _normalize_aliases({"P-1": [["a"]]})

    def test_error_message_names_key_not_value(self):
        # PII-free: the offending KEY and shape class, never the alias text.
        with pytest.raises(ValueError, match=r"P-1") as excinfo:
            _normalize_aliases({"P-1": "super-secret-alias-text"})
        assert "super-secret-alias-text" not in str(excinfo.value)


class TestAliasesRejectionAtEveryFace:
    """The seam is wired at every real construction point — a malformed
    `aliases` shape must raise ValueError there, not silently corrupt (bare
    string -> per-character split) or crash later with a cryptic TypeError.
    """

    def test_scalar_restore_unguarded_rejects_bare_string(self):
        with pytest.raises(ValueError):
            restore("x", {"P-1": "orig"}, aliases={"P-1": "abc"}, guard=False)

    def test_scalar_restore_unguarded_rejects_non_str_element(self):
        with pytest.raises(ValueError):
            restore("x", {"P-1": "orig"}, aliases={"P-1": [123]}, guard=False)

    def test_scalar_restore_guarded_rejects_bare_string(self):
        # The seam runs before the guard/no-guard dispatch, so the guarded
        # branch must reject too, not just the guard=False legacy path.
        key = {"P-1": "orig"}
        anchor = make_anchor(key)
        with pytest.raises(ValueError):
            restore("x", key, aliases={"P-1": "abc"}, guard=True, anchor=anchor)


class TestAliasesTupleRoundTrip:
    """Round-trip safety: aliases are canonically TUPLE-valued
    (``PseudonymLLMResult.aliases``), so the seam must ACCEPT tuples, not
    just lists, or it breaks the redact -> LLM -> restore round trip. Uses
    ``redact_pseudonym_llm`` (NOT batch ``redact()``, which returns no
    aliases at all) as the producer, per the canonical shape it emits.
    """

    def test_tuple_valued_aliases_from_redact_pseudonym_llm_round_trip(self):
        r = redact_pseudonym_llm("联系王建国", salt=b"tuple-rt", lang="zh")
        person_fakes = {f: r.key[f] for f in r.aliases if r.key.get(f) == "王建国"}
        assert person_fakes, "realistic person fake should carry aliases"
        fake = next(iter(person_fakes))
        alias = r.aliases[fake][0]
        assert isinstance(r.aliases[fake], tuple), "aliases values must be tuple-valued"
        llm_output = r.downstream_text.replace(fake, alias)
        restored = restore(llm_output, r.key, aliases=r.aliases, guard=False)
        assert restored == "联系王建国"
