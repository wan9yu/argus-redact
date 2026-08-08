"""The scope guard may only ever WITHHOLD — never corrupt.

An out-of-scope pseudonym is withheld by dropping it from the restore lookup.
If it is also dropped from the longest-first alternation, a SHORTER in-scope
pseudonym matches inside it and splices one identity's original into another
identity's token. The guard then reports that token as "withheld" while having
already mangled it — turning the security feature ON makes the output worse
than leaving it off.

Every case here asserts the same two things:
  * the out-of-scope token survives byte-for-byte in the output;
  * every in-scope substitution lands exactly where an unguarded restore put it.
"""

from __future__ import annotations

import pytest

from argus_redact import restore
from argus_redact.compose.anchor import Anchor

NONCE = "abc123deadbeef00"  # >= the 16-char guard floor


def guarded(text, key, scope, aliases=None):
    return restore(
        f"{text}\n{NONCE}",
        key,
        aliases=aliases,
        guard=True,
        anchor=Anchor(nonce=NONCE, scope=frozenset(scope)),
        detailed=True,
    )


class TestOutOfScopePseudonymsAreWithheldAtomically:
    def test_zh_name_prefix_is_not_spliced(self):
        """李明 (in scope) is a strict prefix of 李明华 (out of scope)."""
        key = {"李明": "张伟", "李明华": "王芳"}
        text, meta = guarded("李明华 reported that 李明 left.", key, {"李明"})

        assert text == "李明华 reported that 张伟 left."
        assert "张伟华" not in text, "an out-of-scope identity was spliced"
        assert meta["outcome"] == "partial"

    def test_code_prefix_is_not_spliced(self):
        """P-1 (in scope) is a prefix of P-10 (out of scope)."""
        key = {"P-1": "Alice", "P-10": "Ten"}
        text, meta = guarded("P-10 and P-1", key, {"P-1"})

        assert text == "P-10 and Alice"
        assert "Alice0" not in text
        assert meta["outcome"] == "partial"

    def test_three_way_prefix_chain(self):
        key = {"P-1": "Alice", "P-10": "Ten", "P-100": "Hundred"}
        text, _ = guarded("P-100 P-10 P-1", key, {"P-1"})
        assert text == "P-100 P-10 Alice"

    @pytest.mark.parametrize(
        "scope",
        [{"P-1"}, {"P-10"}, {"P-100"}, {"P-1", "P-10"}, {"P-1", "P-100"}, {"P-1", "P-10", "P-100"}],
    )
    def test_every_scope_width_only_withholds(self, scope):
        """At any scope width the guard is a pure filter of the unguarded pass.

        The oracle tokenises against the FULL key longest-first — the same set
        the redactor minted — and substitutes only the in-scope tokens. A naive
        per-code ``str.replace`` loop would reproduce the very defect under
        test, because ``"P-1"`` occurs inside ``"P-100"``.
        """
        import re

        key = {"P-1": "Alice", "P-10": "Ten", "P-100": "Hundred"}
        source = "P-100 P-10 P-1"
        text, _ = guarded(source, key, scope)

        alternation = "|".join(re.escape(c) for c in sorted(key, key=len, reverse=True))
        expected = re.sub(
            alternation,
            lambda m: key[m.group(0)] if m.group(0) in scope else m.group(0),
            source,
        )
        assert text == expected


class TestAliasesCannotEscapeScope:
    def test_alias_of_in_scope_fake_cannot_claim_an_out_of_scope_fake(self):
        """The dedupe trap: an alias of P-1 IS the out-of-scope fake P-2.

        Merging aliases over an already-scoped key cannot see the collision
        (P-2's own entry was filtered away first), so P-2 would be substituted
        with P-1's identity — the withheld pseudonym restored, wrongly.
        """
        key = {"P-1": "Alice", "P-2": "Bob"}
        text, meta = guarded("P-1 and P-2", key, {"P-1"}, aliases={"P-1": ("P-2",)})

        assert text == "Alice and P-2"
        assert text != "Alice and Alice"
        assert meta["outcome"] == "partial"

    def test_alias_of_out_of_scope_fake_is_reported_as_withheld(self):
        """strict=True must fail closed on an out-of-scope alias too."""
        key = {"P-1": "Alice", "P-2": "Bob"}
        text, meta = guarded("P-1 met Bobby", key, {"P-1"}, aliases={"P-2": ("Bobby",)})

        assert text == "Alice met Bobby"
        codes = [e["reason_code"] for e in meta["security_events"]]
        assert "out_of_scope_pseudonym" in codes
        assert meta["outcome"] == "partial"

    def test_strict_raises_on_an_out_of_scope_alias(self):
        from argus_redact.pure.restore import RestoreGuardError

        key = {"P-1": "Alice", "P-2": "Bob"}
        with pytest.raises(RestoreGuardError):
            restore(
                f"P-1 met Bobby\n{NONCE}",
                key,
                aliases={"P-2": ("Bobby",)},
                guard=True,
                anchor=Anchor(nonce=NONCE, scope=frozenset({"P-1"})),
                strict=True,
            )
