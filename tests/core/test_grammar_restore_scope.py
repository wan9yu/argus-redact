"""C7 — restore's reverse grammar fix must scope to actual pronoun restorations.

`restore()` fixes up a first-person verb right after a restored self_reference
pronoun (e.g. key {"P-1": "I"} turns "P-1 is here" back into "I is here", then
the grammar fix corrects that to "I am here"). Before this fix, that grammar
fix ran as a whole-text pass whenever ANY key value was a self-ref pronoun —
so an UNRELATED "I is" already present elsewhere in the text (never produced
by this restoration) also got rewritten to "I am", corrupting content the
restore step never touched.
"""

from argus_redact import restore


class TestGrammarRestoreScope:
    def test_unrelated_i_is_not_mangled_by_restored_pronoun_fix(self):
        # The restored "P-1" -> "I is here" gets grammar-fixed to "I am here",
        # but the unrelated "The letter I is silent." must survive verbatim —
        # it was never produced by a substitution.
        key = {"P-1": "I"}
        text = "P-1 is here. The letter I is silent."

        result = restore(text, key, guard=False)

        assert result.startswith("I am here.")
        assert "The letter I is silent." in result
        assert result == "I am here. The letter I is silent."

    def test_correctly_conjugated_restored_pronoun_not_over_corrected(self):
        # "P-1 am fine" restores to "I am fine", which is already correct —
        # the grammar fix must not touch it (no "I is"/"I has"/... pattern).
        key = {"P-1": "I"}
        text = "P-1 am fine"

        result = restore(text, key, guard=False)

        assert result == "I am fine"

    def test_no_self_ref_key_leaves_text_byte_identical(self):
        # No key value is a self-ref pronoun -> the grammar fix must never
        # fire at all, regardless of what verbs happen to sit in the text.
        key = {"P-1": "Alice"}
        text = "P-1 is here. The letter I is silent."

        result = restore(text, key, guard=False)

        assert result == "Alice is here. The letter I is silent."

    def test_two_close_together_self_ref_restorations_both_get_fixed(self):
        # Two separate "I" restorations close together: the first window
        # (12 chars past the first restored "I") reaches byte 13 of the
        # output — far enough to cover the *second* restored "I" itself, but
        # NOT its own trailing "is". The old overlap-SKIP logic then dropped
        # the second span entirely (its start fell inside the first window),
        # so the second "I is" was never fixed. Merging windows instead of
        # skipping must fix both.
        key = {"P-1": "I", "P-2": "I"}
        text = "P-1 is" + " " * 8 + "P-2 is right"

        result = restore(text, key, guard=False)

        assert result == "I am" + " " * 8 + "I am right"
