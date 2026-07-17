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
from argus_redact.pure.grammar import normalize_grammar_en


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


class TestGrammarRestoreWePronoun:
    """The reverse grammar fix must cover `we`, not just `I`.

    `we` is a `SELF_REF_PRONOUNS` value just like `I`, so pseudonymizing it
    arms the same forward rule (any self-ref key value rewrites a following
    first-person verb to third-person on the pseudonym code). Before this
    fix, `GRAMMAR_RESTORE_EN` only reversed `I ...` back to first person, so a
    restored `we` was left with the third-person verb: `we have` round-tripped
    through pseudonymize -> normalize -> restore as `we has` (silently wrong).
    """

    def test_we_have_roundtrips_through_forward_normalize_and_restore(self):
        key = {"P-1": "we"}
        # Simulate the forward pseudonymize + normalize step redact() performs:
        # "we have a meeting" -> (pseudonymize "we") "P-1 have a meeting"
        # -> (normalize_grammar_en, armed by the self-ref key value "we").
        forward = normalize_grammar_en("P-1 have a meeting", ["we"])
        assert forward == "P-1 has a meeting"  # sanity: forward rule fired

        result = restore(forward, key, guard=False)

        assert result == "we have a meeting"

    def test_we_do_roundtrips_through_forward_normalize_and_restore(self):
        key = {"P-1": "we"}
        forward = normalize_grammar_en("P-1 do the work", ["we"])
        assert forward == "P-1 does the work"

        result = restore(forward, key, guard=False)

        assert result == "we do the work"

    def test_we_dont_roundtrips_through_forward_normalize_and_restore(self):
        key = {"P-1": "we"}
        forward = normalize_grammar_en("P-1 don't know", ["we"])
        assert forward == "P-1 doesn't know"

        result = restore(forward, key, guard=False)

        assert result == "we don't know"

    def test_we_is_restores_to_we_are(self):
        # There's no forward "are"->"is" rule (VERB_PAIRS has no "are" entry),
        # so this exercises the reverse rule directly the same way the "I"
        # copula case is exercised elsewhere in this file — "we is" must not
        # survive a restore, since "we" takes "are", not "is".
        key = {"P-1": "we"}
        text = "P-1 is here"

        result = restore(text, key, guard=False)

        assert result == "we are here"

    def test_i_am_and_i_have_still_roundtrip(self):
        # Control: adding "we" reversals must not regress the pre-existing
        # "I" reversals.
        key = {"P-1": "I"}

        forward_am = normalize_grammar_en("P-1 am here", ["I"])
        assert forward_am == "P-1 is here"
        assert restore(forward_am, key, guard=False) == "I am here"

        forward_have = normalize_grammar_en("P-1 have a cat", ["I"])
        assert forward_have == "P-1 has a cat"
        assert restore(forward_have, key, guard=False) == "I have a cat"

    def test_correctly_conjugated_we_verb_not_over_corrected(self):
        # "we have"/"we are" are already correct — restoring them must not
        # trigger any reverse rule (no "we is"/"we has"/... pattern present).
        key = {"P-1": "we"}

        assert restore("P-1 have fun", key, guard=False) == "we have fun"
        assert restore("P-1 are fine", key, guard=False) == "we are fine"
