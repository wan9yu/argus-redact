"""``restore_json``/``restore_csv`` must emit the same alias-collision
``SecurityWarning`` the streaming and one-shot restore faces already emit.

Both structured restore faces build a `_core.StructuredRestorer` session via
`make_structured_restorer` (the same session `StreamingRestorer.__init__`
uses) and that session exposes the identical `alias_collisions` getter —
populated when two different originals' aliases collide on the same string,
making the restored value for that string ambiguous between them. Streaming
already reads the getter and warns at construction time
(`StreamingRestorer.__init__` -> `warn_alias_collisions`); the structured
JSON/CSV faces built the session but never read the getter, so an identical
collision was silently swallowed there.
"""

from __future__ import annotations

import warnings

import pytest

from argus_redact.exceptions import SecurityWarning
from argus_redact.structured import restore_csv, restore_json

# Two different originals whose alias both collide on "Shared" -- restoring
# "Shared" back is genuinely ambiguous between Alice and Bob.
_COLLIDING_KEY = {"P-1": "Alice", "P-2": "Bob"}
_COLLIDING_ALIASES = {"P-1": ["Shared"], "P-2": ["Shared"]}


class TestRestoreJsonAliasCollisionWarning:
    def test_restore_json_should_warn_when_aliases_collide(self):
        with pytest.warns(SecurityWarning, match="alias"):
            restore_json(
                {"text": "hello Shared"}, dict(_COLLIDING_KEY), aliases=dict(_COLLIDING_ALIASES)
            )

    def test_restore_json_should_not_warn_when_aliases_do_not_collide(self):
        key = {"P-1": "Alice"}
        aliases = {"P-1": ["Al"]}
        with warnings.catch_warnings():
            warnings.simplefilter("error", SecurityWarning)
            result = restore_json({"text": "hello Al"}, key, aliases=aliases)
        assert result == {"text": "hello Alice"}

    def test_restore_json_should_not_warn_when_no_aliases_are_given(self):
        # No `aliases=` at all -> no collision is even possible; must stay quiet.
        with warnings.catch_warnings():
            warnings.simplefilter("error", SecurityWarning)
            result = restore_json({"text": "P-1 says hi"}, {"P-1": "Alice"})
        assert result == {"text": "Alice says hi"}


class TestRestoreCsvAliasCollisionWarning:
    def test_restore_csv_should_warn_when_aliases_collide(self):
        csv_text = "note\nhello Shared"
        with pytest.warns(SecurityWarning, match="alias"):
            restore_csv(csv_text, dict(_COLLIDING_KEY), aliases=dict(_COLLIDING_ALIASES))

    def test_restore_csv_should_not_warn_when_aliases_do_not_collide(self):
        key = {"P-1": "Alice"}
        aliases = {"P-1": ["Al"]}
        csv_text = "note\nhello Al"
        with warnings.catch_warnings():
            warnings.simplefilter("error", SecurityWarning)
            result = restore_csv(csv_text, key, aliases=aliases)
        assert "Alice" in result

    def test_restore_csv_should_not_warn_when_no_aliases_are_given(self):
        csv_text = "note\nP-1 says hi"
        with warnings.catch_warnings():
            warnings.simplefilter("error", SecurityWarning)
            result = restore_csv(csv_text, {"P-1": "Alice"})
        assert "Alice" in result
