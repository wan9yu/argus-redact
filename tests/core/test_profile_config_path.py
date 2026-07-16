"""C1 + R5 — profile + file-path config no longer crashes; non-dict config

gets a clean TypeError instead of an AttributeError.

C1: ``redact(profile=..., config="<path>")`` used to always crash — the
profile block did ``profile_config.update(config)`` while ``config`` was
still a str (a file path); the str->dict file resolution ran *after* that
merge. Fixed by resolving the file path before the profile merge.

R5: ``_validate_config`` called ``config.items()`` with no type guard, so a
non-dict config (e.g. a list of pairs) raised ``AttributeError`` instead of a
message naming the actual problem.
"""

from __future__ import annotations

import json

import pytest

from argus_redact import redact


class TestProfileWithFileConfig:
    def test_profile_plus_file_path_config_succeeds(self, tmp_path):
        """(a) profile= + a real config file path together must not crash."""
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"phone": {"strategy": "mask"}}), encoding="utf-8")

        redacted, key = redact(
            "call 13800138000",
            lang="zh",
            profile="gdpr",
            config=str(config_path),
        )

        assert "13800138000" not in redacted
        assert key

    def test_profile_plus_file_path_config_user_override_wins(self, tmp_path):
        """User config (from the file) overrides the profile's base config."""
        config_path = tmp_path / "config.json"
        # gdpr forces phone -> remove; the user file asks for mask instead.
        config_path.write_text(json.dumps({"phone": {"strategy": "mask"}}), encoding="utf-8")

        redacted, _ = redact(
            "call 13800138000",
            lang="zh",
            profile="gdpr",
            config=str(config_path),
        )

        # mask keeps a partial digit run visible; remove would not.
        assert any(ch.isdigit() for ch in redacted)

    def test_profile_with_missing_config_file_still_raises_filenotfound(self, tmp_path):
        """A genuinely missing file still raises FileNotFoundError, not the
        old dict-update crash — ordering changed but the error for a bad
        path is unchanged."""
        missing = tmp_path / "does-not-exist.json"

        with pytest.raises(FileNotFoundError):
            redact("call 13800138000", lang="zh", profile="gdpr", config=str(missing))


class TestValidateConfigNonDict:
    def test_list_config_raises_clean_type_error(self):
        """(c) a non-dict config raises a TypeError naming `config`, not an
        AttributeError from inside `.items()`."""
        with pytest.raises(TypeError, match="config"):
            redact("call 13800138000", lang="zh", config=[("phone", {})])

    def test_list_config_error_is_not_attribute_error(self):
        try:
            redact("call 13800138000", lang="zh", config=[("phone", {})])
        except AttributeError:
            pytest.fail("non-dict config raised AttributeError instead of TypeError")
        except TypeError:
            pass


class TestValidateConfigNonDictEntryValue:
    """F4 — a well-formed dict config with a non-dict per-type VALUE (e.g.
    ``{"phone": "mask"}``, a plausible caller mistake for
    ``{"phone": {"strategy": "mask"}}``) used to be silently skipped
    (``continue``), so the strategy was quietly ignored instead of raising.
    """

    def test_non_dict_entry_value_raises_typeerror_naming_the_key(self):
        with pytest.raises(TypeError, match=r"config\['phone'\]"):
            redact("电话13800138000", lang="zh", config={"phone": "mask"})

    def test_non_dict_entry_value_is_not_silently_ignored(self):
        """Before the fix this silently degraded to the default strategy
        instead of raising — confirm it's a hard failure, not a no-op."""
        try:
            redact("电话13800138000", lang="zh", config={"phone": "mask"})
        except TypeError:
            pass
        else:
            pytest.fail("non-dict config[phone] value should raise, not silently redact")

    def test_valid_dict_config_still_redacts(self):
        """Positive control: a correctly-shaped dict config is unaffected."""
        redacted, key = redact(
            "电话13800138000", lang="zh", config={"phone": {"strategy": "mask"}}
        )

        assert "13800138000" not in redacted
        assert key


class TestValidateConfigUnderscoreKeyNarrowing:
    """`_validate_config` used to skip every underscore-prefixed key, not just
    the one reserved sentinel (`_unified_prefix`). `register_pii_type` does
    not forbid underscore-named custom entity types, so a config entry like
    ``{"_internal_id": {"strategy": "bogus_typo"}}`` was silently skipped
    instead of raising on the unknown strategy.
    """

    def test_underscore_named_custom_type_bad_strategy_still_raises(self):
        with pytest.raises(ValueError, match="bogus_typo"):
            redact("x", config={"_internal_id": {"strategy": "bogus_typo"}})

    def test_unified_prefix_sentinel_still_raises(self):
        """Unchanged behavior: `_unified_prefix` remains a reserved sentinel
        rejected by its own dedicated check, not by the per-type loop."""
        with pytest.raises(ValueError, match="_unified_prefix"):
            redact(
                "x",
                config={"_unified_prefix": "R", "phone": {"strategy": "remove"}},
            )


class TestProfileConfigDeepMerge:
    """C8 — the profile+config merge used to be a shallow
    ``profile_config.update(config)``: a user override for a type already in
    the profile REPLACED the whole per-type dict instead of merging into it.

    gdpr forces ``phone -> {"strategy": "remove"}``. A caller who only wants
    to tweak ``visible_suffix`` (a mask-only knob) without touching strategy
    — ``config={"phone": {"visible_suffix": 2}}`` — should still get gdpr's
    ``remove`` behavior. Under the shallow bug, the whole "phone" entry was
    replaced by ``{"visible_suffix": 2}``, "strategy" was lost, and the type
    fell back to its registry default (``mask``), leaking the trailing
    digits ("78") and prefix ("138") of the original number in plaintext.
    """

    def test_partial_override_keeps_profile_strategy(self):
        redacted, key = redact(
            "Call 13812345678",
            lang="zh",
            profile="gdpr",
            config={"phone": {"visible_suffix": 2}},
        )

        assert "13812345678" not in redacted
        # A shallow merge drops "strategy": "remove" and falls back to the
        # phone default ("mask" with visible_prefix=3), which would leak
        # both ends of the number in plaintext. Discriminate remove-vs-mask
        # by shape, not by banning specific digits (the remove placeholder's
        # random suffix can coincidentally contain "78"/"138").
        assert "PHON-" in redacted
        assert "*" not in redacted
        assert key

    def test_type_only_in_user_config_applies_fully(self):
        """Control: a user config for a type NOT present in the profile's
        config still applies in full (nothing to merge against)."""
        redacted, key = redact(
            "身份证 110101199003077758",
            lang="zh",
            profile="gdpr",
            config={"id_number": {"strategy": "mask", "visible_suffix": 3}},
        )

        # mask with visible_suffix=3 keeps the last 3 original digits visible.
        assert "758" in redacted
        assert "110101199003077758" not in redacted
        assert key

    def test_user_supplied_strategy_still_overrides_profile(self):
        """Control: when the user DOES specify "strategy", their value wins
        over the profile's, same as before the deep-merge fix."""
        redacted, key = redact(
            "Call 13812345678",
            lang="zh",
            profile="gdpr",
            config={"phone": {"strategy": "mask"}},
        )

        # mask (not gdpr's remove) leaves a partial digit run visible.
        assert any(ch.isdigit() for ch in redacted)
        assert key

    def test_cached_profile_not_poisoned_by_prior_merge(self):
        """Control: the profile dict is module-level/shared. A merge for one
        call must not mutate it in place — a later call (even with a
        different or absent user config) must still see gdpr's original
        "remove" strategy for phone."""
        redact(
            "Call 13812345678",
            lang="zh",
            profile="gdpr",
            config={"phone": {"visible_suffix": 2}},
        )

        redacted, key = redact("Call 13812345678", lang="zh", profile="gdpr")

        assert "13812345678" not in redacted
        # Same shape-based discriminator as above, not a digit-substring ban.
        assert "PHON-" in redacted
        assert "*" not in redacted
        assert key
