"""Tests for model profiles — verify profile selection and defaults."""

from argus_redact.impure.model_profiles import (
    PROFILES,
    ModelProfile,
    get_model_profile,
)


class TestModelProfiles:
    def test_should_return_qwen3_profile(self):
        p = get_model_profile("qwen3:8b")
        assert p.name == "qwen3:8b"
        assert "/no_think" in p.prompt_prefix
        assert p.timeout == 60

    def test_should_return_qwen25_32b_profile(self):
        p = get_model_profile("qwen2.5:32b")
        assert p.name == "qwen2.5:32b"
        assert p.prompt_prefix == ""
        assert p.timeout == 30

    def test_should_return_default_for_unknown_model(self):
        p = get_model_profile("unknown-model:latest")
        assert p.name == "default"
        assert p.timeout == 30
        assert p.confidence == 0.7

    def test_all_profiles_should_have_required_fields(self):
        for name, profile in PROFILES.items():
            assert isinstance(profile, ModelProfile)
            assert profile.name == name
            assert profile.timeout > 0
            assert 0 < profile.confidence <= 1.0

    def test_qwen3_confidence_higher_than_qwen25_3b(self):
        q3 = get_model_profile("qwen3:8b")
        q25 = get_model_profile("qwen2.5:3b")
        assert q3.confidence > q25.confidence
