"""Tests for input pollution runtime check on the pseudonym-llm profile."""

import pytest

from argus_redact import redact
from argus_redact.glue.redact_pseudonym_llm import (
    PseudonymPollutionError,
    redact_pseudonym_llm,
)


class TestPollutionCheck:
    def test_should_raise_on_polluted_input_with_realistic_profile(self):
        polluted = "second pass on 19999123456"  # contains a 199-99 fake
        with pytest.raises(PseudonymPollutionError) as exc:
            redact_pseudonym_llm(polluted)
        msg = str(exc.value).lower()
        assert "pollution" in msg or "reserved-range" in msg

    def test_should_allow_with_polluted_input_ok_flag(self):
        polluted = "second pass on 19999123456"
        result = redact_pseudonym_llm(
            polluted, salt=b"fixed-salt-for-test", _polluted_input_ok=True
        )
        assert result is not None

    def test_should_allow_with_strict_input_disabled(self):
        polluted = "second pass on 19999123456"
        result = redact_pseudonym_llm(
            polluted, salt=b"fixed-salt-for-test", strict_input=False
        )
        assert result is not None

    def test_default_profile_should_not_run_pollution_check(self):
        polluted = "phone 19999123456 here"
        text, _key = redact(polluted)
        assert isinstance(text, str)
