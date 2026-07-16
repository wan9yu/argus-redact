"""R3 — ``types``/``types_exclude`` as a bare ``str`` must fail closed.

``set("phone")`` silently becomes ``{'p', 'h', 'o', 'n', 'e'}`` — a caller who
passes a plausible bare string (rather than a one-element list) gets every
real entity type filtered out, so ``redact()`` returns the input unchanged
with a *success* return (empty key, no error). That's a silent leak: the
caller believes redaction happened. It must raise ``TypeError`` instead.
"""

import importlib.util

import pytest

from argus_redact import redact

HAS_STARLETTE = importlib.util.find_spec("starlette") is not None


class TestTypesBareStrRejected:
    def test_should_raise_typeerror_for_bare_str_types(self):
        with pytest.raises(TypeError):
            redact("张伟 13812345678", types="phone", mode="fast", salt=42)

    def test_should_raise_typeerror_for_bare_str_types_exclude(self):
        with pytest.raises(TypeError):
            redact("张伟 13812345678", types_exclude="phone", mode="fast", salt=42)

    def test_should_still_redact_with_list_types(self):
        redacted, key = redact("张伟 13812345678", types=["phone"], mode="fast", salt=42)

        assert "13812345678" not in redacted
        assert key

    def test_should_still_redact_with_tuple_types(self):
        redacted, key = redact("张伟 13812345678", types=("phone",), mode="fast", salt=42)

        assert "13812345678" not in redacted
        assert key

    def test_should_still_exclude_with_list_types_exclude(self):
        # types_exclude=["phone"] should still let other types (e.g. person) through
        # while the phone itself is skipped.
        redacted, key = redact("张伟 13812345678", types_exclude=["phone"], mode="fast", salt=42)

        assert "13812345678" in redacted


class TestEmptyTypesListRejected:
    """An empty list is a distinct caller mistake from a bare str, but the
    same fail-open family: set([]) filters out every entity, so redact()
    returns the input unchanged with a *success* return (empty key, no
    error). Must raise ValueError instead of silently leaking.
    """

    def test_should_raise_valueerror_for_empty_types_list(self):
        with pytest.raises(ValueError):
            redact("电话13800138000", types=[], mode="fast", salt=42)

    def test_should_raise_valueerror_for_empty_types_exclude_list(self):
        with pytest.raises(ValueError):
            redact("电话13800138000", types_exclude=[], mode="fast", salt=42)

    def test_should_still_redact_with_nonempty_types_list(self):
        redacted, key = redact("电话13800138000", types=["phone"], mode="fast", salt=42)

        assert "13800138000" not in redacted
        assert key

    def test_should_still_detect_all_with_types_none(self):
        redacted, key = redact("电话13800138000", types=None, mode="fast", salt=42)

        assert "13800138000" not in redacted
        assert key


class TestRedactPseudonymLlmInheritsFix:
    """redact_pseudonym_llm has no own set(types) — it must inherit the guard
    via the shared _detect() call, not need a second check."""

    def test_should_raise_typeerror_for_bare_str_types(self):
        pytest.importorskip("argus_redact.glue.redact_pseudonym_llm")
        from argus_redact.glue.redact_pseudonym_llm import redact_pseudonym_llm

        with pytest.raises(TypeError):
            redact_pseudonym_llm("张伟 13812345678", types="phone", mode="fast")


@pytest.mark.skipif(not HAS_STARLETTE, reason="starlette (serve extra) not installed")
class TestServerRedactRejectsBareStrTypes:
    @pytest.fixture
    def client(self):
        import warnings

        from starlette.testclient import TestClient

        from argus_redact import SecurityWarning
        from argus_redact.server import create_app

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SecurityWarning)
            return TestClient(create_app(allow_no_auth=True))

    def test_should_return_400_not_200_leak_for_bare_str_types(self, client):
        resp = client.post(
            "/redact",
            json={"text": "张伟 13812345678", "types": "phone", "salt": 42},
        )

        assert resp.status_code == 400
        assert "13812345678" not in resp.text

    def test_should_return_400_for_bare_str_types_exclude(self, client):
        resp = client.post(
            "/redact",
            json={"text": "张伟 13812345678", "types_exclude": "phone", "salt": 42},
        )

        assert resp.status_code == 400

    def test_should_return_400_not_200_leak_for_empty_types_list(self, client):
        resp = client.post(
            "/redact",
            json={"text": "电话13800138000", "types": [], "salt": 42},
        )

        assert resp.status_code == 400
        assert "13800138000" not in resp.text

    def test_should_return_400_for_empty_types_exclude_list(self, client):
        resp = client.post(
            "/redact",
            json={"text": "电话13800138000", "types_exclude": [], "salt": 42},
        )

        assert resp.status_code == 400
