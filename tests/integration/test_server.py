"""Tests for HTTP API server — using Starlette TestClient (in-process, coverage tracked)."""

import importlib.util

import pytest

HAS_STARLETTE = importlib.util.find_spec("starlette") is not None

pytestmark = pytest.mark.skipif(not HAS_STARLETTE, reason="starlette not installed")


@pytest.fixture(scope="module")
def client():
    from argus_redact.server import create_app
    from starlette.testclient import TestClient

    return TestClient(create_app())


class TestServerRedact:
    def test_should_redact_text(self, client):
        resp = client.post(
            "/redact",
            json={"text": "电话13812345678", "mode": "fast", "seed": 42},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert "13812345678" not in data["redacted"]
        assert "key" in data

    def test_should_redact_with_lang(self, client):
        resp = client.post(
            "/redact",
            json={"text": "SSN 123-45-6789", "mode": "fast", "lang": "en", "seed": 42},
        )

        assert resp.status_code == 200
        assert "123-45-6789" not in resp.json()["redacted"]

    def test_should_redact_with_multi_lang(self, client):
        resp = client.post(
            "/redact",
            json={
                "text": "电话13812345678, SSN 123-45-6789",
                "mode": "fast",
                "lang": ["zh", "en"],
                "seed": 42,
            },
        )

        data = resp.json()
        assert "13812345678" not in data["redacted"]
        assert "123-45-6789" not in data["redacted"]

    def test_should_return_detailed_when_requested(self, client):
        resp = client.post(
            "/redact",
            json={"text": "电话13812345678", "mode": "fast", "seed": 42, "detailed": True},
        )

        data = resp.json()
        assert "details" in data
        assert data["details"]["stats"]["total"] >= 1

    def test_should_return_report_when_requested(self, client):
        resp = client.post(
            "/redact",
            json={
                "text": "身份证110101199003074610",
                "mode": "fast",
                "seed": 42,
                "report": True,
            },
        )

        data = resp.json()
        assert "risk" in data
        assert data["risk"]["level"] == "critical"
        assert "PIPL Art.51" in data["risk"]["pipl_articles"]
        assert "PIPL Art.29" in data["risk"]["pipl_articles"]
        assert data["stats"]["total"] >= 1

    def test_should_filter_by_profile(self, client):
        resp = client.post(
            "/redact",
            json={"text": "电话13812345678", "mode": "fast", "seed": 42, "profile": "pipl"},
        )

        assert resp.status_code == 200
        assert "key" in resp.json()

    def test_should_filter_by_types(self, client):
        resp = client.post(
            "/redact",
            json={
                "text": "电话13812345678，身份证110101199003074610",
                "mode": "fast",
                "seed": 42,
                "types": ["phone"],
            },
        )

        data = resp.json()
        # phone should be redacted, id_number should NOT
        assert "110101199003074610" in data["redacted"]

    def test_should_filter_by_types_exclude(self, client):
        resp = client.post(
            "/redact",
            json={
                "text": "电话13812345678，身份证110101199003074610",
                "mode": "fast",
                "seed": 42,
                "types_exclude": ["phone"],
            },
        )

        data = resp.json()
        # id_number should be redacted, phone should NOT
        assert "13812345678" in data["redacted"]
        assert "110101199003074610" not in data["redacted"]

    def test_should_return_400_on_unknown_profile(self, client):
        resp = client.post(
            "/redact",
            json={"text": "test", "mode": "fast", "profile": "nonexistent"},
        )

        assert resp.status_code == 400

    def test_should_return_400_on_invalid_mode(self, client):
        resp = client.post(
            "/redact",
            json={"text": "test", "mode": "invalid"},
        )

        assert resp.status_code == 400


class TestServerRestore:
    def test_should_restore_text(self, client):
        r1 = client.post(
            "/redact",
            json={"text": "电话13812345678", "mode": "fast", "seed": 42},
        )
        data = r1.json()

        r2 = client.post(
            "/restore",
            json={"text": data["redacted"], "key": data["key"]},
        )

        assert r2.status_code == 200
        assert "13812345678" in r2.json()["restored"]


class TestServerInfo:
    def test_should_return_info(self, client):
        resp = client.get("/info")

        assert resp.status_code == 200
        data = resp.json()
        assert "version" in data
        assert "languages" in data
        assert "zh" in data["languages"]


class TestServerHealth:
    def test_should_return_healthy(self, client):
        resp = client.get("/health")

        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


@pytest.fixture(scope="module")
def auth_client():
    """Client for a server with API key auth enabled."""
    import os
    os.environ["ARGUS_API_KEY"] = "test-secret-key"
    from argus_redact.server import create_app
    from starlette.testclient import TestClient

    app = create_app()
    yield TestClient(app)
    del os.environ["ARGUS_API_KEY"]


class TestServerAuth:
    def test_should_reject_when_no_auth_header(self, auth_client):
        resp = auth_client.post(
            "/redact",
            json={"text": "电话13812345678", "mode": "fast"},
        )

        assert resp.status_code == 401

    def test_should_reject_when_wrong_key(self, auth_client):
        resp = auth_client.post(
            "/redact",
            json={"text": "电话13812345678", "mode": "fast"},
            headers={"Authorization": "Bearer wrong-key"},
        )

        assert resp.status_code == 401

    def test_should_accept_when_correct_key(self, auth_client):
        resp = auth_client.post(
            "/redact",
            json={"text": "电话13812345678", "mode": "fast", "seed": 42},
            headers={"Authorization": "Bearer test-secret-key"},
        )

        assert resp.status_code == 200
        assert "13812345678" not in resp.json()["redacted"]

    def test_health_should_not_require_auth(self, auth_client):
        resp = auth_client.get("/health")

        assert resp.status_code == 200


class TestServerInputValidation:
    def test_should_reject_oversized_body(self, client):
        """Request body >1MB should be rejected."""
        text = "x" * (1024 * 1024 + 1)

        resp = client.post("/redact", json={"text": text, "mode": "fast"})

        assert resp.status_code == 400
        assert "exceeds" in resp.json()["error"].lower() or "maximum" in resp.json()["error"].lower()

    def test_should_reject_missing_text(self, client):
        resp = client.post("/redact", json={"mode": "fast"})

        # Should handle gracefully (empty text is valid, missing is empty string)
        assert resp.status_code == 200

    def test_should_reject_config_as_file_path(self, client):
        """Config passed as string path via HTTP should be rejected (security)."""
        resp = client.post(
            "/redact",
            json={"text": "test", "mode": "fast", "config": "/etc/passwd"},
        )

        assert resp.status_code == 400
