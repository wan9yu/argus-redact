"""Tests for HTTP API server — using Starlette TestClient (in-process, coverage tracked)."""

import importlib.util

import pytest

HAS_STARLETTE = importlib.util.find_spec("starlette") is not None
HAS_HTTPX = importlib.util.find_spec("httpx") is not None

pytestmark = pytest.mark.skipif(not HAS_STARLETTE, reason="starlette not installed")


@pytest.fixture(scope="module")
def client():
    # v0.6.2: server refuses to start without ARGUS_API_KEY; allow_no_auth=True
    # opts out for local/in-process testing.
    import warnings

    from starlette.testclient import TestClient

    from argus_redact import SecurityWarning
    from argus_redact.server import create_app

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SecurityWarning)
        app = create_app(allow_no_auth=True)

    with TestClient(app) as client:
        yield client


class TestServerRedact:
    def test_should_redact_text(self, client):
        resp = client.post(
            "/redact",
            json={"text": "电话13812345678", "mode": "fast", "salt": 42},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert "13812345678" not in data["redacted"]
        assert "key" in data

    def test_should_redact_with_lang(self, client):
        resp = client.post(
            "/redact",
            json={"text": "SSN 123-45-6789", "mode": "fast", "lang": "en", "salt": 42},
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
                "salt": 42,
            },
        )

        data = resp.json()
        assert "13812345678" not in data["redacted"]
        assert "123-45-6789" not in data["redacted"]

    def test_should_return_detailed_when_requested(self, client):
        resp = client.post(
            "/redact",
            json={"text": "电话13812345678", "mode": "fast", "salt": 42, "detailed": True},
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
                "salt": 42,
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
            json={"text": "电话13812345678", "mode": "fast", "salt": 42, "profile": "pipl"},
        )

        assert resp.status_code == 200
        assert "key" in resp.json()

    def test_should_filter_by_types(self, client):
        resp = client.post(
            "/redact",
            json={
                "text": "电话13812345678，身份证110101199003074610",
                "mode": "fast",
                "salt": 42,
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
                "salt": 42,
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

    def test_report_and_detailed_agree_on_security_events(self, client):
        """`report=True` used to drop the events `detailed=True` carried.

        The fixture must actually produce an event. An earlier version of this
        test used a plain phone-number fixture that produces none, so it compared
        two empty lists and passed even when the endpoint hardcoded `[]`.
        """
        body = {
            "text": "卡号4111111111111111",
            "lang": "zh",
            "config": {"bank_card": {"strategy": "keep"}},
        }
        report = client.post("/redact", json={**body, "report": True}).json()
        detailed = client.post("/redact", json={**body, "detailed": True}).json()
        assert report["security_events"], (
            "fixture must produce at least one security event, or this test "
            "compares two empty lists and cannot fail"
        )
        assert report["security_events"] == detailed["details"].get("security_events", [])

    def test_report_carries_the_compliance_risk_fields(self, client):
        """`gdpr_special_category` and `hipaa_categories` shipped in v0.5.9 and
        reached no wire face until v0.8.8."""
        resp = client.post(
            "/redact",
            json={"text": "请联系张伟，电话 13812345678。", "lang": "zh", "report": True},
        )
        risk = resp.json()["risk"]
        assert "gdpr_special_category" in risk
        assert "hipaa_categories" in risk


class TestServerRestore:
    def test_should_restore_text(self, client):
        r1 = client.post(
            "/redact",
            json={"text": "电话13812345678", "mode": "fast", "salt": 42},
        )
        data = r1.json()

        r2 = client.post(
            "/restore",
            # v0.8.0: /restore guards by default; this is a plain round-trip
            # (not an anchor test), so opt into the legacy path explicitly.
            json={"text": data["redacted"], "key": data["key"], "guard": False},
        )

        assert r2.status_code == 200
        assert "13812345678" in r2.json()["restored"]

    def test_should_restore_alternate_transliteration_via_aliases_field(self, client):
        r = client.post(
            "/restore",
            json={
                "text": "Wang Wu phoned",
                "key": {"王五": "王建国"},
                "aliases": {"王五": ["Wang Wu"]},
                "guard": False,
            },
        )

        assert r.status_code == 200
        assert r.json()["restored"] == "王建国 phoned"

    def test_should_reject_non_object_aliases(self, client):
        r = client.post(
            "/restore",
            json={"text": "x", "key": {}, "aliases": ["not", "an", "object"], "guard": False},
        )

        assert r.status_code == 400

    def test_should_strip_display_marker_field(self, client):
        r = client.post(
            "/restore",
            json={
                "text": "P-037ⓥ说了话",
                "key": {"P-037": "王五"},
                "display_marker": "ⓥ",
                "guard": False,
            },
        )

        assert r.status_code == 200
        assert r.json()["restored"] == "王五说了话"


class TestServerInfo:
    def test_should_return_info(self, client):
        resp = client.get("/info")

        assert resp.status_code == 200
        data = resp.json()
        assert "version" in data
        assert "languages" in data
        # Expected set is COMPUTED from the shipped-pack SSOT, not a frozen
        # literal — so adding a 9th pack must surface here (and on /info) or
        # this assertion fails, instead of silently passing at 8.
        from argus_redact.glue.redact import _LANG_PATTERNS

        assert set(data["languages"].keys()) == set(_LANG_PATTERNS.keys())
        for code, info in data["languages"].items():
            assert info["patterns"] > 0, f"{code}: expected non-zero patterns"
            assert isinstance(info["ner"], bool), f"{code}: ner field should be a bool"


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
    from starlette.testclient import TestClient

    from argus_redact.server import create_app

    app = create_app()
    with TestClient(app) as client:
        yield client
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
            json={"text": "电话13812345678", "mode": "fast", "salt": 42},
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
        assert (
            "exceeds" in resp.json()["error"].lower() or "maximum" in resp.json()["error"].lower()
        )

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

    def test_should_reject_key_as_file_path_on_redact(self, client):
        """Key passed as string path to /redact should be rejected (security)."""
        resp = client.post(
            "/redact",
            json={"text": "test", "mode": "fast", "key": "/tmp/secret.json"},
        )

        assert resp.status_code == 400
        assert "key" in resp.json()["error"].lower()

    def test_should_reject_key_as_list_on_redact(self, client):
        """Key passed as a JSON list to /redact should be rejected (non-dict)."""
        resp = client.post(
            "/redact",
            json={"text": "test", "mode": "fast", "key": ["not", "a", "dict"]},
        )

        assert resp.status_code == 400
        assert "key" in resp.json()["error"].lower()

    def test_should_reject_key_as_file_path_on_restore(self, client):
        """Key passed as string path to /restore should be rejected (security)."""
        resp = client.post(
            "/restore",
            json={"text": "test", "key": "/tmp/secret.json"},
        )

        assert resp.status_code == 400
        assert "key" in resp.json()["error"].lower()

    def test_should_reject_key_as_list_on_restore(self, client):
        """Key passed as a JSON list to /restore should be rejected (non-dict)."""
        resp = client.post(
            "/restore",
            json={"text": "test", "key": ["not", "a", "dict"]},
        )

        assert resp.status_code == 400
        assert "key" in resp.json()["error"].lower()


@pytest.mark.skipif(not HAS_HTTPX, reason="httpx not installed")
class TestServerConcurrency:
    """Handlers are ``async def`` but used to call the (blocking) Rust core
    inline (``result = redact(...)``). The bindings already release the GIL
    while the core scans, but that only pays off if something else can run on
    the event-loop thread while the scan is in flight — called inline, the
    scan monopolized the single event-loop thread and stalled every OTHER
    concurrent request, including a plain ``GET /health``, behind one
    expensive ``/redact`` call. ``run_in_threadpool`` offloads the call so the
    GIL-released scan and the loop's ability to serve others actually compose.
    """

    @pytest.mark.asyncio
    async def test_slow_redact_does_not_block_a_concurrent_health_check(self, monkeypatch):
        import asyncio
        import time

        import httpx
        from httpx import ASGITransport

        from argus_redact import server as server_module

        slow_seconds = 1.0

        def _slow_redact(*args, **kwargs):
            # Stands in for the GIL-detached blocking scan: a plain
            # synchronous sleep occupies the calling thread exactly like a
            # long Rust-core call would, without the cost of a real scan.
            time.sleep(slow_seconds)
            return "redacted", {}

        monkeypatch.setattr(server_module, "redact", _slow_redact)
        # Independent of whatever ARGUS_API_KEY state another test in this
        # module left behind (TestServerAuth's module-scoped fixture sets it
        # for the whole file) — this test wants the unauthenticated app.
        monkeypatch.delenv("ARGUS_API_KEY", raising=False)

        app = server_module.create_app(allow_no_auth=True)
        transport = ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            redact_task = asyncio.create_task(ac.post("/redact", json={"text": "x"}))
            # Give the slow request a head start so a non-offloaded (inline)
            # handler is already occupying the event loop by the time the
            # health check is fired.
            await asyncio.sleep(0.05)
            health_resp = await ac.get("/health")
            # Timing-robust discriminator: capture whether the slow /redact call
            # is STILL in flight at the instant /health returned. Inline, the
            # blocking call owns the single event-loop thread until it returns,
            # so /health cannot complete before redact_task — it would already
            # be `.done()` here. Offloaded to a threadpool, the loop stays free
            # and /health returns first. This is an ordering fact, immune to
            # absolute wall-clock contention (no `elapsed < X` threshold).
            redact_still_in_flight = not redact_task.done()
            redact_resp = await redact_task

        assert health_resp.status_code == 200
        assert health_resp.json() == {"status": "ok"}
        assert redact_resp.status_code == 200
        assert redact_resp.json() == {"redacted": "redacted", "key": {}}
        assert redact_still_in_flight, (
            "/health only returned after the /redact call had finished — the "
            "event loop was blocked by an inline core call instead of offloading "
            "it to a threadpool thread"
        )

    @pytest.mark.asyncio
    async def test_slow_restore_does_not_block_a_concurrent_health_check(self, monkeypatch):
        # Symmetric to the /redact case: handle_restore offloads its core call
        # too, so an expensive /restore must not stall a concurrent /health.
        import asyncio
        import time

        import httpx
        from httpx import ASGITransport

        from argus_redact import server as server_module

        slow_seconds = 1.0

        def _slow_restore(*args, **kwargs):
            time.sleep(slow_seconds)
            return "restored", {}

        monkeypatch.setattr(server_module, "restore", _slow_restore)
        monkeypatch.delenv("ARGUS_API_KEY", raising=False)

        app = server_module.create_app(allow_no_auth=True)
        transport = ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            # guard=False with no anchor is the legacy round-trip path; it still
            # reaches the offloaded restore() call.
            restore_task = asyncio.create_task(
                ac.post("/restore", json={"text": "x", "key": {}, "guard": False})
            )
            await asyncio.sleep(0.05)
            health_resp = await ac.get("/health")
            restore_still_in_flight = not restore_task.done()
            restore_resp = await restore_task

        assert health_resp.status_code == 200
        assert health_resp.json() == {"status": "ok"}
        assert restore_resp.status_code == 200
        assert restore_resp.json()["restored"] == "restored"
        assert restore_still_in_flight, (
            "/health only returned after the /restore call had finished — the "
            "event loop was blocked by an inline core call instead of offloading "
            "it to a threadpool thread"
        )
