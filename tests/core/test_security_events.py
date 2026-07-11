from argus_redact.pure.security_events import PROVENANCE_FAILED, security_event


def test_security_event_shape():
    e = security_event(PROVENANCE_FAILED, count=1, detail="nonce absent")
    assert e == {
        "type": "security",
        "reason_code": "provenance_failed",
        "count": 1,
        "detail": "nonce absent",
    }


def test_security_event_default_detail_none():
    assert security_event(PROVENANCE_FAILED, count=2)["detail"] is None
