"""Tests for StreamingRedactor.export_state / from_state (v0.5.5).

A long-running conversation session can be serialized to JSON, persisted
(Redis, disk), and resumed in a separate process — same originals continue
to map to the same fakes.
"""

import json

import pytest

from argus_redact.streaming import _STATE_SCHEMA_VERSION, StreamingRedactor


class TestExportStateShape:
    def test_export_state_is_json_serializable(self):
        r = StreamingRedactor(salt=b"some-session-salt-1234")
        r.feed("张明今天打了13912345678。")
        state = r.export_state()
        # Must round-trip through JSON without TypeError
        encoded = json.dumps(state)
        assert isinstance(encoded, str) and len(encoded) > 0
        loaded = json.loads(encoded)
        assert loaded == state

    def test_export_state_includes_version_stamp(self):
        r = StreamingRedactor(salt=b"x")
        state = r.export_state()
        assert "version" in state
        assert state["version"] == _STATE_SCHEMA_VERSION

    def test_salt_passed_out_of_band_round_trips_with_edge_bytes(self):
        # v0.6.2: export_state() omits salt by default; caller passes it
        # out-of-band to from_state(state, salt=...).
        salt = bytes([0x00, 0xFF, 0x42, 0x00, 0xFE])
        r = StreamingRedactor(salt=salt)
        state = r.export_state()
        assert "salt" not in state
        r2 = StreamingRedactor.from_state(state, salt=salt)
        assert r2._salt == salt


class TestRoundTripThroughJson:
    def test_round_trip_preserves_existing_mappings(self):
        salt = b"long-session-salt-abc"
        r1 = StreamingRedactor(salt=salt)
        r1.feed("张明今天打了13912345678。")
        state_json = json.dumps(r1.export_state())

        r2 = StreamingRedactor.from_state(json.loads(state_json), salt=salt)
        # Re-feed same originals — should reuse the same fakes
        res2 = r2.feed("又一次13912345678。")
        # Phone fake from r2 must be present in r1's accumulated mapping too
        new_phone_fakes = [k for k in res2.key if "13912345678" == res2.key[k]]
        assert new_phone_fakes, "phone should still be redacted post-resume"
        assert any(f in r1.aggregate_key() for f in new_phone_fakes), (
            "same original should map to same fake across processes"
        )

    def test_resumed_redactor_keeps_growing_aggregate_key(self):
        salt = b"salt-xyz"
        r1 = StreamingRedactor(salt=salt)
        # v0.5.8: incremental default emits at sentence boundaries — feed
        # complete sentences so the aggregate key actually populates.
        r1.feed("张明的手机13912345678。")
        keys_before = set(r1.aggregate_key().keys())
        state = r1.export_state()
        r2 = StreamingRedactor.from_state(state, salt=salt)
        r2.feed("张明又说了一遍13912345678，加上李华15812345678。")
        keys_after = set(r2.aggregate_key().keys())
        assert keys_before <= keys_after, "resume must not lose mappings"
        # New entity (李华 / 158...) added in r2
        assert len(keys_after) > len(keys_before)

    def test_round_trip_preserves_reserved_names_override(self):
        # `reserved_names={"person_zh": ()}` disables canonical-name pollution
        # detection; this option must round-trip.
        salt = b"with-reserved-override"
        r1 = StreamingRedactor(
            salt=salt,
            reserved_names={"person_zh": ()},
        )
        # Feed input that contains a canonical fake name (张三) — strict_input
        # would normally reject it, but the empty override allows it through.
        r1.feed("用户张三打来电话13912345678。")
        state = r1.export_state()
        # Round-trip through JSON
        r2 = StreamingRedactor.from_state(json.loads(json.dumps(state)), salt=salt)
        # Same input must still pass the pollution check on r2
        r2.feed("张三再次来电15812345678。")  # would raise without override

    def test_resumed_session_matches_uninterrupted_session(self):
        # Two redactors with the same salt + same chunk sequence — one
        # uninterrupted, the other interrupted-then-resumed via state — must
        # agree on the final aggregate key.
        salt = b"identity-test-salt"
        chunks = [
            "张明今天打了13912345678。",
            "李华的电话是15812345678。",
            "再次联系张明13912345678确认。",
        ]
        # Uninterrupted
        r_uninterrupted = StreamingRedactor(salt=salt)
        for c in chunks:
            r_uninterrupted.feed(c)

        # Interrupted at chunk 2
        r_partial = StreamingRedactor(salt=salt)
        r_partial.feed(chunks[0])
        state = r_partial.export_state()
        r_resumed = StreamingRedactor.from_state(state, salt=salt)
        for c in chunks[1:]:
            r_resumed.feed(c)

        assert r_uninterrupted.aggregate_key() == r_resumed.aggregate_key()


class TestVersionGate:
    def test_unsupported_version_raises_value_error(self):
        r = StreamingRedactor(salt=b"x")
        state = r.export_state()
        state["version"] = 99
        with pytest.raises(ValueError) as exc:
            StreamingRedactor.from_state(state, salt=b"x")
        assert "99" in str(exc.value) or "version" in str(exc.value).lower()

    def test_missing_version_raises_value_error(self):
        with pytest.raises(ValueError):
            StreamingRedactor.from_state({"accumulated_key": {}}, salt=b"x")
