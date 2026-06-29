"""Tests for StreamingRedactor.export_state / from_state (v0.5.5).

A long-running conversation session can be serialized to JSON, persisted
(Redis, disk), and resumed in a separate process — same originals continue
to map to the same fakes.
"""

import inspect
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

    def test_export_before_flush_preserves_in_flight_tail(self):
        # Exporting with an un-flushed in-flight buffer
        # must NOT drop the buffered tail. Text with no trailing sentence
        # boundary stays in _inc_buffer (not yet emitted); a checkpoint there
        # previously lost it, so the tail's PII vanished from the pipeline
        # instead of being redacted on the resumed flush.
        salt = bytes(range(32))
        r1 = StreamingRedactor(salt=salt)
        r1.feed("张明的电话是13912345678")  # no boundary → stays buffered
        baseline = StreamingRedactor(salt=salt)
        baseline.feed("张明的电话是13912345678")
        expected_tail = baseline.flush().downstream_text
        assert expected_tail and "13912345678" not in expected_tail  # sanity

        state = json.loads(json.dumps(r1.export_state()))
        r2 = StreamingRedactor.from_state(state, salt=salt)
        resumed_tail = r2.flush().downstream_text

        assert resumed_tail == expected_tail  # tail carried across the checkpoint
        assert "13912345678" not in resumed_tail

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
        r1.flush()  # emit so accumulated_key gets populated
        state_json = json.dumps(r1.export_state())

        r2 = StreamingRedactor.from_state(json.loads(state_json), salt=salt)
        # Re-feed same originals — should reuse the same fakes
        r2.feed("又一次13912345678。")
        r2.flush()  # emit

        # Both sessions must map the same phone to the same fake.
        r1_phone_fake = next((k for k, v in r1.aggregate_key().items() if v == "13912345678"), None)
        r2_phone_fake = next((k for k, v in r2.aggregate_key().items() if v == "13912345678"), None)
        assert r1_phone_fake is not None, "phone should be redacted post-flush in r1"
        assert r2_phone_fake is not None, "phone should be redacted post-flush in r2"
        assert r1_phone_fake == r2_phone_fake, (
            "same original should map to same fake across processes"
        )

    def test_resumed_redactor_keeps_growing_aggregate_key(self):
        salt = b"salt-xyz"
        r1 = StreamingRedactor(salt=salt)
        r1.feed("张明的手机13912345678。")
        r1.flush()  # emit to populate aggregate_key
        keys_before = set(r1.aggregate_key().keys())
        state = r1.export_state()
        r2 = StreamingRedactor.from_state(state, salt=salt)
        r2.feed("张明又说了一遍13912345678，加上李华15812345678。")
        r2.flush()  # emit
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
        # agree on the FULL aggregate key (person fakes included). The checkpoint
        # serializes the in-flight buffer (inc_buffer + ctx_len) AND the
        # accumulated key, so resuming from state is byte-for-byte identical to
        # never interrupting: both sessions detect+redact the SAME buffer content
        # at the SAME points, so even positional person fakes line up. The
        # checkpoint happens WITHOUT a flush — flushing would empty the buffer
        # (so it would no longer be testing in-flight persistence) and force a
        # separate redact pass whose positional fakes could diverge.
        salt = b"identity-test-salt"
        chunks = [
            "张明今天打了13912345678。",
            "李华的电话是15812345678。",
            "再次联系张明13912345678确认。",
        ]
        # Uninterrupted: feed all chunks, then flush once at end-of-stream.
        r_uninterrupted = StreamingRedactor(salt=salt)
        for c in chunks:
            r_uninterrupted.feed(c)
        r_uninterrupted.flush()

        # Interrupted at chunk 0: checkpoint WITHOUT flush, resume, finish.
        r_partial = StreamingRedactor(salt=salt)
        r_partial.feed(chunks[0])
        state = r_partial.export_state()
        r_resumed = StreamingRedactor.from_state(state, salt=salt)
        for c in chunks[1:]:
            r_resumed.feed(c)
        r_resumed.flush()

        assert r_uninterrupted.aggregate_key() == r_resumed.aggregate_key()


class TestExportStateCompleteness:
    """Guard: every redaction-affecting __init__ parameter is persisted by export_state.

    A future ctor param that is threaded through feed() but forgotten in
    export_state() reverts to its DEFAULT on resume, producing under-redaction
    or cross-checkpoint inconsistency.  This introspection guard fails CI the
    moment the param is added to __init__ but not serialised.
    """

    def test_all_init_params_persisted_in_export_state(self):
        """set(__init__ params) - {"self", "salt"} must be a subset of export_state keys."""
        r = StreamingRedactor(salt=b"x")
        state = r.export_state()
        exported_keys = set(state.keys())

        sig = inspect.signature(StreamingRedactor.__init__)
        init_params = set(sig.parameters.keys()) - {"self", "salt"}

        unpersisted = init_params - exported_keys
        assert not unpersisted, (
            f"StreamingRedactor.__init__ parameters not persisted in export_state(): "
            f"{sorted(unpersisted)} — a future resume will revert these to defaults, "
            f"causing under-redaction or cross-checkpoint inconsistency"
        )


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
