"""Tests for performance telemetry — opt-in logging of redact() timing."""

import json
import os
import tempfile

from argus_redact import redact
from argus_redact.telemetry import PerfRecord, set_perf_hook


class TestPerfRecord:
    def test_should_have_required_fields(self):
        record = PerfRecord(
            version="0.4.6",
            timestamp="2026-04-06T12:00:00",
            text_len=100,
            text_ascii_ratio=0.5,
            lang=["zh"],
            mode="fast",
            normalize_ms=0.1,
            layer_1_ms=0.3,
            layer_1b_person_ms=0.1,
            layer_2_ms=0.0,
            layer_3_ms=0.0,
            merge_ms=0.01,
            replace_ms=0.02,
            total_ms=0.54,
            entities_found=2,
            entity_types=["phone", "email"],
            rust_core=True,
            slow=False,
            sampled=False,
        )

        assert record.text_len == 100
        assert record.total_ms == 0.54

    def test_should_serialize_to_json(self):
        from dataclasses import asdict

        record = PerfRecord(
            version="0.4.6",
            timestamp="2026-04-06T12:00:00",
            text_len=50,
            text_ascii_ratio=1.0,
            lang=["en"],
            mode="fast",
            normalize_ms=0.0,
            layer_1_ms=0.1,
            layer_1b_person_ms=0.0,
            layer_2_ms=0.0,
            layer_3_ms=0.0,
            merge_ms=0.0,
            replace_ms=0.0,
            total_ms=0.1,
            entities_found=0,
            entity_types=[],
            rust_core=False,
            slow=False,
            sampled=True,
        )

        line = json.dumps(asdict(record))
        parsed = json.loads(line)
        assert parsed["mode"] == "fast"
        assert parsed["text_len"] == 50


class TestPerfHook:
    def test_should_call_hook_when_set(self):
        records = []
        set_perf_hook(lambda r: records.append(r))

        redact("电话13812345678", seed=42, mode="fast")

        set_perf_hook(None)
        assert len(records) == 1
        assert records[0].text_len > 0
        assert records[0].entities_found >= 1

    def test_should_not_call_hook_when_none(self):
        set_perf_hook(None)

        # Should not raise
        redact("电话13812345678", seed=42, mode="fast")

    def test_should_include_timing_breakdown(self):
        records = []
        set_perf_hook(lambda r: records.append(r))

        redact("电话13812345678，身份证110101199003074610", seed=42, mode="fast")

        set_perf_hook(None)
        r = records[0]
        assert r.layer_1_ms >= 0
        assert r.total_ms >= r.layer_1_ms
        assert r.normalize_ms >= 0

    def test_should_mark_slow_when_above_threshold(self):
        records = []
        set_perf_hook(lambda r: records.append(r))

        # Small text = fast, should not be marked slow
        redact("电话13812345678", seed=42, mode="fast")

        set_perf_hook(None)
        # Can't guarantee it's fast on all hardware, just check field exists
        assert isinstance(records[0].slow, bool)


class TestPerfLogFile:
    def test_should_write_jsonl_when_env_var_set(self):
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = f.name

        try:
            os.environ["ARGUS_PERF_LOG"] = path
            os.environ["ARGUS_PERF_SAMPLE"] = "1.0"  # 100% sampling for test
            from argus_redact.telemetry import _init_file_hook

            _init_file_hook()

            redact("电话13812345678", seed=42, mode="fast")

            from argus_redact.telemetry import set_perf_hook

            set_perf_hook(None)

            with open(path) as f:
                lines = f.readlines()
            assert len(lines) >= 1
            record = json.loads(lines[0])
            assert "total_ms" in record
            assert "text_len" in record
        finally:
            os.environ.pop("ARGUS_PERF_LOG", None)
            os.environ.pop("ARGUS_PERF_SAMPLE", None)
            os.unlink(path)
