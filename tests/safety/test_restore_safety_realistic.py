"""Restore-safety check for realistic mode: reserved-range scanning of LLM output."""

from argus_redact.pure.restore import check_restore_safety


class TestRestoreSafetyRealistic:
    def test_should_warn_on_amplification(self):
        """LLM output contains more reserved-range values than the input."""
        downstream = "联系 张明 拨 19999123456"
        # LLM hallucinated extra 19999... values → suspicious
        llm_output = "张明 给了 19999123456 和 19999987654 和 19999555000"
        key = {"张明": "王建国", "19999123456": "13912345678"}
        warnings = check_restore_safety(downstream, llm_output, key)
        assert any(
            "19999" in w or "amplification" in w.lower() or "reserved-range" in w.lower()
            for w in warnings
        )

    def test_should_not_warn_on_legitimate_echo(self):
        """LLM echoing the same reserved-range value count produces no amplification warning."""
        downstream = "联系 张明 拨 19999123456"
        llm_output = "好的, 我会拨打 19999123456 联系 张明"
        key = {"张明": "王建国", "19999123456": "13912345678"}
        warnings = check_restore_safety(downstream, llm_output, key)
        assert not any("amplification" in w.lower() for w in warnings)
