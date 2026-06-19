"""pure/ layer must not read os.environ."""

from pathlib import Path


def test_pure_hints_has_no_os_environ():
    src = Path("src/argus_redact/pure/hints.py").read_text(encoding="utf-8")
    assert "os.environ" not in src, "pure/hints.py must not read os.environ (move env reads to glue)"


def test_ablation_env_warns(monkeypatch, caplog):
    import argus_redact.glue.redact as r
    monkeypatch.setenv("ARGUS_ABLATION_HINTS", "off")
    r._warn_ablation_once.cache_clear()  # reset the one-time guard
    with caplog.at_level("WARNING"):
        r._warn_ablation_once()
    assert any("ABLATION" in rec.message.upper() for rec in caplog.records)
