"""pure/ layer must not read os.environ."""

from pathlib import Path


def test_pure_hints_has_no_os_environ():
    src = Path("src/argus_redact/pure/hints.py").read_text(encoding="utf-8")
    assert "os.environ" not in src, "pure/hints.py must not read os.environ (move env reads to glue)"
