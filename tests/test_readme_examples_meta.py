"""Guard against the fixture regex silently matching zero blocks (i.e. broken fixture)."""

from tests.test_readme_examples import _PIN_BLOCK, _REPO_ROOT

_MIN_PINNED_BLOCKS = 3  # v0.6.8: en hero + zh hero + zh unified_prefix example


def test_readme_fixture_finds_minimum_pinned_blocks():
    total = 0
    for md in [_REPO_ROOT / "README.md", _REPO_ROOT / "README.zh.md"]:
        total += sum(1 for _ in _PIN_BLOCK.finditer(md.read_text(encoding="utf-8")))
    assert total >= _MIN_PINNED_BLOCKS, (
        f"Fixture found {total} pinned blocks across READMEs, expected >= "
        f"{_MIN_PINNED_BLOCKS}. Regex broken or all pins removed?"
    )
