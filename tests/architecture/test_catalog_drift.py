"""Architecture: docs/pii-types.md is auto-generated from the registry.

Drift check ensures the committed catalog stays in sync. If this test
fails, run `make catalog` and commit the regenerated file.
"""

from __future__ import annotations

from pathlib import Path

import argus_redact.specs.en  # noqa: F401  ensure registry loaded
import argus_redact.specs.shared  # noqa: F401
import argus_redact.specs.zh  # noqa: F401

REPO_ROOT = Path(__file__).resolve().parents[2]
CATALOG_PATH = REPO_ROOT / "docs" / "pii-types.md"


class TestCatalogDrift:
    def test_pii_types_md_matches_registry(self):
        """Regenerating the catalog must produce byte-identical output to the
        committed file. If this fails, run `make catalog` and commit."""
        from argus_redact.specs.gen_catalog import render_catalog

        expected = CATALOG_PATH.read_text(encoding="utf-8")
        actual = render_catalog()

        assert actual == expected, (
            "docs/pii-types.md is out of sync with the registry. "
            "Run `make catalog` and commit the result."
        )

    def test_catalog_includes_all_registered_types(self):
        from argus_redact.specs.gen_catalog import render_catalog
        from argus_redact.specs.registry import list_types

        catalog = render_catalog()
        for td in list_types():
            heading = f"### `{td.name}`"
            assert heading in catalog, f"Missing in catalog: {td.lang}/{td.name}"

    def test_catalog_marks_out_of_scope_types(self):
        from argus_redact.specs.gen_catalog import render_catalog

        catalog = render_catalog()
        # HK/TW/Macau IDs explicitly listed under "Out of scope (v0.5.x)".
        assert "## Out of scope (v0.5.x)" in catalog, (
            "Catalog missing 'Out of scope (v0.5.x)' section header"
        )
        for label in ("HKID", "台湾身份证", "澳门身份证", "台湾居留证"):
            assert label in catalog, f"Missing out-of-scope marker: {label}"
