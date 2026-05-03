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

    def test_catalog_omits_empty_out_of_scope_section(self):
        """v0.5.10: HK / TW / Macau / Taiwan ARC shipped, so the
        'Out of scope' section should not render when ``_OUT_OF_SCOPE``
        is empty. If a future release adds a deferred type, populate
        ``_OUT_OF_SCOPE`` and update this test to reassert the section."""
        from argus_redact.specs.gen_catalog import _OUT_OF_SCOPE, render_catalog

        catalog = render_catalog()
        if _OUT_OF_SCOPE:
            assert "## Out of scope" in catalog, (
                "Catalog must render 'Out of scope' section when _OUT_OF_SCOPE is non-empty"
            )
        else:
            assert "## Out of scope" not in catalog, (
                "Catalog must not render an empty 'Out of scope' section"
            )
        # The four ID types must now appear as fully shipped catalog entries.
        for type_name in ("hk_id", "tw_id", "macau_id", "taiwan_arc"):
            assert f"### `{type_name}`" in catalog, (
                f"v0.5.10: {type_name} should now appear as a shipped catalog entry"
            )
