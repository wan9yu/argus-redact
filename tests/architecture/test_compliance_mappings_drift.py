"""Architecture: docs/compliance-mappings.md is auto-generated from the registry.

Drift check ensures the committed transparency doc stays in sync. If this test
fails, run `make compliance-mappings` and commit the regenerated file.

This gate is a pytest test (collected by ``testpaths``), not merely a
``make compliance-mappings-check`` target: CI runs the pytest suite, so a
byte-identity assertion here is enforced on every push, whereas a make-only
check that CI never invokes would be a false green.
"""

from __future__ import annotations

from pathlib import Path

import argus_redact.specs.en  # noqa: F401  ensure registry loaded
import argus_redact.specs.shared  # noqa: F401
import argus_redact.specs.zh  # noqa: F401

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPLIANCE_MAPPINGS_PATH = REPO_ROOT / "docs" / "compliance-mappings.md"


class TestComplianceMappingsDrift:
    def test_compliance_mappings_md_matches_registry(self):
        """Regenerating the doc must produce byte-identical output to the committed
        file. If this fails, run `make compliance-mappings` and commit."""
        from argus_redact.specs.gen_compliance_mappings import render_compliance_mappings

        expected = COMPLIANCE_MAPPINGS_PATH.read_text(encoding="utf-8")
        actual = render_compliance_mappings()

        assert actual == expected, (
            "docs/compliance-mappings.md is out of sync with the registry. "
            "Run `make compliance-mappings` and commit the result."
        )

    def test_cnpj_renders_under_explicit_downgrades(self):
        """cnpj (a legal-entity registry at sensitivity 2) must render as a cited
        downgrade.

        This is a CONTENT assertion, distinct from the byte-identity gate above:
        a naive ``(sensitivity >= 3) and not member`` downgrade recompute would
        silently drop cnpj (it never trips the S>=3 gate — it downgrades via
        ``_NON_NATURAL_PERSON``). The byte-match gate would not catch that, because
        `make compliance-mappings` would regenerate a cnpj-less doc that still
        byte-matches the (also cnpj-less) generator output; and the oracle self-test
        iterates the frozen DECISION_TABLE, which is a separate code path from the
        renderer's live recompute. This anchors the rendered result directly.
        """
        from argus_redact.specs.gen_compliance_mappings import render_compliance_mappings

        rendered = render_compliance_mappings()
        marker = "## Explicit downgrades"
        assert marker in rendered, "the 'Explicit downgrades' section is missing"

        section = rendered.split(marker, 1)[1]
        # Bound the section to the next top-level heading so a cnpj mention
        # elsewhere (e.g. the per-type table) cannot satisfy this by accident.
        section = section.split("\n## ", 1)[0]
        assert "`cnpj`" in section, (
            "cnpj must render under '## Explicit downgrades' — the "
            "_NON_NATURAL_PERSON downgrade path dropped it."
        )
