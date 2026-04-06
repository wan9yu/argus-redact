"""argus-redact: Encrypt PII, not meaning. Locally."""

from argus_redact._types import RedactReport
from argus_redact.glue.redact import redact
from argus_redact.pure.restore import check_restore_safety, restore, wipe_key
from argus_redact.pure.risk import assess_risk
from argus_redact.report import (
    generate_report_json,
    generate_report_markdown,
    generate_report_pdf,
)

__version__ = "0.4.6"
__all__ = [
    "redact", "restore", "check_restore_safety", "wipe_key", "assess_risk",
    "RedactReport",
    "generate_report_json", "generate_report_markdown", "generate_report_pdf",
    "__version__",
]
