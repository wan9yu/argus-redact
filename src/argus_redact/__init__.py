"""argus-redact: Encrypt PII, not meaning. Locally."""

from argus_redact._types import RedactReport
from argus_redact.glue.redact import redact
from argus_redact.pure.restore import restore
from argus_redact.pure.risk import assess_risk
from argus_redact.report import (
    generate_report_json,
    generate_report_markdown,
    generate_report_pdf,
)

__version__ = "0.4.1"
__all__ = [
    "redact", "restore", "assess_risk",
    "RedactReport",
    "generate_report_json", "generate_report_markdown", "generate_report_pdf",
    "__version__",
]
