"""argus-redact: Encrypt PII, not meaning. Locally."""

from argus_redact import layers
from argus_redact._metadata import (
    GDPR_SPECIAL_CATEGORIES,
    HIPAA_PHI_CATEGORIES,
    PIPL_REFERENCES,
)
from argus_redact._types import PseudonymLLMResult, RedactReport
from argus_redact.compose.anchor import Anchor, make_anchor
from argus_redact.compose.audit import AuditEntry, AuditLedger, collect_security_events
from argus_redact.exceptions import LayerUnavailableError, SecurityWarning, SessionStateError
from argus_redact.glue.guarded_restore import guarded_restore
from argus_redact.glue.redact import redact
from argus_redact.glue.redact_pseudonym_llm import (
    PseudonymPollutionError,
    redact_pseudonym_llm,
)
from argus_redact.glue.restore import restore
from argus_redact.pure.pseudonym import max_pseudonym_length
from argus_redact.pure.replacer import is_strategy_reversible
from argus_redact.pure.restore import RestoreGuardError, check_restore_safety, wipe_key
from argus_redact.pure.risk import assess_risk

__version__ = "0.8.3"
__all__ = [
    # ─── Layer 1 — primitive (frozen at 1.0) ───
    "redact",
    "restore",
    "assess_risk",
    "check_restore_safety",
    "wipe_key",
    "is_strategy_reversible",
    "max_pseudonym_length",
    "SecurityWarning",
    "SessionStateError",
    "LayerUnavailableError",
    "PseudonymPollutionError",
    # ─── Layer 2 — compose (best-effort; also at argus_redact.compose.*) ───
    "redact_pseudonym_llm",
    "StreamingRedactor",  # deprecated top-level alias — use argus_redact.compose.StreamingRedactor
    # ─── guard-by-default restore (v0.7.18) ───
    "make_anchor",
    "Anchor",
    "RestoreGuardError",
    "guarded_restore",
    # ─── Compliance-as-artifact (v0.7.18) ───
    "AuditLedger",
    "AuditEntry",
    "collect_security_events",
    # ─── Compliance metadata SSOT (re-exported from _metadata) ───
    "GDPR_SPECIAL_CATEGORIES",
    "HIPAA_PHI_CATEGORIES",
    "PIPL_REFERENCES",
    # ─── Type aliases ───
    "PseudonymLLMResult",
    "RedactReport",
    # ─── Internal SSOT modules ───
    "layers",
    # ─── Version ───
    "__version__",
]


# ─── PEP 562 module-level __getattr__ — deprecation warnings ───
# Top-level `argus_redact.StreamingRedactor` is the legacy import path
# (pre-v0.6.7). The canonical home is `argus_redact.compose.StreamingRedactor`.
# The symbol still resolves (lazy import) so existing callers keep working;
# removal deferred to v1.0.
_DEPRECATED_TOP_LEVEL = {"StreamingRedactor"}


def __getattr__(name):
    if name in _DEPRECATED_TOP_LEVEL:
        import warnings

        warnings.warn(
            f"argus_redact.{name} top-level import is deprecated and will be "
            f"removed in v1.0. Use `from argus_redact.compose import {name}` instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        from argus_redact.compose import StreamingRedactor

        return StreamingRedactor
    raise AttributeError(f"module 'argus_redact' has no attribute {name!r}")
