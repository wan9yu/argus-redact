"""Exception types raised by argus-redact.

This module collects shared exception classes. Currently:

- SessionStateError — raised by integration adapter classes (LangChain
  RestoreRunnable, LlamaIndex RestoreTransform) when their paired redact
  helper has not yet produced a key, or has been .reset().

Other exception types remain in their origin modules for v0.6.6:
- argus_redact.glue.redact_pseudonym_llm.PseudonymPollutionError
- argus_redact.pure.replacer.SecurityWarning

Consolidation of all exceptions into this module is deferred to v0.6.10.
"""

from __future__ import annotations


class SessionStateError(RuntimeError):
    """Raised when an integration helper's session state is missing or inconsistent.

    Typical cause: RestoreRunnable.invoke() / RestoreTransform.__call__()
    called before any RedactRunnable.invoke() / RedactTransform.__call__()
    has produced a key in the paired instance, or after .reset() cleared it.
    """
