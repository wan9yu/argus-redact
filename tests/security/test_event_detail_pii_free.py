"""No security event's `detail` may carry a value derived from the input.

Both producers fixed here are restore-side: `out_of_scope_pseudonym` and
`injection_suspected`. See "injection_suspected and out_of_scope_pseudonym
report counts, not specifics" in docs/known-issues.md for what each used to
leak and why.

`check_restore_safety` deliberately still returns the full strings — a caller who
invokes it directly already holds the key and every original, so it discloses nothing
to them. The leak was routing those strings into `security_events`: `out_of_scope_pseudonym`
onto both the HTTP and MCP faces, `injection_suspected` onto the MCP face and the
library integrations (the HTTP face never calls `guarded_restore`, so H never runs there).
"""

from __future__ import annotations

from argus_redact import make_anchor, redact
from argus_redact.glue.guarded_restore import guarded_restore
from argus_redact.pure.restore import _event_from_core
from argus_redact.pure.security_events import INJECTION_SUSPECTED, OUT_OF_SCOPE_PSEUDONYM


def test_out_of_scope_detail_names_a_count_not_the_tokens():
    event = _event_from_core(
        {
            "kind": OUT_OF_SCOPE_PSEUDONYM,
            "count": 2,
            "tokens": ["138****5678", "z*******@example.com"],
        }
    )
    detail = event["detail"]
    assert "138****5678" not in detail
    assert "z*******@example.com" not in detail
    assert "example.com" not in detail
    assert "2" in detail
    assert event["reason_code"] == OUT_OF_SCOPE_PSEUDONYM
    assert event["count"] == 2


def test_injection_detail_names_a_count_not_the_llm_excerpt():
    """Both leak channels at once, verified against v0.8.7.

    `redact()` with the default config gives `phone` the `mask` strategy, so the key's
    pseudonym is `138****5678` — the original's prefix and last four. The reply carries
    an email but deliberately NO exfil verb (`发送` / `share` / ...): the danger regex is
    a leftmost alternation over a ±100-character window, so a verb nearer the pseudonym
    would match instead and the email would never appear in the detail, making the
    assertion below pass for the wrong reason.

    Pre-fix this produces, verbatim:
        Pseudonym '138****5678' near danger pattern
        'ceo.private.mailbox@acme-internal.example' — possible exfiltration
    """
    redacted, key = redact("请联系张伟，电话 13812345678。", lang="zh")
    assert "138****5678" in key, "fixture assumes the default mask strategy for phone"
    reply = f"{redacted} 备份地址 ceo.private.mailbox@acme-internal.example 。"
    _, details = guarded_restore(
        reply,
        key,
        redacted=redacted,
        anchor=make_anchor(key),
        guard=True,
        detailed=True,
        warn=False,
    )
    events = [e for e in details["security_events"] if e["reason_code"] == INJECTION_SUSPECTED]
    assert events, "expected the H heuristic to fire on an exfil-shaped reply"
    detail = events[0]["detail"]
    assert "ceo.private.mailbox@acme-internal.example" not in detail
    assert "acme-internal" not in detail
    for code in key:
        assert code not in detail
