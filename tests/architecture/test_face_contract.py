"""Every `RedactReport` field is a recorded decision on every wire face.

The three faces build their payloads as explicit allowlists, so a field nobody
remembers to add is silently absent — that is how `residual_personal_data` reached
no face between v0.7.18 and v0.8.8, and how `coverage` and `layers_used` shipped in
v0.8.7 with zero wire consumers on day one.

`test_compose_signatures.py` already fails when `RedactReport` gains a field, but its
message reads "update REDACTREPORT_FIELDS + CHANGELOG" — you satisfy it by editing a
frozenset, never having thought about a consumer. This file is what converts that
into three decisions.

"Emit everything" would be the wrong gate, which is why the table records intent
rather than presence: the MCP face withholds `entities` because `entities[].original`
is raw plaintext and that envelope is read back into a model's context window. Writing
the reason down is precisely what stops someone helpfully "completing" the face later.

Every reason below is derived from code, not invented. Where no reason could be found
in the code, the field is EMITted rather than rationalised — a contract full of
post-hoc justifications would be worse than no contract, because it would make
accidental omissions look deliberate.
"""

from __future__ import annotations

import dataclasses
import importlib.util
import warnings

import pytest

from argus_redact._types import RedactReport
from argus_redact.exceptions import SecurityWarning

EMIT = "emit"
PARTIAL = "partial"
WITHHELD = "withheld"


@dataclasses.dataclass(frozen=True)
class Decision:
    """One face's decision about one `RedactReport` field.

    `wire` names the TOP-LEVEL envelope keys that carry the field — more than one
    when a face splits it (the CLI renders `risk` into `summary` and `compliance`
    as well as a full `risk` block), and empty exactly when the field is withheld.
    """

    state: str
    wire: tuple[str, ...] = ()
    reason: str = ""


HTTP_REDACT_REPORT = "http:/redact:report"
CLI_ASSESS = "cli:assess"
MCP_ASSESS = "mcp:assess"

_FACE_CONTRACT: dict[str, dict[str, Decision]] = {
    # The HTTP face is the restore-capable one: it hands back the key because the
    # caller needs it to call /restore. Nothing is withheld here.
    HTTP_REDACT_REPORT: {
        "redacted_text": Decision(EMIT, ("redacted",)),
        "key": Decision(EMIT, ("key",)),
        "entities": Decision(EMIT, ("entities",)),
        "stats": Decision(EMIT, ("stats",)),
        "risk": Decision(EMIT, ("risk",)),
        "residual_personal_data": Decision(EMIT, ("residual_personal_data",)),
        "security_events": Decision(EMIT, ("security_events",)),
        "coverage": Decision(EMIT, ("coverage",)),
        "layers_used": Decision(EMIT, ("layers_used",)),
    },
    CLI_ASSESS: {
        "redacted_text": Decision(
            WITHHELD,
            reason=(
                "`assess` is the read-only risk command; `argus-redact redact` "
                "(cli/main.py, the `redact` subparser) is the one that emits "
                "redacted text. Emitting it here would make the two commands "
                "differ only in their key handling."
            ),
        ),
        "key": Decision(
            WITHHELD,
            reason=(
                "`assess` emits no redacted text, so a restore key would have "
                "nothing to restore into. `argus-redact redact --key <path>` is "
                "the command that writes a key, to its own file."
            ),
        ),
        # `summary.entities_detected` is len(entities); the full list is emitted too.
        "entities": Decision(EMIT, ("entities", "summary")),
        "stats": Decision(EMIT, ("stats",)),
        # `summary` and `compliance` are the pre-existing human-facing rollup and
        # stay byte-identical for back-compat; the full projection lands under
        # `risk`, matching the other two faces.
        "risk": Decision(EMIT, ("risk", "summary", "compliance")),
        "residual_personal_data": Decision(EMIT, ("residual_personal_data",)),
        "security_events": Decision(EMIT, ("security_events",)),
        "coverage": Decision(EMIT, ("coverage",)),
        "layers_used": Decision(EMIT, ("layers_used",)),
    },
    MCP_ASSESS: {
        "redacted_text": Decision(EMIT, ("redacted",)),
        "key": Decision(
            WITHHELD,
            reason=(
                "the MCP face never returns a raw key. `redact` hands out an opaque "
                "`key_token` backed by a process-local keyring (mcp_server.py's "
                "`_create_key_token`) so the key never enters a model's context; "
                "`assess` does not mint one at all."
            ),
        ),
        "entities": Decision(
            WITHHELD,
            reason=(
                "`entities[].original` is raw plaintext and this envelope is "
                "returned into an LLM's context window. This is the one decision "
                "that predates the contract, and it is a safety decision, not an "
                "oversight — do not 'complete' this face by adding it."
            ),
        ),
        # `entities_found` is stats["total"], kept because test_mcp.py pins it.
        "stats": Decision(EMIT, ("stats", "entities_found")),
        "risk": Decision(EMIT, ("risk",)),
        "residual_personal_data": Decision(EMIT, ("residual_personal_data",)),
        "security_events": Decision(EMIT, ("security_events",)),
        "coverage": Decision(EMIT, ("coverage",)),
        "layers_used": Decision(EMIT, ("layers_used",)),
    },
}

_REPORT_FIELDS = frozenset(f.name for f in dataclasses.fields(RedactReport))


def declared_wire_keys(face: str) -> set[str]:
    """Top-level envelope keys the contract says this face emits."""
    return {key for d in _FACE_CONTRACT[face].values() for key in d.wire}


def test_every_face_decides_every_report_field():
    """THE gate. A tenth `RedactReport` field fails all three faces at once, and
    the only way to pass is to record what each face does about it."""
    for face, decisions in _FACE_CONTRACT.items():
        assert set(decisions) == set(_REPORT_FIELDS), (
            f"{face} has no decision for "
            f"{sorted(_REPORT_FIELDS - set(decisions))} and decides "
            f"{sorted(set(decisions) - _REPORT_FIELDS)}, which is not a "
            f"RedactReport field.\n"
            f"Adding a field to RedactReport means deciding, for each face, "
            f"whether it goes on the wire — and writing down why when it does not."
        )


def test_anything_less_than_emitted_carries_a_reason():
    for face, decisions in _FACE_CONTRACT.items():
        for name, d in decisions.items():
            if d.state in (WITHHELD, PARTIAL):
                assert d.reason.strip(), (
                    f"{face}.{name} is {d.state} with no reason. A reason derived "
                    f"from the code is mandatory; if none can be found, emit the "
                    f"field instead of rationalising its absence."
                )


def test_emitted_fields_name_a_wire_key_and_withheld_ones_do_not():
    for face, decisions in _FACE_CONTRACT.items():
        for name, d in decisions.items():
            if d.state in (EMIT, PARTIAL):
                assert d.wire, f"{face}.{name} is {d.state} but names no wire key"
            else:
                assert not d.wire, f"{face}.{name} is withheld but names wire keys {d.wire}"


def test_every_state_is_one_of_the_three():
    for face, decisions in _FACE_CONTRACT.items():
        for name, d in decisions.items():
            assert d.state in (EMIT, PARTIAL, WITHHELD), (
                f"{face}.{name} has unknown state {d.state!r}"
            )


def test_the_gate_is_not_vacuous():
    """Positive control. The field-set gate passes today only because the table is
    complete, which on its own is an unfalsifiable green — so prove it rejects both
    a missing decision and a decision about a field that does not exist.

    Do not 'clean up' the second half: a table that accepts a stale field name would
    let a renamed field look decided while reaching no face at all.
    """
    complete = dict(_FACE_CONTRACT[HTTP_REDACT_REPORT])

    missing = dict(complete)
    missing.pop("coverage")
    assert set(missing) != set(_REPORT_FIELDS)

    stale = dict(complete)
    stale["residual_pii"] = Decision(EMIT, ("residual_pii",))
    assert set(stale) != set(_REPORT_FIELDS)

    assert set(complete) == set(_REPORT_FIELDS)


def test_a_reasonless_withholding_is_rejected():
    """Positive control for the reason requirement."""
    bad = Decision(WITHHELD)
    assert not bad.reason.strip()


@pytest.mark.skipif(importlib.util.find_spec("starlette") is None, reason="starlette not installed")
def test_http_redact_report_envelope_matches_the_contract():
    """The serialised envelope, not field-by-field.

    Every plaintext-absence assertion in the server and MCP suites indexes ONE key
    (`data["redacted"]`), so none of them would notice a field leaking through a
    different key. A key-set comparison over the whole payload is what closes that.
    """
    from starlette.testclient import TestClient

    from argus_redact.server import create_app

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SecurityWarning)
        client = TestClient(create_app(allow_no_auth=True))
        resp = client.post(
            "/redact",
            json={"text": "请联系张伟，电话 13812345678。", "lang": "zh", "report": True},
        )
    assert resp.status_code == 200
    assert set(resp.json()) == declared_wire_keys(HTTP_REDACT_REPORT)


def test_cli_assess_envelope_matches_the_contract(tmp_path):
    import argparse
    import io
    import json
    from contextlib import redirect_stdout

    from argus_redact.cli.main import cmd_assess

    source = tmp_path / "input.txt"
    source.write_text("请联系张伟，电话 13812345678。", encoding="utf-8")

    buf = io.StringIO()
    args = argparse.Namespace(input=str(source), lang="zh", mode="fast", output=None)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SecurityWarning)
        with redirect_stdout(buf):
            cmd_assess(args)
    assert set(json.loads(buf.getvalue())) == declared_wire_keys(CLI_ASSESS)


@pytest.mark.skipif(importlib.util.find_spec("mcp") is None, reason="mcp not installed")
def test_mcp_assess_envelope_matches_the_contract():
    """Driven through the tool dispatch, not the coroutine directly.

    `call_tool` exercises the mcp 2.0 argument parsing and result wrapping that a
    direct `await assess_text(...)` skips — which is exactly the path that broke
    when this integration was migrated off the private `_tool_manager` API.
    """
    import asyncio
    import json

    from argus_redact.integrations.mcp_server import mcp

    async def _run():
        return await mcp.call_tool(
            "assess", {"text": "请联系张伟，电话 13812345678。", "lang": "zh", "mode": "fast"}
        )

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SecurityWarning)
        result = asyncio.run(_run())
    payload = json.loads(result.content[0].text)
    assert set(payload) == declared_wire_keys(MCP_ASSESS)
