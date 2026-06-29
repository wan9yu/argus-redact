"""PRvL+ multi-model runner — Privacy / Reversibility / Utility through cloud LLMs.

argus-redact's «Reversible by Design» methodology, made repo-reproducible: send
argus-redacted text through frontier cloud LLMs (via OpenRouter) and measure, per
(model × redaction-profile × case), the three PRvL+ promises:

  Privacy       — the ORIGINAL PII must NOT appear in the model output (leak rate).
  Reversibility — we can locally ``restore()`` the original PII from the output.
  Utility       — the model still completes the task despite redaction.

This repo DEFINES the PRvL+ metrics; the paper follows the repo. The exact,
canonical metric definitions are implemented inline in ``_score_row`` below — read
those, not a separate prose spec.

Models run via the ``openrouter`` provider (env ``OPENROUTER_API_KEY``). Each row
records BOTH the paper/friendly label and the exact OpenRouter model id plus the
call date, because the paper requires exact model-version strings + dates.

NOTE on the "GPT-5" label: it maps to the OpenRouter id ``openai/gpt-5.5``. The
original GPT-5 id is retired on OpenRouter, so gpt-5.5 is the current closest
GPT-5-family endpoint; the paper-facing label stays "GPT-5".

Run (needs OPENROUTER_API_KEY in env, never committed):
    python -m tests.benchmark.prvl_multi_eval                         # 4 models × 3 profiles
    python -m tests.benchmark.prvl_multi_eval --models GPT-5 --profiles realistic --limit 1
    python -m tests.benchmark.prvl_multi_eval --judge                 # add LLM-judge utility
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

from argus_redact import redact, redact_pseudonym_llm, restore

# Reuse the re-id eval's LLM client wiring (single source for PROVIDERS + the
# openrouter endpoint). ``call_llm`` is defined locally below — see its docstring
# for why the re-id eval's 20-token variant is NOT reused for this benchmark.
from tests.benchmark.reid_eval import PROVIDERS

RESULTS_DIR = Path(__file__).resolve().parent / "results"
OPENROUTER_URL, _OPENROUTER_DEFAULT_MODEL, OPENROUTER_ENV_KEY = PROVIDERS["openrouter"]

# Fixed 32-byte high-entropy salt so runs are reproducible and no low-entropy
# SecurityWarning fires (int / <16-byte salts are grid-searchable). Same idea as
# bench_l1's _BENCH_SALT.
SALT = b"prvl-multi-eval-fixed-salt!!!!!!"

# Friendly (paper / baker) label → exact OpenRouter model id. The label is the
# paper-facing name kept stable across endpoint churn; the id is what call_llm gets.
MODELS: list[tuple[str, str]] = [
    ("GPT-5",           "openai/gpt-5.5"),
    ("Claude-Opus-4.5", "anthropic/claude-opus-4.5"),
    ("Gemini-2.5-Pro",  "google/gemini-2.5-pro"),
    ("GLM-4.5",         "z-ai/glm-4.5"),
]
_MODEL_BY_LABEL = dict(MODELS)

PROFILES = ["default", "pseudonym", "realistic"]
JUDGE_MODEL_DEFAULT = "openai/gpt-5.5"

# Refusal markers (case-insensitive for ASCII; CJK markers match as-is). An output
# containing any of these is NOT counted as a usable answer.
_REFUSAL_MARKERS = (
    "i cannot", "i can't", "i'm sorry", "i am sorry", "unable to",
    "无法", "抱歉", "对不起",
)

# Cases that ask for a person's HEALTH condition / medical advice: a frontier
# model declining these on privacy grounds is CORRECT behavior, not a redaction
# failure — tagged so the aggregate separates "expected safety refusal" from a
# task argus actually broke. (health-extract qa_en + health-advice advice_zh.)
_EXPECTED_REFUSAL_CASES = frozenset({"qa_en", "advice_zh"})


def call_llm(base_url: str, model: str, api_key: str, system: str, user: str,
             timeout: float = 60.0) -> str:
    """Single OpenAI-compatible chat completion → reply text.

    Mirrors ``reid_eval.call_llm``'s signature so callers (and the offline test's
    monkeypatch point ``prvl_multi_eval.call_llm``) line up — but lifts the
    re-id eval's hard ``max_tokens=20`` cap. The re-id eval only parses a single
    candidate-id digit, so 20 tokens is fine there; this benchmark measures whether
    the model COMPLETES a task (summary / translation / advice), so a 20-token
    truncation would corrupt the Utility (and Reversibility) signal. We therefore
    request a full answer at temperature 0 for determinism.
    """
    import httpx

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": user})
    resp = httpx.post(
        base_url, headers=headers,
        json={"model": model, "messages": messages,
              "temperature": 0, "max_tokens": 1024},
        timeout=timeout,
    )
    resp.raise_for_status()
    # Some models / finish_reasons return null content (length cap, content filter,
    # or reasoning-only replies). Treat null as an empty answer — never return None.
    return resp.json()["choices"][0]["message"].get("content") or ""


def _default_cases() -> list[dict]:
    """Union (dedup by id) of the two in-repo PRvL case sets, normalized.

    Canonical sources: ``test_prvl.LLM_PROMPTS`` (key ``prompt_template``) and
    ``test_prvl_multi_llm.TEST_CASES`` (key ``prompt``). Both are reused as SSOT so
    the case corpus can't drift from the existing benchmarks. Fields normalized to:
    id, text, prompt, lang, pii, task_type. First occurrence of an id wins.
    """
    from tests.benchmark.test_prvl import LLM_PROMPTS
    from tests.benchmark.test_prvl_multi_llm import TEST_CASES

    merged: dict[str, dict] = {}
    for src in (LLM_PROMPTS, TEST_CASES):
        for c in src:
            cid = c["id"]
            if cid in merged:
                continue
            merged[cid] = {
                "id": cid,
                "text": c["text"],
                "prompt": c.get("prompt") or c["prompt_template"],
                "lang": c["lang"],
                "pii": list(c.get("pii", [])),
                "task_type": c.get("task_type", "unknown"),
                "expected_safety_refusal": cid in _EXPECTED_REFUSAL_CASES,
            }
    return list(merged.values())


# ── Redaction profiles (the 3 strategies we compare) ──
# Each returns (downstream_text, key, aliases). ``downstream_text`` is what the
# model sees; ``key`` (+ aliases) is what restore() uses locally.

def redact_profile(profile: str, text: str, lang: str | list[str]):
    """Apply one redaction profile. Documented exact calls per profile:

    - ``default``   : ``redact(text, mode="fast", lang=lang, salt=SALT)`` — each
      type's default strategy (mix of mask/remove/pseudonym labels, e.g.
      ``P-49507`` / ``138****5678`` / ``MED-34161``).
    - ``pseudonym`` : opaque uniform ``P-NNNNN`` codes. There is no single kwarg
      that forces every detected type to one opaque code, because mask-default
      types (phone/email) ignore ``unified_prefix`` (it only collapses
      reversible-strategy types). So we (1) run one detection pass
      (``redact(..., detailed=True)``) to enumerate the detected types, (2) force
      ``strategy="pseudonym"`` on each via ``config``, and (3) collapse them all to
      a single opaque ``P-`` prefix via ``unified_prefix="P"``. Result: every PII
      span becomes ``P-NNNNN`` with no type hint and no partial leak.
    - ``realistic`` : ``redact_pseudonym_llm(text, salt=SALT, lang=lang,
      strict_input=False)`` — realistic reserved-range fake substitution; uses
      ``.downstream_text`` + ``.key`` + ``.aliases``.
    """
    if profile == "default":
        redacted, key = redact(text, mode="fast", lang=lang, salt=SALT)
        return redacted, key, None
    if profile == "pseudonym":
        _r, _k, det = redact(text, mode="fast", lang=lang, salt=SALT, detailed=True)
        types = {e["type"] for e in det["entities"]}
        cfg = {t: {"strategy": "pseudonym"} for t in types}
        redacted, key = redact(
            text, mode="fast", lang=lang, salt=SALT, config=cfg, unified_prefix="P"
        )
        return redacted, key, None
    if profile == "realistic":
        res = redact_pseudonym_llm(text, salt=SALT, lang=lang, strict_input=False)
        return res.downstream_text, res.key, res.aliases
    raise ValueError(f"unknown profile {profile!r}; choose from {PROFILES}")


# ── PRvL+ metrics (OUR canonical definitions) ──

def _classify_output(output: str) -> str:
    """Classify a model reply: ``'refusal'`` | ``'empty'`` | ``'completed'``.

    Separating refusal from empty matters for PRvL+ utility: a safety refusal on a
    health-privacy task is correct model behavior, NOT a redaction failure, so it
    must not be conflated with a null/empty (API / length-cap) miss or with a
    genuine completion. Refusal is checked first (a refusal can be >10 chars).
    """
    stripped = output.strip()
    if any(m in stripped.lower() for m in _REFUSAL_MARKERS):
        return "refusal"
    if len(stripped) < 10:
        return "empty"
    return "completed"


def _utility_basic(output: str) -> float:
    """1.0 iff the reply COMPLETED the task (neither refusal nor empty)."""
    return 1.0 if _classify_output(output) == "completed" else 0.0


def _privacy(pii: list[str], output: str) -> dict:
    return {"leaked": [p for p in pii if p in output], "total": len(pii)}


def _leak_rate(privacy: dict) -> float:
    return len(privacy["leaked"]) / privacy["total"] if privacy["total"] else 0.0


def _reversibility(pii: list[str], output: str, key: dict,
                   aliases: dict | None) -> float:
    """Fraction of original PII recoverable by restoring the model output.

    We ``restore(output, key)`` (with realistic-strategy aliases when present) and
    count how many original PII values reappear — i.e. the redaction codes/fakes
    survived the LLM round-trip well enough to map back. 0 when there is no PII.
    """
    if not pii:
        return 0.0
    restored = restore(output, key, aliases=aliases) if aliases else restore(output, key)
    return sum(1 for p in pii if p in restored) / len(pii)


def _judge_utility(case: dict, output: str, *, profile: str, base_url: str,
                   judge_model: str, api_key: str, timeout: float) -> float | None:
    """Optional LLM-judge utility in [0,1]; None on parse failure.

    Profile-aware: under the ``realistic`` profile the input was redacted with
    realistic FAKE substitutions, so the judge must grade task completion ONLY and
    not penalize the output for relying on values that look like real PII — that is
    the point of the profile, and reversibility is recovered locally via the key.
    Without this note the judge marks realistic output down as "unverifiable real
    PII", confounding utility with a trust judgment.
    """
    task = case["prompt"].replace("{text}", "[redacted input omitted]")
    realistic_note = (
        " NOTE: the input was redacted with REALISTIC FAKE substitutions (fake but "
        "real-looking names/numbers); grade ONLY whether the task is accomplished, "
        "and do NOT penalize the output for containing or relying on substituted "
        "values that look like real PII."
        if profile == "realistic"
        else ""
    )
    prompt = (
        "You are grading whether an AI assistant completed a task. "
        f"TASK: {task}. The assistant was given a privacy-redacted version of the "
        f"input.{realistic_note} ASSISTANT OUTPUT: {output}. Does the output "
        "correctly accomplish the task despite redaction? Reply with ONLY a number "
        "0.0-1.0."
    )
    try:
        reply = call_llm(base_url, judge_model, api_key, "", prompt, timeout)
    except Exception as e:  # noqa: BLE001 — a failed judge call must not abort the run
        print(f"[judge-error] {case['id']}: {e}", file=sys.stderr)
        return None
    m = re.search(r"\d+(?:\.\d+)?", reply or "")
    if not m:
        return None
    try:
        return max(0.0, min(1.0, float(m.group())))
    except ValueError:
        return None


def _score_row(case: dict, profile: str, label: str, model_id: str, *,
               base_url: str, api_key: str, timeout: float, judge: bool,
               judge_model: str) -> dict:
    """Redact → query → score one (model, profile, case). Never raises on an API
    error: records the row with output="" + error=<msg> so one failure can't abort
    the whole matrix."""
    lang = case["lang"]
    downstream, key, aliases = redact_profile(profile, case["text"], lang)

    row: dict = {
        "case_id": case["id"], "profile": profile, "model": label,
        "model_id": model_id, "redacted": downstream, "task_type": case["task_type"],
    }
    try:
        output = call_llm(base_url, model_id, api_key, "",
                          case["prompt"].format(text=downstream), timeout)
    except Exception as e:  # noqa: BLE001 — one failed call must not abort the run
        print(f"[api-error] {label}/{profile}/{case['id']}: {e}", file=sys.stderr)
        privacy = _privacy(case["pii"], "")
        row.update(output="", error=str(e), privacy=privacy,
                   reversibility=0.0, utility=0.0, completion="empty",
                   is_refusal=False,
                   expected_safety_refusal=case.get("expected_safety_refusal", False),
                   utility_judge=None)
        return row

    output = output or ""  # null content (finish_reason=length/filter) → empty answer
    privacy = _privacy(case["pii"], output)
    completion = _classify_output(output)
    row.update(
        output=output,
        privacy=privacy,
        reversibility=_reversibility(case["pii"], output, key, aliases),
        utility=1.0 if completion == "completed" else 0.0,
        completion=completion,                       # completed | refusal | empty
        is_refusal=(completion == "refusal"),
        expected_safety_refusal=case.get("expected_safety_refusal", False),
        utility_judge=(
            _judge_utility(case, output, profile=profile, base_url=base_url,
                           judge_model=judge_model, api_key=api_key, timeout=timeout)
            if judge else None
        ),
    )
    return row


def _aggregate(rows: list[dict]) -> dict:
    """Mean metrics per ``"<model> / <profile>"`` group."""
    groups: dict[str, list[dict]] = {}
    for r in rows:
        groups.setdefault(f"{r['model']} / {r['profile']}", []).append(r)

    out: dict[str, dict] = {}
    for k, grp in groups.items():
        n = len(grp)
        judged = [r["utility_judge"] for r in grp if r["utility_judge"] is not None]
        out[k] = {
            "leak_rate": sum(_leak_rate(r["privacy"]) for r in grp) / n,
            "reversibility": sum(r["reversibility"] for r in grp) / n,
            "utility_completed": sum(r["utility"] for r in grp) / n,
            "refusal_rate": sum(1 for r in grp if r.get("is_refusal")) / n,
            "utility_judge": (sum(judged) / len(judged)) if judged else None,
            "n": n,
        }
    return out


def run(*, models: list[str] | None = None, profiles: list[str] | None = None,
        limit: int | None = None, cases: list[dict] | None = None,
        judge: bool = False, judge_model: str = JUDGE_MODEL_DEFAULT,
        timeout: float = 60.0, out: str | Path | None = None,
        api_key: str | None = None, write: bool = True) -> dict:
    """Run the PRvL+ matrix and return the snapshot dict (also writing it when
    ``write`` and an ``out`` path resolve). Importable so the offline test can call
    it directly with ``call_llm`` monkeypatched."""
    labels = models or [m[0] for m in MODELS]
    profs = profiles or list(PROFILES)
    for lbl in labels:
        if lbl not in _MODEL_BY_LABEL:
            raise SystemExit(f"unknown model label {lbl!r}; choose from {[m[0] for m in MODELS]}")
    for p in profs:
        if p not in PROFILES:
            raise SystemExit(f"unknown profile {p!r}; choose from {PROFILES}")

    all_cases = cases if cases is not None else _default_cases()
    if limit:
        all_cases = all_cases[:limit]

    # No raising key resolution: the offline test stubs call_llm and CI may have no
    # key. A real run with an empty key simply records per-row api-errors.
    key = api_key if api_key is not None else os.environ.get(OPENROUTER_ENV_KEY, "")

    rows: list[dict] = []
    for lbl in labels:
        model_id = _MODEL_BY_LABEL[lbl]
        for profile in profs:
            for case in all_cases:
                rows.append(_score_row(
                    case, profile, lbl, model_id,
                    base_url=OPENROUTER_URL, api_key=key, timeout=timeout,
                    judge=judge, judge_model=judge_model,
                ))

    snap = {
        "benchmark": "prvl_multi",
        "package_version": _pkg_version(),
        "date": datetime.now().isoformat(),
        "provider": "openrouter",
        "models": [{"label": lbl, "openrouter_id": _MODEL_BY_LABEL[lbl]} for lbl in labels],
        "profiles": profs,
        "cases": len(all_cases),
        "judge": judge,
        "rows": rows,
        "aggregate": _aggregate(rows),
    }

    if write:
        out_path = Path(out) if out else RESULTS_DIR / f"prvl_multi_{_pkg_version()}.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(snap, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[snapshot] wrote {out_path} ({len(rows)} row(s))")
    return snap


def _pkg_version() -> str:
    try:
        import argus_redact
        return getattr(argus_redact, "__version__", "dev")
    except Exception:  # noqa: BLE001
        return "dev"


def _print_table(snap: dict) -> None:
    print(f"\n[provider] {snap['provider']}  (cases={snap['cases']}, judge={snap['judge']})")
    print(
        f"{'model / profile':<30}{'leak':<9}{'revers':<9}"
        f"{'compl':<9}{'refuse':<9}{'judge':<8}{'n'}"
    )
    print("-" * 82)
    for k, a in snap["aggregate"].items():
        judge = "n/a" if a["utility_judge"] is None else f"{a['utility_judge']:.2f}"
        print(f"{k:<30}{a['leak_rate']:<9.1%}{a['reversibility']:<9.1%}"
              f"{a['utility_completed']:<9.1%}{a['refusal_rate']:<9.1%}{judge:<8}{a['n']}")
    print()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="PRvL+ multi-model runner (Privacy / Reversibility / Utility)"
    )
    ap.add_argument("--models", default=None,
                    help=f"comma list of labels (default: all). choices: {[m[0] for m in MODELS]}")
    ap.add_argument("--profiles", default=None,
                    help=f"comma list (default: {','.join(PROFILES)})")
    ap.add_argument("--limit", type=int, default=None, help="evaluate only the first N cases")
    ap.add_argument("--judge", action="store_true", help="add LLM-judge utility (extra calls)")
    ap.add_argument("--judge-model", default=JUDGE_MODEL_DEFAULT,
                    help="OpenRouter id of the judge model")
    ap.add_argument("--out", default=None,
                    help="snapshot JSON path (default: results/prvl_multi_<version>.json)")
    ap.add_argument("--timeout", type=float, default=60.0, help="per-call timeout (seconds)")
    args = ap.parse_args(argv)

    if not os.environ.get(OPENROUTER_ENV_KEY):
        print(f"[warn] {OPENROUTER_ENV_KEY} not set — calls will error per-row", file=sys.stderr)

    snap = run(
        models=[s.strip() for s in args.models.split(",")] if args.models else None,
        profiles=[s.strip() for s in args.profiles.split(",")] if args.profiles else None,
        limit=args.limit,
        judge=args.judge,
        judge_model=args.judge_model,
        timeout=args.timeout,
        out=args.out,
    )
    _print_table(snap)
    return 0


if __name__ == "__main__":
    sys.exit(main())
