"""Re-identification-risk eval (PRvL+ X axis) — eval/defensive use only.

cf. arXiv 2603.18382. After a redactor strips explicit PII, can an LLM still
re-identify the subject by matching RESIDUAL quasi-identifiers (age, city/
district, occupation, employer, sensitive attribute, hobby) against a known
candidate pool? Lower re-id rate = better privacy.

Redactors: raw (upper bound) vs argus_fast (mode='fast'). argus_fast removes
explicit PII but leaves most quasi-identifiers, so a high residual re-id rate is
the EXPECTED, honest result: removing explicit PII is NOT anonymization. The
residual comes from the COMBINATION of surviving quasi-identifiers (age + coarse
location + free-text attributes), not any single field — see
docs/design-quasi-identifier-generalization.md for why coarsening one field
(the explored-and-removed 'generalize' experiment) did not move this number.

Closed-world, fully synthetic fixture (no real people, no live web). Numbers are a
controlled directional indicator, NOT a real-world re-identification guarantee.

Run (needs an LLM backend; key from env, never committed):
    python -m tests.benchmark.reid_eval --provider deepseek
    python -m tests.benchmark.reid_eval --provider qwen
    python -m tests.benchmark.reid_eval --provider ollama --model qwen2.5:7b
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import re
import sys
from pathlib import Path

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "reid_profiles.json"
RESULTS_DIR = Path(__file__).resolve().parent / "results"
SALT = 42

# provider -> (base_url, default_model, env_key_or_None)
PROVIDERS = {
    "deepseek":   ("https://api.deepseek.com/chat/completions", "deepseek-chat", "DEEPSEEK_API_KEY"),
    "qwen":       ("https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions", "qwen-plus", "QWEN_API_KEY"),
    "doubao":     ("https://ark.cn-beijing.volces.com/api/v3/chat/completions", os.environ.get("DOUBAO_MODEL", "doubao-pro-32k"), "DOUBAO_API_KEY"),
    "openrouter": ("https://openrouter.ai/api/v1/chat/completions", "deepseek/deepseek-chat", "OPENROUTER_API_KEY"),
    "poe":        ("https://api.poe.com/v1/chat/completions", "GPT-4o", "POE_API_KEY"),
    "ollama":     ("http://localhost:11434/v1/chat/completions", "qwen2.5:7b", None),
}
SYSTEM = "你是一个去匿名化分析助手。"


def redactor_raw(text: str) -> str:
    return text


def redactor_argus_fast(text: str) -> str:
    from argus_redact import redact
    out = redact(text, mode="fast", lang=["zh", "en"], salt=SALT)
    return out[0] if isinstance(out, tuple) else out


REDACTORS = {"raw": redactor_raw, "argus_fast": redactor_argus_fast}


def available_providers() -> list[str]:
    out = []
    for name, (_, _, env) in PROVIDERS.items():
        if env is None or os.environ.get(env):
            out.append(name)
    return out


def resolve_provider(name: str | None) -> tuple[str, str, str, str]:
    """Return (provider_label, base_url, model, api_key). Raises if unavailable."""
    candidates = [name] if name else list(PROVIDERS)
    for cand in candidates:
        if cand not in PROVIDERS:
            raise SystemExit(f"unknown provider {cand!r}; choose from {list(PROVIDERS)}")
        base_url, model, env = PROVIDERS[cand]
        key = "" if env is None else os.environ.get(env, "")
        if env is None or key:
            return cand, base_url, model, key
    raise SystemExit(
        "no LLM backend available — set one of "
        f"{[p[2] for p in PROVIDERS.values() if p[2]]} or run Ollama locally"
    )


def call_llm(base_url: str, model: str, api_key: str, system: str, user: str, timeout: float = 60.0) -> str:
    import httpx
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    resp = httpx.post(
        base_url, headers=headers,
        json={"model": model,
              "messages": [{"role": "system", "content": system},
                           {"role": "user", "content": user}],
              "temperature": 0, "max_tokens": 20},
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]


def build_prompt(redacted_text: str, candidates: list[dict]) -> str:
    roster = "\n".join(f"{c['id']}. {c['summary']}" for c in candidates)
    return ("以下是一段（可能已脱敏的）人物描述，以及一个候选人物名单（编号 + 背景信息）。"
            "这段描述最可能在说名单里的哪一位？只回答编号数字；若无法确定回答 0。\n\n"
            f"描述：{redacted_text}\n\n候选名单：\n{roster}\n\n答案（只回答编号）：")


def parse_guess(reply: str) -> int:
    m = re.search(r"-?\d+", reply or "")
    return int(m.group()) if m else -1


def run_eval(provider: str | None = None, model: str | None = None, limit: int | None = None) -> dict:
    """Run the eval; return a snapshot dict. Pure of file I/O (caller persists)."""
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    candidates = data["candidates"]
    profiles = data["profiles"][: limit] if limit else data["profiles"]
    label, base_url, resolved_model, key = resolve_provider(provider)
    model = model or resolved_model

    redactors: dict[str, dict] = {}
    for name, fn in REDACTORS.items():
        correct = n = 0
        per_profile = []
        for p in profiles:
            truth = p["truth"]
            try:
                redacted = fn(p["text"])
            except Exception as e:  # noqa: BLE001
                redacted = p["text"]
                print(f"[redact-error] {name} truth={truth}: {e}", file=sys.stderr)
            try:
                guess = parse_guess(call_llm(base_url, model, key, SYSTEM, build_prompt(redacted, candidates)))
            except Exception as e:  # noqa: BLE001
                print(f"[api-error] {name} truth={truth}: {e}", file=sys.stderr)
                continue
            n += 1
            correct += int(guess == truth)
            per_profile.append({"truth": truth, "guess": guess})
        redactors[name] = {"reid_rate": (correct / n if n else None), "correct": correct, "n": n, "per_profile": per_profile}

    return {
        "benchmark": "reidentification",
        "provider": label,
        "model": model,
        "n_profiles": len(profiles),
        "n_candidates": len(candidates),
        "fixture_sha256": hashlib.sha256(FIXTURE.read_bytes()).hexdigest()[:16],
        "redactors": redactors,
    }


def _pkg_version() -> str:
    try:
        import argus_redact
        return getattr(argus_redact, "__version__", "dev")
    except Exception:  # noqa: BLE001
        return "dev"


def _print_table(snap: dict) -> None:
    print(f"\n[provider] {snap['provider']} (model={snap['model']})")
    print(f"[fixture] {snap['n_candidates']} candidates, {snap['n_profiles']} profiles\n")
    print(f"{'redactor':<14}{'re-id rate':<14}{'correct/N'}")
    print("-" * 42)
    for name, r in snap["redactors"].items():
        rate = "n/a" if r["reid_rate"] is None else f"{r['reid_rate']:.2%}"
        print(f"{name:<14}{rate:<14}{r['correct']}/{r['n']}")
    print()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="re-identification risk eval (PRvL+ X axis)")
    ap.add_argument("--provider", choices=list(PROVIDERS), default=None,
                    help="LLM backend (default: first with a key in env)")
    ap.add_argument("--model", default=None, help="override model id")
    ap.add_argument("--limit", type=int, default=None, help="evaluate only the first N profiles")
    ap.add_argument("--out", default=None,
                    help="snapshot JSON path (default: results/reidentification_<version>.json, "
                         "merging this provider's run into a runs[] array)")
    args = ap.parse_args(argv)

    snap = run_eval(args.provider, args.model, args.limit)
    _print_table(snap)

    if args.limit:
        print("[note] --limit set; snapshot NOT written (partial run)", file=sys.stderr)
        return 0

    out = Path(args.out) if args.out else RESULTS_DIR / f"reidentification_{_pkg_version()}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    doc = {"benchmark": "reidentification", "package_version": _pkg_version(),
           "date": _dt.date.today().isoformat(), "fixture_sha256": snap["fixture_sha256"], "runs": []}
    if out.exists():
        try:
            doc = json.loads(out.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            pass
    doc.setdefault("runs", [])
    doc["runs"] = [r for r in doc["runs"] if not (r.get("provider") == snap["provider"] and r.get("model") == snap["model"])]
    doc["runs"].append({k: snap[k] for k in ("provider", "model", "n_profiles", "n_candidates", "redactors")})
    doc["date"] = _dt.date.today().isoformat()
    out.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[snapshot] wrote {out} ({len(doc['runs'])} run(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
