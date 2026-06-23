"""Re-id ABLATION — rank which surviving quasi-identifier drives re-identification.

For each survivor (medical-condition / hobby / surviving-city), strip it from the
ALREADY-redacted (argus_fast) text and measure the re-id-rate drop. Higher drop =
higher leverage = build that detector first. cf. docs/design-quasi-identifier-
generalization.md (occupation > location was found this way). Off by default;
ARGUS_REID_EVAL=1 + a provider key required. No new engine behavior — pure
measurement to order the build.

Run (needs an LLM backend; key from env, never committed):
    ARGUS_REID_EVAL=1 python -m tests.benchmark.reid_ablation --provider deepseek
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

# Hand-authored strip patterns for the synthetic fixture's survivors. Eval-only
# (NOT detection) — they isolate each signal's re-id contribution.
_STRIP = {
    "condition": [r"对?[一-鿿]{2,6}(?:严重)?过敏", r"花生|海鲜|乳糖|高血压|糖尿病|抑郁症"],
    "hobby": [r"攀岩|岩馆|钓鱼|书法|马拉松|滑雪|瑜伽|围棋|登山|骑行"],
    "city": [r"上海|北京|广州|深圳|杭州|成都|武汉|西安"],
}

# English survivor strip patterns (case-insensitive), keyed to reid_profiles_en.json.
# Eval-only (NOT detection) — isolate each signal's re-id contribution.
_STRIP_EN = {
    "occupation": [
        r"(?i)pastry chef", r"(?i)software engineer", r"(?i)data scientist",
        r"(?i)(?:high-school|high school) (?:mathematics|physics|english) teacher",
        r"(?i)teaches? (?:high-school|high school) (?:mathematics|physics|english)",
        r"(?i)(?:icu|emergency-room|registered) nurse", r"(?i)accountant",
        r"(?i)lawyer", r"(?i)graphic designer", r"(?i)civil engineer",
        r"(?i)electrician", r"(?i)project manager", r"(?i)physical therapist",
    ],
    "condition": [
        r"(?i)celiac disease", r"(?i)gluten intolerance", r"(?i)type 2 diabetes",
        r"(?i)asthma", r"(?i)anxiety", r"(?i)hypertension|high blood pressure",
        r"(?i)hypothyroidism", r"(?i)migraines?", r"(?i)eczema", r"(?i)anemia",
        r"(?i)psoriasis", r"(?i)allergic to penicillin",
        r"(?i)knee .{0,20}surgery|injured my knee",
    ],
    "hobby": [
        r"(?i)salsa dancing", r"(?i)restor\w* .{0,12}motorcycles", r"(?i)rock climbing",
        r"(?i)playing chess", r"(?i)gardening", r"(?i)playing the piano",
        r"(?i)running marathons?", r"(?i)surfing", r"(?i)photography",
        r"(?i)cycling", r"(?i)baking", r"(?i)fishing", r"(?i)hiking",
    ],
}


def _strip(text: str, which: str, table: dict) -> str:
    if which == "(none)":
        return text
    for pat in table[which]:
        text = re.sub(pat, "", text)
    return text


def main() -> int:
    if os.environ.get("ARGUS_REID_EVAL") != "1":
        print("ablation skipped (set ARGUS_REID_EVAL=1 + a provider key)")
        return 0

    # REUSE reid_eval.py's real helpers — client, prompt, parser, fixture, salt.
    from tests.benchmark import reid_eval as E

    ap = argparse.ArgumentParser(
        description="re-id ablation — rank surviving quasi-identifiers by re-id leverage"
    )
    ap.add_argument("--provider", choices=list(E.PROVIDERS), default=None,
                    help="LLM backend (default: first with a key in env)")
    ap.add_argument("--model", default=None, help="override model id")
    ap.add_argument("--limit", type=int, default=None, help="evaluate only the first N profiles")
    ap.add_argument("--pool", choices=["zh", "en"], default="zh",
                    help="closed-world fixture + prompt + strip table (default: zh)")
    args = ap.parse_args()

    # 1. Resolve provider (CLI arg, else reid_eval's "first with a key" logic).
    label, base_url, resolved_model, key = E.resolve_provider(args.provider)
    model = args.model or resolved_model

    # 2. Load the fixture via reid_eval's path constant + field layout.
    fixture_path = E.FIXTURE_EN if args.pool == "en" else E.FIXTURE
    data = json.loads(fixture_path.read_text(encoding="utf-8"))
    candidates = data["candidates"]
    profiles = data["profiles"][: args.limit] if args.limit else data["profiles"]
    system = E.SYSTEM_EN if args.pool == "en" else E.SYSTEM
    prompt_fn = E.build_prompt_en if args.pool == "en" else E.build_prompt
    strip_table = _STRIP_EN if args.pool == "en" else _STRIP
    variants = ["(none)", "occupation", "condition", "hobby"] if args.pool == "en" \
        else ["(none)", "condition", "hobby", "city"]

    # 3. argus_fast baseline: redact each profile once, reuse the redacted strings
    #    across every ablation variant (reid_eval handles the (text, key) tuple).
    baseline = [(p["truth"], E.redactor_argus_fast(p["text"])) for p in profiles]

    print(f"\n[provider] {label} (model={model})")
    print(f"[fixture] {len(candidates)} candidates, {len(baseline)} profiles (argus_fast baseline)\n")
    print(f"{'strip':<14}{'re-id rate':<14}{'correct/N':<12}{'drop vs (none)'}")
    print("-" * 56)

    # 4. For each survivor, strip from the redacted text and re-run the re-id ask.
    rates: dict[str, float | None] = {}
    drops: dict[str, float] = {}
    for which in variants:
        correct = n = 0
        for truth, redacted in baseline:
            ablated = _strip(redacted, which, strip_table)
            try:
                reply = E.call_llm(base_url, model, key, system, prompt_fn(ablated, candidates))
            except Exception as e:  # noqa: BLE001
                print(f"[api-error] strip={which} truth={truth}: {e}", file=sys.stderr)
                continue
            guess = E.parse_guess(reply)
            n += 1
            correct += int(guess == truth)
        rate = (correct / n) if n else None
        rates[which] = rate
        base_rate = rates.get("(none)")
        drop = (base_rate - rate) if (base_rate is not None and rate is not None and which != "(none)") else 0.0
        if which != "(none)":
            drops[which] = drop
        rate_s = "n/a" if rate is None else f"{rate:.2%}"
        drop_s = "—" if which == "(none)" else f"{drop:+.2%}"
        print(f"{which:<14}{rate_s:<14}{f'{correct}/{n}':<12}{drop_s}")

    # 5. Largest re-id drop = highest leverage = build that detector first.
    print()
    if drops:
        ranked = sorted(drops.items(), key=lambda kv: kv[1], reverse=True)
        order = ", ".join(f"{w} ({d:+.2%})" for w, d in ranked)
        top = ranked[0][0]
        print(f"[leverage] re-id drop ranking: {order}")
        print(f"[build-order] largest drop = '{top}' — build that detector FIRST.")
    else:
        print("[leverage] no comparable runs (all variants errored or empty).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
