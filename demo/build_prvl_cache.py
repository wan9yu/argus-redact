"""Offline baker: project today's PRvL paper-data into demo/prvl_cache.json.

Run once after a fresh PRvL benchmark; the cache is committed alongside app.py.
"""
from __future__ import annotations

import json
from pathlib import Path

SRC = Path.home() / "Desktop/argus-paper-data/2026-05-04/raw/prvl_multi.json"
DST = Path(__file__).resolve().parent / "prvl_cache.json"

CASE_ID = "summarize_zh"
PROFILE = "pseudonym-llm"
MODEL_ORDER = ["GPT-5", "Claude-Opus-4.5", "Gemini-2.5-Pro", "GLM-4.5"]


def main() -> None:
    if not SRC.exists():
        raise SystemExit(
            f"Source PRvL data not found at: {SRC}\n"
            f"This baker is a one-shot tool — update SRC to point to your "
            f"current PRvL run JSON, or rebake against the latest data."
        )
    try:
        rows_raw = json.loads(SRC.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise SystemExit(f"Source file is not valid JSON: {SRC}\n{e}") from e
    matched = [
        r for r in rows_raw
        if r["case_id"] == CASE_ID and r["profile"] == PROFILE
    ]
    if len(matched) != len(MODEL_ORDER):
        raise SystemExit(
            f"Expected {len(MODEL_ORDER)} rows for {CASE_ID}/{PROFILE}, got {len(matched)}"
        )
    by_model = {r["model"]: r for r in matched}
    rows_out = []
    for model in MODEL_ORDER:
        if model not in by_model:
            raise SystemExit(f"Missing row for model {model}")
        r = by_model[model]
        try:
            rows_out.append({
                "model": model,
                "downstream_text": r["redacted"],
                "llm_reply": r["output"],
                "leaked": r["privacy"]["leaked"],
                "total_pii": r["privacy"]["total"],
                "utility": r["utility"],
            })
        except KeyError as e:
            raise SystemExit(
                f"Malformed source row for model {model}: missing field {e}\n"
                f"Expected source schema: case_id, profile, model, redacted, "
                f"output, privacy.{{leaked,total}}, utility"
            ) from e
    DST.write_text(
        json.dumps(
            {
                "source_run": "PRvL bench 2026-05-04",
                "case_id": CASE_ID,
                "profile": PROFILE,
                "rows": rows_out,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"✓ wrote {DST} with {len(rows_out)} rows")


if __name__ == "__main__":
    main()
