"""argus-redact CLI — redact / restore / info."""

import argparse
import json
import sys
from pathlib import Path


def _read_input(input_path: str | None) -> str:
    """Read text from file or stdin. Forces UTF-8 decoding."""
    if input_path:
        path = Path(input_path)
        if not path.exists():
            print(f"Error: input file not found: {input_path}", file=sys.stderr)
            sys.exit(1)
        return path.read_text(encoding="utf-8")
    # Bypass platform-default encoding (cp1252 on Windows) — read raw bytes
    # and decode as UTF-8. Without this, Chinese stdin produces surrogate
    # characters that downstream Rust regex / json.dumps reject.
    return sys.stdin.buffer.read().decode("utf-8")


def _write_output(text: str, output_path: str | None):
    """Write text to file or stdout. Forces UTF-8 encoding on stdout."""
    if output_path:
        Path(output_path).write_text(text, encoding="utf-8")
        return
    # Bypass platform-default stdout encoding (cp1252 on Windows). Use the
    # binary buffer to avoid UnicodeEncodeError on CJK output.
    payload = text if text.endswith("\n") else text + "\n"
    sys.stdout.buffer.write(payload.encode("utf-8"))


def _parse_strategy_override(s: str | None) -> dict[str, str] | None:
    """Parse 'phone:realistic,address:remove' → {'phone': 'realistic', ...}.

    Empty / None → None. Malformed pair → ValueError naming the offending pair.
    """
    if not s:
        return None
    out: dict[str, str] = {}
    for pair in s.split(","):
        pair = pair.strip()
        if not pair:
            continue
        if ":" not in pair:
            raise ValueError(
                f"Invalid --strategy-override pair {pair!r}; "
                f"expected 'type:strategy' (e.g. phone:realistic)"
            )
        ent_type, _, strategy = pair.partition(":")
        ent_type = ent_type.strip()
        strategy = strategy.strip()
        if not ent_type or not strategy:
            raise ValueError(f"Empty type or strategy in pair {pair!r}")
        out[ent_type] = strategy
    return out or None


def cmd_redact(args):
    from argus_redact import redact, redact_pseudonym_llm

    text = _read_input(args.input)
    key_path = Path(args.key)

    profile = getattr(args, "profile", None)
    seed = int(args.seed) if args.seed else None
    lang = args.lang.split(",") if "," in args.lang else args.lang

    raw_override = getattr(args, "strategy_override", None)
    try:
        strategy_overrides = _parse_strategy_override(raw_override)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)
    if strategy_overrides and profile != "pseudonym-llm":
        print(
            "Error: --strategy-override only applies with --profile pseudonym-llm",
            file=sys.stderr,
        )
        sys.exit(2)

    unified_prefix = getattr(args, "unified_prefix", None)

    if profile == "pseudonym-llm":
        salt = seed.to_bytes(8, "big", signed=False) if seed is not None and seed >= 0 else None
        result = redact_pseudonym_llm(
            text,
            lang=lang,
            mode=args.mode,
            salt=salt,
            strategy_overrides=strategy_overrides,
            unified_prefix=unified_prefix,
        )
        key_path.write_text(
            json.dumps(result.key, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        payload = {
            "audit_text": result.audit_text,
            "downstream_text": result.downstream_text,
            "display_text": result.display_text,
            "key": result.key,
        }
        _write_output(json.dumps(payload, ensure_ascii=False, indent=2), args.output)
        return

    # Standard path (default / pipl / gdpr / hipaa / config-only)
    existing_key = None
    if key_path.exists():
        try:
            existing_key = json.loads(key_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            print(f"Error: invalid key file: {args.key}", file=sys.stderr)
            sys.exit(5)

    redacted, key = redact(
        text,
        seed=seed,
        mode=args.mode,
        lang=lang,
        key=existing_key,
        config=args.config,
        profile=profile,
        unified_prefix=unified_prefix,
    )

    key_path.write_text(
        json.dumps(key, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    _write_output(redacted, args.output)


def cmd_restore(args):
    from argus_redact import restore

    key_path = Path(args.key)
    if not key_path.exists():
        print(f"Error: key file not found: {args.key}", file=sys.stderr)
        sys.exit(4)

    try:
        key = json.loads(key_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        print(f"Error: invalid key file: {args.key}", file=sys.stderr)
        sys.exit(5)

    text = _read_input(args.input)
    restored = restore(text, key)

    _write_output(restored, args.output)


def cmd_info(args):
    import importlib
    import importlib.util

    from argus_redact.lang.shared.patterns import PATTERNS as SHARED

    langs = {
        "zh": "Chinese",
        "en": "English",
        "ja": "Japanese",
        "ko": "Korean",
        "de": "German",
        "uk": "British",
        "in": "Indian",
    }

    from argus_redact import __version__

    print(f"argus-redact v{__version__}")
    print()
    print("Languages:")
    for code, name in langs.items():
        mod_code = "in_" if code == "in" else code
        try:
            mod = importlib.import_module(f"argus_redact.lang.{mod_code}.patterns")
            count = len(mod.PATTERNS) + len(SHARED)
        except ModuleNotFoundError:
            count = 0
        has_ner = importlib.util.find_spec(f"argus_redact.lang.{mod_code}.ner_adapter") is not None
        ner_label = " + NER" if has_ner else ""
        print(f"  {code}  {name:10s} regex ({count} patterns){ner_label}")

    print()
    print("Layers:")
    print("  1 Pattern (regex)       ✓")
    has_hanlp = importlib.util.find_spec("hanlp") is not None
    has_spacy = importlib.util.find_spec("spacy") is not None
    ner_ok = has_hanlp or has_spacy
    print(f"  2 Entity (NER)          {'✓' if ner_ok else '✗'}")
    ollama_ok = importlib.util.find_spec("requests") is not None
    print(f"  3 Semantic (Ollama)     {'✓' if ollama_ok else '✗'}")


def cmd_assess(args):
    from argus_redact import redact

    text = _read_input(args.input)
    lang = args.lang.split(",") if "," in args.lang else args.lang

    report = redact(
        text,
        mode=args.mode,
        lang=lang,
        report=True,
    )

    data = {
        "summary": {
            "risk_score": report.risk.score,
            "risk_level": report.risk.level,
            "entities_detected": len(report.entities),
        },
        "compliance": {
            "pipl_articles": list(report.risk.pipl_articles),
        },
        "entities": list(report.entities),
        "stats": report.stats,
    }
    output = json.dumps(data, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Report saved to {args.output}", file=sys.stderr)
    else:
        print(output)


def cmd_setup(args):
    """Pre-download NER models for offline use."""
    langs = args.lang.split(",") if "," in args.lang else [args.lang]

    for code in langs:
        print(f"Setting up {code}...")
        try:
            if code == "zh":
                import hanlp

                print("  Downloading HanLP MSRA NER model...")
                hanlp.load(hanlp.pretrained.mtl.CLOSE_TOK_POS_NER_SRL_DEP_SDP_CON_ELECTRA_BASE_ZH)
                print("  Done.")
            elif code in ("en", "ja", "ko"):
                import spacy

                model_map = {
                    "en": "en_core_web_sm",
                    "ja": "ja_core_news_sm",
                    "ko": "ko_core_news_sm",
                }
                model = model_map[code]
                print(f"  Downloading spaCy model {model}...")
                try:
                    spacy.load(model)
                    print(f"  {model} already installed.")
                except OSError:
                    from spacy.cli import download

                    download(model)
                    print("  Done.")
            else:
                print(f"  {code}: regex only, no model to download.")
        except ImportError:
            print(f"  {code}: language pack not installed. Run: pip install argus-redact[{code}]")


def cmd_serve(args):
    import uvicorn

    from argus_redact.server import create_app

    app = create_app(allow_no_auth=args.insecure)
    print(f"argus-redact server starting on {args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port)


def _build_parser() -> argparse.ArgumentParser:
    """Construct the top-level argparse parser. Extracted for testability."""
    parser = argparse.ArgumentParser(
        prog="argus-redact",
        description="Encrypt PII, not meaning. Locally.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # redact
    p_redact = subparsers.add_parser("redact", help="Redact PII from text")
    p_redact.add_argument("input", nargs="?", default=None, help="Input file (default: stdin)")
    p_redact.add_argument("-k", "--key", required=True, help="Key file path")
    p_redact.add_argument("-o", "--output", default=None, help="Output file (default: stdout)")
    p_redact.add_argument("-l", "--lang", default="zh", help="Language (default: zh)")
    p_redact.add_argument(
        "-m", "--mode", default="fast", help="Detection mode: fast (default), ner, auto"
    )
    p_redact.add_argument("-s", "--seed", default=None, help="Random seed for determinism")
    p_redact.add_argument("-c", "--config", default=None, help="Config file (JSON or YAML)")
    p_redact.add_argument(
        "--profile",
        choices=["default", "pipl", "gdpr", "hipaa", "pseudonym-llm"],
        default=None,
        help=(
            "Compliance profile. 'pseudonym-llm' emits JSON with audit_text, "
            "downstream_text, display_text, key (for LLM-friendly redaction)."
        ),
    )
    p_redact.add_argument(
        "--strategy-override",
        default=None,
        metavar="TYPE:STRATEGY,...",
        help=(
            "Per-type strategy override for --profile pseudonym-llm. "
            "Example: --strategy-override 'phone:remove,address:realistic'. "
            "Strategy names: pseudonym, realistic, mask, remove, category, "
            "name_mask, landline_mask."
        ),
    )
    p_redact.add_argument(
        "--unified-prefix",
        metavar="PREFIX",
        default=None,
        help="Unify all reversible-strategy types under one prefix (e.g. 'R' -> R-NNNNN)",
    )
    p_redact.set_defaults(func=cmd_redact)

    # restore
    p_restore = subparsers.add_parser("restore", help="Restore redacted text")
    p_restore.add_argument("input", nargs="?", default=None, help="Input file (default: stdin)")
    p_restore.add_argument("-k", "--key", required=True, help="Key file path")
    p_restore.add_argument("-o", "--output", default=None, help="Output file (default: stdout)")
    p_restore.set_defaults(func=cmd_restore)

    # assess
    p_assess = subparsers.add_parser("assess", help="Assess privacy risk of text")
    p_assess.add_argument("input", nargs="?", default=None, help="Input file (default: stdin)")
    p_assess.add_argument("-o", "--output", default=None, help="Save report to file")
    p_assess.add_argument("-l", "--lang", default="zh", help="Language (default: zh)")
    p_assess.add_argument(
        "-m", "--mode", default="fast", help="Detection mode: fast (default), ner, auto"
    )
    # PDF/markdown report generation removed — use redact(report=True) for raw data
    p_assess.set_defaults(func=cmd_assess)

    # info
    p_info = subparsers.add_parser("info", help="Show installed capabilities")
    p_info.set_defaults(func=cmd_info)

    # setup
    p_setup = subparsers.add_parser("setup", help="Pre-download NER models for offline use")
    p_setup.add_argument("-l", "--lang", default="zh", help="Language(s) to download (default: zh)")
    p_setup.set_defaults(func=cmd_setup)

    # serve
    p_serve = subparsers.add_parser("serve", help="Start HTTP API server")
    p_serve.add_argument("--host", default="127.0.0.1", help="Host (default: 127.0.0.1)")
    p_serve.add_argument("--port", type=int, default=8000, help="Port (default: 8000)")
    p_serve.add_argument(
        "--insecure",
        action="store_true",
        help="Run without ARGUS_API_KEY auth (local development only).",
    )
    p_serve.set_defaults(func=cmd_serve)

    return parser


def main():
    # Force UTF-8 on stdout/stderr so CJK output / error messages don't crash
    # under Windows cp1252 default. _read_input / _write_output bypass these
    # for stdin/stdout binary paths, but `print(..., file=sys.stderr)` and
    # CLI subcommands using `print()` rely on the configured encoding.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    parser = _build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
