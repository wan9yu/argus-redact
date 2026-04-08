"""argus-redact CLI — redact / restore / info."""

import argparse
import json
import sys
from pathlib import Path


def _read_input(input_path: str | None) -> str:
    """Read text from file or stdin."""
    if input_path:
        path = Path(input_path)
        if not path.exists():
            print(f"Error: input file not found: {input_path}", file=sys.stderr)
            sys.exit(1)
        return path.read_text()
    return sys.stdin.read()


def _write_output(text: str, output_path: str | None):
    """Write text to file or stdout."""
    if output_path:
        Path(output_path).write_text(text)
    else:
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")


def cmd_redact(args):
    from argus_redact import redact

    text = _read_input(args.input)
    key_path = Path(args.key)

    # Load existing key if file exists
    existing_key = None
    if key_path.exists():
        try:
            existing_key = json.loads(key_path.read_text())
        except json.JSONDecodeError:
            print(f"Error: invalid key file: {args.key}", file=sys.stderr)
            sys.exit(5)

    seed = int(args.seed) if args.seed else None
    lang = args.lang.split(",") if "," in args.lang else args.lang

    redacted, key = redact(
        text,
        seed=seed,
        mode=args.mode,
        lang=lang,
        key=existing_key,
        config=args.config,
    )

    # Write key file
    key_path.write_text(json.dumps(key, ensure_ascii=False, indent=2))

    _write_output(redacted, args.output)


def cmd_restore(args):
    from argus_redact import restore

    key_path = Path(args.key)
    if not key_path.exists():
        print(f"Error: key file not found: {args.key}", file=sys.stderr)
        sys.exit(4)

    try:
        key = json.loads(key_path.read_text())
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

    import json as _json
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
    output = _json.dumps(data, ensure_ascii=False, indent=2)
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

    app = create_app()
    print(f"argus-redact server starting on {args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port)


def main():
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
    p_redact.add_argument("-m", "--mode", default="auto", help="Detection mode: auto, fast, ner")
    p_redact.add_argument("-s", "--seed", default=None, help="Random seed for determinism")
    p_redact.add_argument("-c", "--config", default=None, help="Config file (JSON or YAML)")
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
    p_assess.add_argument("-m", "--mode", default="auto", help="Detection mode: auto, fast, ner")
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
    p_serve.set_defaults(func=cmd_serve)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
