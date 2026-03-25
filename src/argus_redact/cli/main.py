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

    langs = {"zh": "Chinese", "en": "English", "ja": "Japanese", "ko": "Korean"}

    from argus_redact import __version__

    print(f"argus-redact v{__version__}")
    print()
    print("Languages:")
    for code, name in langs.items():
        try:
            mod = importlib.import_module(f"argus_redact.lang.{code}.patterns")
            count = len(mod.PATTERNS) + len(SHARED)
        except ModuleNotFoundError:
            count = 0
        has_ner = importlib.util.find_spec(f"argus_redact.lang.{code}.ner_adapter") is not None
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
    p_redact.set_defaults(func=cmd_redact)

    # restore
    p_restore = subparsers.add_parser("restore", help="Restore redacted text")
    p_restore.add_argument("input", nargs="?", default=None, help="Input file (default: stdin)")
    p_restore.add_argument("-k", "--key", required=True, help="Key file path")
    p_restore.add_argument("-o", "--output", default=None, help="Output file (default: stdout)")
    p_restore.set_defaults(func=cmd_restore)

    # info
    p_info = subparsers.add_parser("info", help="Show installed capabilities")
    p_info.set_defaults(func=cmd_info)

    # serve
    p_serve = subparsers.add_parser("serve", help="Start HTTP API server")
    p_serve.add_argument("--host", default="0.0.0.0", help="Host (default: 0.0.0.0)")
    p_serve.add_argument("--port", type=int, default=8000, help="Port (default: 8000)")
    p_serve.set_defaults(func=cmd_serve)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
