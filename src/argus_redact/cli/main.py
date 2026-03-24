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
    from argus_redact.lang.shared.patterns import PATTERNS as SHARED_PATTERNS
    from argus_redact.lang.zh.patterns import PATTERNS as ZH_PATTERNS

    print("argus-redact v0.1.0")
    print()
    print("Languages:")
    zh_count = len(ZH_PATTERNS)
    shared_count = len(SHARED_PATTERNS)
    print(f"  zh  regex ({zh_count + shared_count} patterns)")
    print()
    print("Layers:")
    print("  1 Pattern (regex)       ✓")
    print("  2 Entity (NER)          ✗")
    print("  3 Semantic (LLM)        ✗")


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

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
