"""argus-redact CLI — redact / restore / info."""

import argparse
import json
import sys
from pathlib import Path

from argus_redact._safe_io import safe_read_text as _safe_read_text
from argus_redact._safe_io import safe_write_key as _safe_write_key
from argus_redact._safe_io import safe_write_text as _safe_write_text


def _read_input(input_path: str | None) -> str:
    """Read text from file or stdin. Forces UTF-8 decoding."""
    if input_path:
        path = Path(input_path)
        if not path.exists():
            print(f"Error: input file not found: {input_path}", file=sys.stderr)
            sys.exit(1)
        try:
            return _safe_read_text(path)
        except OSError as e:
            # A directory, a symlink (O_NOFOLLOW), a permission error — all
            # OSError subclasses, none of them a FileNotFoundError, all of them
            # a raw traceback before this.
            print(f"Error: cannot read input file {input_path}: {e}", file=sys.stderr)
            sys.exit(1)
        except UnicodeDecodeError:
            print(f"Error: input file is not valid UTF-8: {input_path}", file=sys.stderr)
            sys.exit(1)
    # Bypass platform-default encoding (cp1252 on Windows) — read raw bytes
    # and decode as UTF-8. Without this, Chinese stdin produces surrogate
    # characters that downstream Rust regex / json.dumps reject.
    try:
        return sys.stdin.buffer.read().decode("utf-8")
    except UnicodeDecodeError:
        # The file branch above already guards this; stdin was the last raw
        # traceback. Do NOT decode with errors="replace" — that silently
        # corrupts PII text rather than refusing the input.
        print("Error: stdin is not valid UTF-8", file=sys.stderr)
        sys.exit(1)


def _write_output(text: str, output_path: str | None, mode: int = 0o644):
    """Write text to file or stdout. Forces UTF-8 encoding on stdout."""
    if output_path:
        _safe_write_text(output_path, text, mode=mode)
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


def _load_key_file(key_path: Path, arg: str) -> dict:
    """Load and validate a key file, or exit with a clean message.

    A key file holding a JSON array/string/number parses fine, so the
    JSONDecodeError guard never fired: ``redact`` silently ignored it, exited
    0, and then OVERWROTE the operator's file — destroying it with no error.
    ``restore`` instead raised a raw ``TypeError: key must be a Mapping``
    traceback. The HTTP face already answers 400 'key must be a JSON object';
    this brings the CLI to the same contract.
    """
    try:
        loaded = json.loads(_safe_read_text(key_path))
    except json.JSONDecodeError:
        print(f"Error: invalid key file: {arg}", file=sys.stderr)
        sys.exit(5)
    except OSError as e:
        print(f"Error: cannot read key file {arg}: {e}", file=sys.stderr)
        sys.exit(5)
    except UnicodeDecodeError:
        print(f"Error: key file is not valid UTF-8: {arg}", file=sys.stderr)
        sys.exit(5)
    if not isinstance(loaded, dict):
        print(
            f"Error: key file must contain a JSON object, got {type(loaded).__name__}: {arg}",
            file=sys.stderr,
        )
        sys.exit(5)
    return loaded


def _load_aliases_file(aliases_path: Path, arg: str) -> dict[str, list[str]]:
    """Load and validate an ``--aliases`` sidecar file, or exit with a clean
    message. Mirrors ``_load_key_file``'s error contract: a not-found path is
    exit 4 (matching ``--key``'s not-found code), a malformed/wrong-shaped
    file is exit 5 (matching ``--key``'s invalid-shape code).

    Each value must be a JSON array of strings — a bare string value would
    otherwise iterate character-by-character once handed to ``restore()``
    (the same footgun the HTTP face's ``anchor.scope`` check guards against),
    silently building garbage single-character aliases instead of failing.
    """
    if not aliases_path.exists():
        print(f"Error: aliases file not found: {arg}", file=sys.stderr)
        sys.exit(4)
    try:
        loaded = json.loads(_safe_read_text(aliases_path))
    except json.JSONDecodeError:
        print(f"Error: invalid aliases file: {arg}", file=sys.stderr)
        sys.exit(5)
    except OSError as e:
        print(f"Error: cannot read aliases file {arg}: {e}", file=sys.stderr)
        sys.exit(5)
    except UnicodeDecodeError:
        print(f"Error: aliases file is not valid UTF-8: {arg}", file=sys.stderr)
        sys.exit(5)
    if not isinstance(loaded, dict) or not all(isinstance(v, list) for v in loaded.values()):
        print(
            f"Error: aliases file must contain a JSON object of {{fake: [alias, ...]}}: {arg}",
            file=sys.stderr,
        )
        sys.exit(5)
    return loaded


def cmd_redact(args):
    from argus_redact import redact, redact_pseudonym_llm
    from argus_redact.glue.redact import _parse_lang_arg

    text = _read_input(args.input)
    key_path = Path(args.key)

    profile = getattr(args, "profile", None)
    if args.seed:
        try:
            seed = int(args.seed)
        except ValueError:
            print("Error: --seed must be an integer", file=sys.stderr)
            sys.exit(2)
    else:
        seed = None
    if profile == "pseudonym-llm" and seed is None:
        print(
            "Error: --profile pseudonym-llm requires --seed <int> (realistic "
            "substitution needs a salt)",
            file=sys.stderr,
        )
        sys.exit(2)
    lang = _parse_lang_arg(args.lang)

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
        try:
            result = redact_pseudonym_llm(
                text,
                lang=lang,
                mode=args.mode,
                salt=seed,
                strategy_overrides=strategy_overrides,
                unified_prefix=unified_prefix,
            )
        except (ValueError, TypeError, FileNotFoundError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(3)
        _safe_write_key(str(key_path), result.key)
        payload = {
            "audit_text": result.audit_text,
            "downstream_text": result.downstream_text,
            "display_text": result.display_text,
            "key": result.key,
        }
        _write_output(json.dumps(payload, ensure_ascii=False, indent=2), args.output, mode=0o600)
        return

    # Standard path (default / pipl / gdpr / hipaa / config-only)
    existing_key = None
    if key_path.exists():
        existing_key = _load_key_file(key_path, args.key)

    try:
        redacted, key = redact(
            text,
            salt=seed,
            mode=args.mode,
            lang=lang,
            key=existing_key,
            config=args.config,
            profile=profile,
            unified_prefix=unified_prefix,
        )
    except (ValueError, TypeError, FileNotFoundError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(3)

    _safe_write_key(str(key_path), key)
    _write_output(redacted, args.output)


def cmd_restore(args):
    from argus_redact import restore

    key_path = Path(args.key)
    if not key_path.exists():
        print(f"Error: key file not found: {args.key}", file=sys.stderr)
        sys.exit(4)

    key = _load_key_file(key_path, args.key)

    aliases = None
    aliases_arg = getattr(args, "aliases", None)
    if aliases_arg:
        aliases = _load_aliases_file(Path(aliases_arg), aliases_arg)

    display_marker = getattr(args, "display_marker", None)

    text = _read_input(args.input)
    # guard=False: the CLI restores an operator-held key file locally, with no
    # per-call anchor — the explicit unguarded opt-out, not the fail-closed default.
    try:
        restored = restore(text, key, aliases=aliases, display_marker=display_marker, guard=False)
    except (ValueError, TypeError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(3)

    # Restored output is deanonymized PII — at least as sensitive as the key
    # file, so it gets the same 0o600 mode rather than the world-readable
    # 0o644 default.
    _write_output(restored, args.output, mode=0o600)


def cmd_info(args):
    import importlib.util

    from argus_redact import __version__
    from argus_redact.glue.redact import lang_capabilities

    caps = lang_capabilities()

    print(f"argus-redact v{__version__}")
    print()
    print("Languages:")
    for code, info in caps.items():
        ner_label = " + NER" if info["ner"] else ""
        print(f"  {code}  {info['name']:20s} regex ({info['patterns']} patterns){ner_label}")

    print()
    print("Layers:")
    print("  1 Pattern (regex)       ✓")
    # Same signal as the per-language "+ NER" labels above, so the Layer-2
    # line can never claim more than they do.
    ner_ok = any(info["ner"] for info in caps.values())
    print(f"  2 Entity (NER)          {'✓' if ner_ok else '✗'}")
    ollama_ok = importlib.util.find_spec("requests") is not None
    if ollama_ok:
        # `requests` importing does not mean Ollama is reachable — info never
        # probes the network, so say exactly what was checked.
        print("  3 Semantic (Ollama)     requests installed (endpoint not probed)")
    else:
        print("  3 Semantic (Ollama)     ✗ (requests not installed)")


def cmd_assess(args):
    from argus_redact import redact
    from argus_redact.glue.redact import _parse_lang_arg
    from argus_redact.pure.wire import common_report_fields, risk_payload

    text = _read_input(args.input)
    lang = _parse_lang_arg(args.lang)

    report = redact(
        text,
        mode=args.mode,
        lang=lang,
        report=True,
    )

    data = {
        # `summary` and `compliance` are the human-facing rollup this command has
        # always printed; they stay byte-identical. `risk` below is the full
        # projection, matching the HTTP and MCP faces.
        "summary": {
            "risk_score": report.risk.score,
            "risk_level": report.risk.level,
            "entities_detected": len(report.entities),
        },
        "compliance": {
            "pipl_articles": list(report.risk.pipl_articles),
        },
        "risk": risk_payload(report.risk),
        "entities": list(report.entities),
        "stats": report.stats,
        **common_report_fields(report),
    }
    output = json.dumps(data, ensure_ascii=False, indent=2)
    if args.output:
        # The report's entities[].original field carries plaintext PII spans
        # (see glue/redact.py entity_details) — at least as sensitive as the
        # restore output, so it gets the same 0o600 mode rather than the
        # world-readable 0o644 default.
        _safe_write_text(args.output, output, mode=0o600)
        print(f"Report saved to {args.output}", file=sys.stderr)
    else:
        print(output)


def cmd_setup(args):
    """Pre-download NER models for offline use."""
    from argus_redact.glue.redact import _parse_lang_arg

    # setup takes a single code without a comma (unlike redact/assess, which pass
    # the bare string straight through as `lang`) — wrap it so the loop below
    # iterates codes, not characters.
    parsed = _parse_lang_arg(args.lang)
    langs = parsed if isinstance(parsed, list) else [parsed]

    for code in langs:
        print(f"Setting up {code}...")
        try:
            if code == "zh":
                import hanlp

                print("  Downloading HanLP MSRA NER model...")
                hanlp.load(hanlp.pretrained.mtl.CLOSE_TOK_POS_NER_SRL_DEP_SDP_CON_ELECTRA_BASE_ZH)
                print("  Done.")
            elif code in ("en", "ja", "ko", "de", "uk", "in"):
                import spacy

                model_map = {
                    "en": "en_core_web_sm",
                    "ja": "ja_core_news_sm",
                    "ko": "ko_core_news_sm",
                    "de": "de_core_news_sm",
                    "uk": "en_core_web_sm",
                    "in": "xx_ent_wiki_sm",
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
    p_restore.add_argument(
        "--aliases",
        default=None,
        metavar="FILE",
        help=(
            "Aliases sidecar file: a JSON object {fake: [alternate-transliteration, ...]} "
            "mirroring restore(text, key, aliases=...) — lets an LLM's alternate "
            "transliteration of a fake (e.g. pinyin for a Chinese name) still restore."
        ),
    )
    p_restore.add_argument(
        "--display-marker",
        default=None,
        metavar="MARKER",
        help="Marker (e.g. 'ⓕ') to strip from the input before key lookup.",
    )
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
