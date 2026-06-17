import ast, pathlib
PURE = pathlib.Path("src/argus_redact/pure")

def test_no_pure_module_has_no_core_redaction_fallback():
    offenders = []
    for p in sorted(PURE.glob("*.py")):
        tree = ast.parse(p.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                test_src = ast.unparse(node.test)
                # An `if HAS_CORE:` with a non-empty `else:` arm = a dual-definition
                # fallback (dead, since _core is mandatory). Bare `X if HAS_CORE else None`
                # ternaries are NOT ast.If and are fine.
                if test_src.strip() == "HAS_CORE" and node.orelse:
                    offenders.append(f"{p.name}:{node.lineno} if HAS_CORE/else fallback")
                if test_src.strip() == "not HAS_CORE":
                    offenders.append(f"{p.name}:{node.lineno} if not HAS_CORE")
    assert not offenders, f"dead no-core fallback branches remain: {offenders}"
