#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-default}"

echo "=== format ==="
ruff check --fix src/ tests/
ruff format src/ tests/

echo ""
echo "=== lint ==="
ruff check src/ tests/
ruff format --check src/ tests/

echo ""
case "$MODE" in
    integration)
        echo "=== test (all, including NER + semantic) ==="
        pytest -p no:recording -q
        ;;
    semantic)
        echo "=== test (semantic only) ==="
        pytest -p no:recording -q -m "semantic"
        ;;
    *)
        echo "=== test (fast, skip NER + semantic) ==="
        pytest -p no:recording -q -m "not ner and not semantic and not slow"
        ;;
esac

echo ""
echo "=== build ==="
python -m build --wheel -q

echo ""
echo "✅ all good"
