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
if [ "$MODE" = "integration" ]; then
    echo "=== test (all, including NER integration) ==="
    pytest -p no:recording -q
else
    echo "=== test (fast, skip NER integration) ==="
    pytest -p no:recording -q -m "not ner"
fi

echo ""
echo "=== build ==="
python -m build --wheel -q

echo ""
echo "✅ all good"
