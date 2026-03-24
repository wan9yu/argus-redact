#!/usr/bin/env bash
set -euo pipefail

echo "=== lint ==="
ruff check src/ tests/
ruff format --check src/ tests/

echo ""
echo "=== test ==="
pytest -p no:recording -q

echo ""
echo "=== build ==="
python -m build --wheel -q

echo ""
echo "✅ all good"
