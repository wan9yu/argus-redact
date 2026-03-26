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
    bench)
        echo "=== benchmark ==="
        LANG="${2:-}"
        LIMIT="${3:-1000}"
        if [ -n "$LANG" ]; then
            python -m benchmarks all --mode fast --lang "$LANG" --limit "$LIMIT" --save
        else
            python -m benchmarks all --mode fast --limit "$LIMIT" --save
        fi
        echo ""
        echo "✅ benchmark complete"
        exit 0
        ;;
    deploy)
        echo "=== test (fast) ==="
        pytest -p no:recording -q -m "not ner and not semantic and not slow"
        echo ""
        echo "=== build ==="
        python -m build --wheel -q
        echo ""
        echo "=== deploy HF Space ==="
        python -c "
from huggingface_hub import HfApi
HfApi().upload_folder(folder_path='demo', repo_id='wan9yu/argus-redact', repo_type='space')
print('  HF Space uploaded')
"
        echo ""
        echo "✅ built + deployed"
        exit 0
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
