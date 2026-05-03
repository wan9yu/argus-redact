.PHONY: install dev test cov lint build clean release catalog catalog-check perf-update perf-check

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

test:
	pytest -p no:recording

cov:
	pytest --cov=argus_redact --cov-report=term --cov-report=html -p no:recording

lint:
	ruff check src/ tests/
	ruff format --check src/ tests/

format:
	ruff format src/ tests/

build:
	python -m build

clean:
	rm -rf dist/ build/ *.egg-info src/*.egg-info
	rm -rf .pytest_cache htmlcov .coverage coverage.xml
	find . -type d -name __pycache__ -exec rm -rf {} +

release:
	@VERSION=$$(awk -F'"' '/^version = "/ {print $$2; exit}' pyproject.toml); \
	if [ -z "$$VERSION" ]; then echo "ERROR: could not extract version from pyproject.toml" >&2; exit 1; fi; \
	echo "Releasing v$$VERSION"; \
	git tag "v$$VERSION" && \
	git push origin main --tags && \
	echo "Tag v$$VERSION pushed — GitHub Actions will handle PyPI + GitHub Release + HF Space"

catalog:
	PYTHONPATH=src python -m argus_redact.specs.gen_catalog > docs/pii-types.md

catalog-check:
	@PYTHONPATH=src python -m argus_redact.specs.gen_catalog | diff -u docs/pii-types.md - >/dev/null \
		|| (echo "docs/pii-types.md is out of sync with the registry. Run: make catalog" && exit 1)
	@echo "docs/pii-types.md is in sync"

perf-update:
	PYTHONPATH=src python tests/benchmark/run_perf_budget.py \
		--output tests/benchmark/baseline.json \
		--platform "$$(uname -s)" \
		--commit "$$(git rev-parse --short HEAD)"
	@echo "Baseline updated. Review and commit tests/benchmark/baseline.json"

perf-check:
	@PYTHONPATH=src python tests/benchmark/run_perf_budget.py --output /tmp/argus-perf-current.json && \
		python tests/benchmark/compare_baseline.py /tmp/argus-perf-current.json tests/benchmark/baseline.json; \
		status=$$?; rm -f /tmp/argus-perf-current.json; exit $$status
