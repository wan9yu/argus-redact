.PHONY: install dev test cov lint build clean release catalog catalog-check gen-risk-data gen-risk-data-check gen-confusables gen-confusables-check perf-update perf-check sync-docs-version sync-docs-version-check changelog-version-check mutants-core

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

gen-risk-data:
	PYTHONPATH=src python -m argus_redact.specs.gen_risk_data

gen-risk-data-check:
	@PYTHONPATH=src python -m argus_redact.specs.gen_risk_data --check

gen-confusables:
	PYTHONPATH=src python -m argus_redact.specs.gen_confusables

gen-confusables-check:
	@PYTHONPATH=src python -m argus_redact.specs.gen_confusables --check

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

sync-docs-version:
	python scripts/sync_docs_version.py

sync-docs-version-check:
	python scripts/sync_docs_version.py --check

# Assert the top CHANGELOG entry matches pyproject's version, so a release
# cannot ship a stale changelog. (Until the version bump lands, a deliberate
# CHANGELOG-ahead-of-pyproject state will fail here — that is expected.)
changelog-version-check:
	@CL=$$(grep -m1 -oE '^## v[0-9]+\.[0-9]+\.[0-9]+' CHANGELOG.md | sed -E 's/^## v//'); \
	PP=$$(awk -F'"' '/^version = "/ {print $$2; exit}' pyproject.toml); \
	if [ -z "$$CL" ]; then echo "ERROR: no '## vX.Y.Z' heading found in CHANGELOG.md" >&2; exit 1; fi; \
	if [ -z "$$PP" ]; then echo "ERROR: could not extract version from pyproject.toml" >&2; exit 1; fi; \
	if [ "$$CL" != "$$PP" ]; then \
		echo "Version mismatch: CHANGELOG.md top = $$CL, pyproject.toml = $$PP" >&2; \
		echo "Bump pyproject.toml (and run make sync-docs-version) or add the CHANGELOG entry." >&2; \
		exit 1; \
	fi; \
	echo "CHANGELOG.md and pyproject.toml agree on v$$PP"

# Run cargo-mutants over the security-critical Rust core (crypto / checksum /
# restore / seed / pseudonym) AND the Layer-1 detection core (normalize /
# redact_l1 / person_en / person_zh / patterns). The `--file` glob resolves
# against the workspace ROOT, so we cd into the crate and use the `**/file.rs`
# glob form.
mutants-core:
	cd crates/argus-redact-core && cargo mutants \
		--file '**/seed.rs' --file '**/validators.rs' --file '**/restore.rs' \
		--file '**/replace.rs' --file '**/shake_rng.rs' --file '**/pseudonym.rs' \
		--file '**/normalize.rs' --file '**/redact_l1.rs' --file '**/person_en.rs' \
		--file '**/person_zh.rs' --file '**/patterns.rs' \
		--timeout 120 -j 4
