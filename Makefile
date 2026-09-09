.PHONY: install dev test cov lint build clean release catalog catalog-check compliance-mappings compliance-mappings-check gen-risk-data gen-risk-data-check gen-confusables gen-confusables-check perf-update perf-check detection-update sync-docs-version sync-docs-version-check changelog-version-check tag-version-check mutants-core demo

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

compliance-mappings:
	PYTHONPATH=src python -m argus_redact.specs.gen_compliance_mappings > docs/compliance-mappings.md

compliance-mappings-check:
	@PYTHONPATH=src python -m argus_redact.specs.gen_compliance_mappings | diff -u docs/compliance-mappings.md - >/dev/null \
		|| (echo "docs/compliance-mappings.md is out of sync with the registry. Run: make compliance-mappings" && exit 1)
	@echo "docs/compliance-mappings.md is in sync"

gen-risk-data:
	PYTHONPATH=src python -m argus_redact.specs.gen_risk_data

gen-risk-data-check:
	@PYTHONPATH=src python -m argus_redact.specs.gen_risk_data --check

gen-confusables:
	PYTHONPATH=src python -m argus_redact.specs.gen_confusables

gen-confusables-check:
	@PYTHONPATH=src python -m argus_redact.specs.gen_confusables --check

# Must run under GitHub Actions (see the $$GITHUB_ACTIONS check below): the
# committed baseline's "platform" is "ubuntu-latest", and compare_baseline.py's
# provenance refusal (exit 2) now rejects any comparison where platform
# doesn't match exactly. A local run would stamp `uname -s` ("Darwin"/"Linux"),
# producing a baseline.json that every subsequent CI perf-check would then
# refuse to compare against — a local machine cannot produce a CI-valid
# baseline, so this refuses outright rather than writing one that looks fine
# and silently breaks the next gate run.
perf-update:
	@if [ -z "$$GITHUB_ACTIONS" ]; then \
		echo "ERROR: make perf-update must run in GitHub Actions (ubuntu-latest)." >&2; \
		echo "A local run would stamp this machine's platform (uname -s), which" >&2; \
		echo "compare_baseline.py's provenance check would then refuse against" >&2; \
		echo "every future ubuntu-latest CI measurement. Dispatch/re-run the perf.yml" >&2; \
		echo "job and commit the baseline it produces instead." >&2; \
		exit 1; \
	fi
	PYTHONPATH=src python tests/benchmark/run_perf_budget.py \
		--output tests/benchmark/baseline.json \
		--platform "ubuntu-latest" \
		--commit "$$(git rev-parse --short HEAD)"
	@echo "Baseline updated. Review and commit tests/benchmark/baseline.json"

# A local `make perf-check` is ADVISORY only. It stamps this machine's REAL
# platform (uname -s) and sets ARGUS_PERF_ADVISORY=1, so compare_baseline.py
# downgrades the inevitable platform mismatch (a laptop vs the ubuntu-latest
# baseline) to a printed advisory instead of the exit-2 refusal — rather than
# forging "ubuntu-latest" to sneak past the provenance gate. The timings come
# from different hardware than the baseline was measured on, so this is a smoke
# check; trust the perf.yml CI run for the real gate.
perf-check:
	@PYTHONPATH=src python tests/benchmark/run_perf_budget.py --output /tmp/argus-perf-current.json \
		--platform "$$(uname -s)" --commit "$$(git rev-parse --short HEAD)" && \
		ARGUS_PERF_ADVISORY=1 python tests/benchmark/compare_baseline.py /tmp/argus-perf-current.json tests/benchmark/baseline.json; \
		status=$$?; rm -f /tmp/argus-perf-current.json; exit $$status

# Refresh the FAST-mode detection recall/precision baseline (deterministic).
# Run only after an intentional detection change, then commit the diff. The gate
# itself is tests/benchmark/test_detection_baseline.py (runs in the normal suite).
detection-update:
	PYTHONPATH=src python tests/benchmark/update_detection_baseline.py

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

# Assert a release tag names the version pyproject declares. Called with the tag
# under test: `make tag-version-check TAG=v1.2.3`. Release CI runs this on the
# pushed tag so a mis-tagged release fails before anything is built or published.
# `TAG` is read from the recipe ENVIRONMENT (make places a command-line
# assignment there too), never interpolated as a make variable — a tag name is
# attacker-influenced and git permits `$` and backticks in refnames.
tag-version-check:
	@if [ -z "$$TAG" ]; then echo "ERROR: TAG is required, e.g. make tag-version-check TAG=v1.2.3" >&2; exit 1; fi; \
	PP=$$(awk -F'"' '/^version = "/ {print $$2; exit}' pyproject.toml); \
	if [ -z "$$PP" ]; then echo "ERROR: could not extract version from pyproject.toml" >&2; exit 1; fi; \
	if [ "$$TAG" != "v$$PP" ]; then \
		echo "Version mismatch: tag $$TAG, pyproject.toml = $$PP (expected tag v$$PP)" >&2; \
		exit 1; \
	fi; \
	echo "tag $$TAG matches pyproject.toml v$$PP"

# Run cargo-mutants over the security-critical Rust core (crypto / checksum /
# restore / seed / pseudonym) AND the Layer-1 detection core (normalize /
# redact_l1 / person_en / person_zh / patterns). The `--file` glob resolves
# against the workspace ROOT, so we cd into the crate and use the `**/file.rs`
# glob form.
#
# This list is intentionally NOT wider than the 11 files below: the run
# already takes ~305 minutes at this size, and mutants.yml's timeout-minutes
# (360) is GitHub Actions' effective per-job ceiling headroom, not a dial that
# can keep going up — adding more files here (e.g. fakers/reserved_range/
# merger/masks/streaming) without also sharding the file set (`cargo mutants
# --shard k/N` across a matrix) would just make the job time out dark again.
# Widening coverage is a tracked follow-up that needs the sharded-matrix
# rework, not a bigger --file list on its own.
mutants-core:
	cd crates/argus-redact-core && cargo mutants \
		--file '**/seed.rs' --file '**/validators.rs' --file '**/restore.rs' \
		--file '**/replace.rs' --file '**/shake_rng.rs' --file '**/pseudonym.rs' \
		--file '**/normalize.rs' --file '**/redact_l1.rs' --file '**/person_en.rs' \
		--file '**/person_zh.rs' --file '**/patterns.rs' \
		--timeout 120 -j 4

demo:
	@command -v wasm-pack >/dev/null || { echo "ERROR: wasm-pack not found (cargo install wasm-pack --locked)"; exit 1; }
	@command -v wasm-opt  >/dev/null || { echo "ERROR: wasm-opt not found (install binaryen)"; exit 1; }
	wasm-pack build crates/argus-redact-wasm --release --target web --out-dir $(CURDIR)/demo/pkg-web
	wasm-opt -Oz \
		--enable-bulk-memory \
		--enable-nontrapping-float-to-int \
		--enable-sign-ext \
		--enable-mutable-globals \
		--enable-reference-types \
		--enable-multivalue \
		demo/pkg-web/argus_redact_wasm_bg.wasm -o demo/pkg-web/argus_redact_wasm_bg.wasm
	@echo "demo/pkg-web built (gzipped wasm:" $$(gzip -c demo/pkg-web/argus_redact_wasm_bg.wasm | wc -c) "bytes)"
