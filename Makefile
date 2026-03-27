.PHONY: install dev test cov lint build clean release

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
	@VERSION=$$(python -c "from src.argus_redact import __version__; print(__version__)"); \
	echo "Releasing v$$VERSION"; \
	git tag "v$$VERSION" && \
	git push origin main --tags && \
	echo "Tag v$$VERSION pushed — GitHub Actions will handle PyPI + GitHub Release + HF Space"
