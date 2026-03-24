.PHONY: install dev test cov lint build clean

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
