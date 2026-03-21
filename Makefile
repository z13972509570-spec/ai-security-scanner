.PHONY: install test lint format clean

install:
	pip install -e .

test:
	pytest tests/ -v --cov=src

lint:
	ruff check src/
	black --check src/
	mypy src/

format:
	black src/
	ruff check --fix src/

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	rm -rf build/ dist/ *.egg-info/
