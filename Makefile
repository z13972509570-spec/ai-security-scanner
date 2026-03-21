.PHONY: install test clean

install:
	pip install -e ".[dev]"

test:
	pytest tests/ -v

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

run:
	ai-scan scan ./tests/
