.PHONY: install dev test lint fmt demo eval dataset suite serve docker clean

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

test:
	pytest -q

lint:
	ruff check .

fmt:
	ruff check . --fix
	ruff format .

demo:
	python -m agentshield.demo

dataset:
	python scripts/build_training_set.py

suite:
	python evals/build_suite.py

eval:
	python evals/run_eval.py

serve:
	uvicorn agentshield.api:app --host 127.0.0.1 --port 8000

docker:
	docker build -t agentshield:latest .

clean:
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
