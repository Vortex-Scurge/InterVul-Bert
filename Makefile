.PHONY: all setup install download inspect prepare train evaluate cross_eval demo test lint format clean

PYTHON ?= python3

all: install test demo

setup:
	$(PYTHON) -m venv .venv
	@echo "Virtual environment created. Activate with 'source .venv/bin/activate'"

install:
	pip install -r requirements.txt
	pip install -e .

download:
	$(PYTHON) scripts/download_data.py

inspect:
	$(PYTHON) scripts/inspect_dataset.py

prepare:
	$(PYTHON) scripts/prepare_dataset.py

train:
	$(PYTHON) scripts/train_codebert.py --config configs/codebert_baseline.yaml

evaluate:
	$(PYTHON) scripts/evaluate.py --config configs/codebert_baseline.yaml

cross_eval:
	$(PYTHON) scripts/cross_dataset_eval.py --config configs/cross_dataset.yaml

demo:
	$(PYTHON) scripts/generate_demo.py

report:
	$(PYTHON) scripts/generate_report.py

test:
	pytest tests/ -v

lint:
	ruff check .

format:
	black .

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} +
