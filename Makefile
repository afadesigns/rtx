PYTHON ?= python3
UV ?= uv
PACKAGE = rtx

.PHONY: install lint typecheck test fuzz sbom docs serve lock smoke clean

install:
	$(PYTHON) -m pip install --upgrade pip
	pip install .[dev]

lint:
	ruff check src tests
	semgrep --config p/ci

format:
	ruff format src tests
	black src tests

format-check:
	ruff format --check src tests
	black --check src tests

typecheck:
	mypy src

unit:
	pytest tests/unit

integration:
	pytest tests/integration

fuzz:
	pytest tests/fuzz

test:
	pytest

sbom:
	$(PYTHON) -m rtx.sbom_cli --output reports/sbom.json

lock:
	$(UV) pip compile pyproject.toml --output-file requirements.lock --generate-hashes

smoke:
	PYTHONPATH=src RTX_DISABLE_OSV=1 python -m rtx.cli diagnostics
	PYTHONPATH=src RTX_DISABLE_OSV=1 python -m rtx.cli scan --path examples/mixed --format table

clean:
	rm -rf dist build .pytest_cache .mypy_cache coverage.xml htmlcov reports
