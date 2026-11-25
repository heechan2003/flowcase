# Run from the repository root. `make sync` once, then `make check` before every commit.
VENV := $(CURDIR)/.venv/bin

.PHONY: sync check check-triage check-ioc-report

sync:
	uv sync --all-packages --all-extras

check: check-triage check-ioc-report

check-triage:
	cd packages/triage && $(VENV)/ruff format --check . && $(VENV)/ruff check . && $(VENV)/mypy \
		&& $(VENV)/python scripts/generate_detectors_doc.py --check \
		&& $(VENV)/python scripts/generate_ordering_doc.py --check \
		&& $(VENV)/python scripts/generate_parameters_doc.py --check \
		&& $(VENV)/pytest -q

check-ioc-report:
	cd packages/ioc-report && $(VENV)/ruff format --check . && $(VENV)/ruff check . && $(VENV)/mypy \
		&& $(VENV)/pytest -q
