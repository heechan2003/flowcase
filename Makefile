# Run from the repository root. `make sync` once, then `make check` before every commit.
VENV := $(CURDIR)/.venv/bin

.PHONY: sync check check-triage check-ioc-report check-demo demo

sync:
	uv sync --all-packages --all-extras

check: check-triage check-ioc-report check-demo

check-triage:
	cd packages/triage && $(VENV)/ruff format --check . && $(VENV)/ruff check . && $(VENV)/mypy \
		&& $(VENV)/python scripts/generate_detectors_doc.py --check \
		&& $(VENV)/python scripts/generate_ordering_doc.py --check \
		&& $(VENV)/python scripts/generate_parameters_doc.py --check \
		&& $(VENV)/pytest -q

check-ioc-report:
	cd packages/ioc-report && $(VENV)/ruff format --check . && $(VENV)/ruff check . && $(VENV)/mypy \
		&& $(VENV)/pytest -q

check-demo:
	$(VENV)/ruff format --check demo && $(VENV)/ruff check demo && $(VENV)/mypy

# The whole pipeline on the synthetic network, checked against demo/expected.json (about 10 minutes).
demo:
	$(VENV)/python demo/run.py
