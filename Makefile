# Run from the repository root. `make sync` once, then `make check` before every commit.
VENV := $(CURDIR)/.venv/bin

.PHONY: sync check check-triage check-ioc-report check-scripts check-leaks demo zeek-fixture

sync:
	uv sync --all-packages --all-extras

check: check-triage check-ioc-report check-scripts check-leaks

check-triage:
	cd packages/triage && $(VENV)/ruff format --check . && $(VENV)/ruff check . && $(VENV)/mypy \
		&& $(VENV)/python scripts/generate_detectors_doc.py --check \
		&& $(VENV)/python scripts/generate_ordering_doc.py --check \
		&& $(VENV)/python scripts/generate_parameters_doc.py --check \
		&& $(VENV)/pytest -q

check-ioc-report:
	cd packages/ioc-report && $(VENV)/ruff format --check . && $(VENV)/ruff check . && $(VENV)/mypy \
		&& $(VENV)/pytest -q

# The demo, fixture and repository scripts, with the root pyproject's settings.
check-scripts:
	$(VENV)/ruff format --check demo fixtures scripts && $(VENV)/ruff check demo fixtures scripts \
		&& $(VENV)/mypy

# No routable address and no data file outside fixtures/zeek-real (scripts/check_leaks.py).
check-leaks:
	$(VENV)/python scripts/check_leaks.py

# The whole pipeline on the synthetic network, checked against demo/expected.json (about 10 minutes).
demo:
	$(VENV)/python demo/run.py

# Rebuild fixtures/zeek-real: the capture (scapy) and the logs real Zeek writes from it (Docker).
# Zeek counts the documentation ranges as private address space, and private space as local, so the
# site config turns that off and names the local hosts' range instead.
ZEEK_IMAGE := zeek/zeek:9.0.1
ZEEK_SITE := redef Site::private_address_space_is_local = F; redef Site::local_nets += { 10.0.0.0/8 };
ZEEK_REAL := $(CURDIR)/fixtures/zeek-real
ZEEK_RUN = docker run --rm -v $(ZEEK_REAL):/work -w /work/logs/$(1) $(ZEEK_IMAGE) \
	zeek -D -C -r /work/trace.pcap $(2) -e '$(ZEEK_SITE)'

zeek-fixture:
	uv run --script $(ZEEK_REAL)/make_pcap.py
	rm -rf $(ZEEK_REAL)/logs && mkdir -p $(ZEEK_REAL)/logs/json $(ZEEK_REAL)/logs/json-iso \
		$(ZEEK_REAL)/logs/tsv
	$(call ZEEK_RUN,json,LogAscii::use_json=T)
	$(call ZEEK_RUN,json-iso,LogAscii::use_json=T LogAscii::json_timestamps=JSON::TS_ISO8601)
	$(call ZEEK_RUN,tsv,)
	rm $(ZEEK_REAL)/logs/*/packet_filter.log  # only Zeek's start time: wall clock, not traffic
