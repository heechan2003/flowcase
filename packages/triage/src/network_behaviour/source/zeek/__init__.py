"""Zeek logs in, the four source tables out.

`load_day` reads Zeek's conn, ssl, dns and (optional) weird logs for one UTC day and writes
`flow.activity_1m`, `flow.host_load_5m`, `flow.dns_pairs` and `flow.long_flows` into the source
DuckDB file. Everything downstream (contracts, readers, detectors, IOC rules) reads those tables and
never sees a Zeek field. The mapping rules are in `docs/SOURCE_CONTRACT.md`.
"""

from network_behaviour.source.zeek.loader import LoadReport, ZeekLoadError, load_day

__all__ = ["LoadReport", "ZeekLoadError", "load_day"]
