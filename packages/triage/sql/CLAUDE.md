# SQL Guidance

This file applies to `sql/` and overrides broader guidance only where it is more specific.

## Source SQL (DuckDB)

- Use only `flow.activity_1m`, `flow.host_load_5m`, `flow.dns_pairs`, and `flow.long_flows` unless
  `docs/PRODUCT_CONTRACT.md` changes.
- Keep production source SQL read-only. Allow `SELECT`, `WITH`, and metadata inspection only.
- Require typed UTC start/end parameters for every data query and use half-open ranges `[start, end)`.
- Select explicit columns. Do not use `SELECT *`.
- Aggregate in the query before transfer; never download a raw day.
- Keep the typed placeholders (`{start:DateTime('UTC')}`): `validate_sql` checks them, and the client
  binds each as a DuckDB parameter of the matching type. Metadata queries read `information_schema` only.
- Normalize additive counters defensively and preserve duplicate-handling semantics.
- Use `transport_protocol` for TCP/UDP semantics; zero protocol/port values mean unknown.
- Apply `up_bytes + down_bytes >= 1000000` explicitly to long-flow evidence.
- Match service-level long flows by client, endpoint, available protocol/port, and actual interval overlap.
- Batch candidate lookups; never render one query per client or interpolate untrusted values into SQL.
- Return aggregate evidence from validation queries, not raw identifiers or endpoint rows.

## DuckDB Migrations

- Keep migrations ordered, immutable after release, and safe for both fresh and upgraded databases.
- Preserve the two retained analytical grains exactly as documented.
- Add constraints or validation queries for uniqueness, non-negative measures, and valid bitmap width.
- Make day publication transactional; migrations must not blur staging and published history.
- Do not introduce retained detail tables as a migration shortcut.

## Verification

Any SQL change requires `validate_sql` to pass (`tests/unit/source/test_sql.py` loads every file in
`sql/source/`) and a synthetic integration test against a loaded DuckDB source. There is no live contract
test to opt into: the source is the DuckDB file `load-zeek` writes.
