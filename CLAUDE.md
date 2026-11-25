# flowcase: agent guide

A uv workspace with two packages. Each has its own `CLAUDE.md` with its rules; read the one for the package
you are changing.

- `packages/triage` (`network_behaviour`): daily behavioural triage.
- `packages/ioc-report` (`ioc_report`): IOC match case reports. Depends on `network_behaviour`.

Rules for the whole repository:

- **Synthetic data only.** Never add real traffic, logs, feeds, reports, addresses or names. Examples use
  documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), `10.0.0.0/8` for local hosts
  and `.test` names.
- **Code decides; the model writes.** Dispositions come from code. A model only writes prose, code checks
  every reply, and code's own text stands when a reply fails.
- **No host verdicts.** A case ends `review` or `explained`. Never label a host compromised, infected or
  benign.

Validate with `make check` from the repository root.
