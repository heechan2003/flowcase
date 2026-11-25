# Case study: an Australian university campus network

This pipeline first ran on the campus network of an Australian university, reading a commercial flow
probe's tables through a read-only ClickHouse account. This document records what that deployment measured
and what it decided because of it. It reports aggregates only: no address, name, indicator or row from that
network is in this repository.

The code cites these sections as `CASE_STUDY §N`. The numbering is fixed, so a citation stays valid when a
section is rewritten.

> Status: the section headings are final; the measured values are being transcribed from the original
> deployment's records, counts only.

## Measured facts

### 1. Source shape and retention

How long each source table keeps detail, how its time buckets are laid out, and the parameter-size limit
the server enforces.

### 2. Population

How many addresses a day are observed, and how many carry a service row.

### 3. Activity shape: why the population is not a population of hosts

The unaddressed rows every address carries, and what that does to campus-wide rates and quantiles.

### 4. Peer-band occupancy

How many hosts fall in each behaviour band, which sets the minimum cohort.

### 5. Field availability

Which source columns are populated, and which are always empty.

### 6. Identity

What, if anything, gives continuity beyond the observed address.

### 7. Direction and role

What the source can say about who opened a session, and where it cannot.

### 8. Long-flow evidence

What the long-flow table holds, its size floor, and what a large flow looks like in retained history.

### 9. DNS coverage

Which clients the DNS table covers, and how DNS servers were told apart from clients.

### 10. Timing structure

Minute-grain contact timing, and how often a machine-regular schedule occurs.

### 11. Retained history and published output

What the 365-day store keeps, and what every published day depends on.

### 12. Implementation facts

Facts about the pipeline's own behaviour that shape how its output reads.

### 13. Shadow beacon profile

The beacon shape the shadow evaluation looks for, and how rare it is.

### 14. Address sharing

How many registered domains an address carries before it counts as shared hosting.

### 15. Service prevalence in retained history

How many addresses on how many days make a site established.

### 16. Registration age of the names E3 rests on

How recently the TLS names behind the E3 explanation were registered.

### 17. Serving addresses

Which campus addresses serve a named site to many outside networks.

### 18. Episodes at a served name

How triage episodes fall on sites campus hosts serve.

## Superseded values

Values an earlier detector generation was fitted on, kept so the reasoning behind a change can be followed.

## Evaluations

The evidence bundles behind each parameter, detector and ordering change (`packages/triage/docs/EVALUATION.md`),
summarised by what each measured and decided.
