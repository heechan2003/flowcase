# Runbook — backup and restore

The product database holds 365 days of retained history and every published stream. A day can be
re-derived only while the source holds its detail: the original source kept about fifteen days
(`CASE_STUDY` §1), and here a day stays while it is loaded, unless `NETWORK_BEHAVIOUR_SOURCE_DETAIL_DAYS`
sets a retention. Anything the source no longer holds exists **only** here. A lost database is a lost
year, not a re-runnable job.

## Backup

```shell
network-behaviour backup --output /separate-storage/network_behaviour.duckdb
```

Refuses a target that already exists. Otherwise it checkpoints, copies to a partial file, verifies
schema, history and feed readability, and renames the copy into place. A backup that fails
verification is not written. To refresh a backup, write a new path, then remove the old one.

**The output path must be outside the 60 GiB writable product volume.** A backup beside the database
protects against corruption and nothing else — not a full volume, which is the failure the storage
ceiling exists to anticipate, and not loss of the volume itself.

Cadence follows what is irrecoverable. Every day the source still holds can be re-derived; every
other day cannot. Back up at least as often as the source's retention, or a failure loses history no
amount of re-running can rebuild.

## Restore

```shell
network-behaviour restore \
  --input  /separate-storage/network_behaviour.duckdb \
  --output data/restored-network_behaviour.duckdb
```

Writes a **new** database, verifies it, applies forward migrations, and checkpoints. It refuses to
overwrite an existing output — deliberately, so a restore cannot silently destroy the database it
was meant to rescue. To put a restored database into service, verify it first and then move it into
place yourself.

After restoring:

```shell
NETWORK_BEHAVIOUR_DUCKDB_PATH=data/restored-network_behaviour.duckdb network-behaviour storage-report
NETWORK_BEHAVIOUR_DUCKDB_PATH=data/restored-network_behaviour.duckdb \
  network-behaviour run-day --day <a-published-day> --dry-run
```

Both read `NETWORK_BEHAVIOUR_DUCKDB_PATH`, so without the prefix they check the production database,
not the restored one.

The dry run should report `already_published` for a day the backup contained. If it reports `ready`,
the restore is missing published state and is not equivalent to the original.

## Storage pressure

```shell
network-behaviour storage-report
```

Alerts at the configured threshold and fails closed before projected retained growth reaches the
ceiling. **Publication never drops episodes to fit** — completeness is a Tier 0 invariant, so the
system stops rather than silently publishing less.

When approaching the limit, in order:

1. Verify a backup exists off-volume and passes verification.
2. Confirm 365-day retention pruning has actually run; retained history is bounded by design.
3. Move generated streams (`candidate-feeds/`) off the volume. They are data, reproducible from
   storage, and not part of the database.

Do not raise the ceiling to get past a failing run. The guard exists because a full volume during
publication risks a partially written database, which is a worse outcome than a refused day.

## Verifying a backup is real

A backup nobody has restored is a hypothesis. Periodically restore to a scratch path, run the two
checks above, and delete the scratch copy. The restore path applies forward migrations, so this also
proves the backup is still readable by the *current* build — which is the property that quietly
lapses over a year of schema changes.
