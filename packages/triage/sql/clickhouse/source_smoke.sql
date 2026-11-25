/*
Metadata-only ClickHouse source smoke checks.

These queries do not read source-table rows or expose subscriber/client values.
*/

SELECT version() AS version, timezone() AS timezone, now() AS server_now;

SELECT database, name AS table, engine, total_rows
FROM system.tables
WHERE (database, name) IN (
    ('flow', 'activity_1m'),
    ('flow', 'host_load_5m'),
    ('flow', 'dns_pairs'),
    ('flow', 'long_flows')
)
ORDER BY database, name;

SELECT database, table, name, type,
       is_in_partition_key, is_in_primary_key, is_in_sorting_key
FROM system.columns
WHERE (database, table) IN (
    ('flow', 'activity_1m'),
    ('flow', 'host_load_5m'),
    ('flow', 'dns_pairs'),
    ('flow', 'long_flows')
)
ORDER BY database, table, position;
