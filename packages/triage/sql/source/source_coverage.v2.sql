/*
Bounded coverage, temporal-grain, duplicate, and activity/rate reconciliation
for one UTC day. Long flows use only the approved positive-evidence population.
*/
SELECT
    'activity_1m' AS source_key,
    count(*) AS row_count,
    count(DISTINCT epoch_us(time) // 60000000) AS bucket_count,
    count(*) FILTER (WHERE epoch_us(time) % 60000000 != 0) AS invalid_grain_rows,
    CAST(sum(greatest(up_bytes, 0)) AS UBIGINT) AS up_bytes,
    CAST(sum(greatest(down_bytes, 0)) AS UBIGINT) AS down_bytes,
    count(DISTINCT (
        time, client_ip, server_ip, server_port, transport_protocol, application,
        application_category, root_domain, sni, dns, asn
    )) AS unique_grain_rows
FROM flow.activity_1m
WHERE time >= {start:DateTime64(6, 'UTC')} AND time < {end:DateTime64(6, 'UTC')}
UNION ALL
SELECT
    'host_load_5m' AS source_key,
    count(*) AS row_count,
    count(DISTINCT epoch_us(time) // 300000000) AS bucket_count,
    count(*) FILTER (WHERE epoch_us(time) % 300000000 != 0) AS invalid_grain_rows,
    CAST(sum(greatest(coalesce(up_bytes, 0), 0)) AS UBIGINT) AS up_bytes,
    CAST(sum(greatest(coalesce(down_bytes, 0), 0)) AS UBIGINT) AS down_bytes,
    CAST(0 AS BIGINT) AS unique_grain_rows
FROM flow.host_load_5m
WHERE time >= {start:DateTime64(6, 'UTC')} AND time < {end:DateTime64(6, 'UTC')}
UNION ALL
SELECT
    'dns_pairs' AS source_key,
    count(*) AS row_count,
    count(DISTINCT epoch_us(time) // 3600000000) AS bucket_count,
    count(*) FILTER (WHERE epoch_us(time) % 3600000000 != 0) AS invalid_grain_rows,
    CAST(0 AS UBIGINT) AS up_bytes,
    CAST(0 AS UBIGINT) AS down_bytes,
    CAST(0 AS BIGINT) AS unique_grain_rows
FROM flow.dns_pairs
WHERE time >= {start:DateTime64(6, 'UTC')} AND time < {end:DateTime64(6, 'UTC')}
UNION ALL
SELECT
    'long_flows' AS source_key,
    count(*) AS row_count,
    CAST(0 AS BIGINT) AS bucket_count,
    count(*) FILTER (WHERE finish < start OR duration_sec < 0) AS invalid_grain_rows,
    CAST(0 AS UBIGINT) AS up_bytes,
    CAST(0 AS UBIGINT) AS down_bytes,
    CAST(0 AS BIGINT) AS unique_grain_rows
FROM flow.long_flows
WHERE start >= {start:DateTime64(6, 'UTC')} AND start < {end:DateTime64(6, 'UTC')}
  AND up_bytes + down_bytes >= 1000000
