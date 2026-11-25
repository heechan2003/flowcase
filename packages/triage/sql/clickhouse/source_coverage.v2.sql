/*
Bounded coverage, temporal-grain, duplicate, and activity/rate reconciliation
for one UTC day. Long flows use only the approved positive-evidence population.
*/
WITH
    {start:DateTime64(6, 'UTC')} AS start_utc,
    {end:DateTime64(6, 'UTC')} AS end_utc
SELECT
    'activity_1m' AS source_key,
    count() AS row_count,
    uniqExact(toStartOfMinute(time)) AS bucket_count,
    countIf(time != toStartOfMinute(time)) AS invalid_grain_rows,
    sum(toUInt64(greatest(up_bytes, 0))) AS up_bytes,
    sum(toUInt64(greatest(down_bytes, 0))) AS down_bytes,
    uniqExact(tuple(
        time, client_ip, server_ip, server_port, transport_protocol, application,
        application_category, root_domain, sni, dns, asn
    )) AS unique_grain_rows
FROM flow.activity_1m
PREWHERE time >= start_utc AND time < end_utc
UNION ALL
SELECT
    'host_load_5m' AS source_key,
    count() AS row_count,
    uniqExact(toStartOfInterval(time, INTERVAL 5 MINUTE)) AS bucket_count,
    countIf(time != toStartOfInterval(time, INTERVAL 5 MINUTE)) AS invalid_grain_rows,
    sum(toUInt64(greatest(ifNull(up_bytes, 0), 0))) AS up_bytes,
    sum(toUInt64(greatest(ifNull(down_bytes, 0), 0))) AS down_bytes,
    toUInt64(0) AS unique_grain_rows
FROM flow.host_load_5m
PREWHERE time >= start_utc AND time < end_utc
UNION ALL
SELECT
    'dns_pairs' AS source_key,
    count() AS row_count,
    uniqExact(toStartOfHour(time)) AS bucket_count,
    countIf(time != toStartOfHour(time)) AS invalid_grain_rows,
    toUInt64(0) AS up_bytes,
    toUInt64(0) AS down_bytes,
    toUInt64(0) AS unique_grain_rows
FROM flow.dns_pairs
PREWHERE time >= start_utc AND time < end_utc
UNION ALL
SELECT
    'long_flows' AS source_key,
    count() AS row_count,
    toUInt64(0) AS bucket_count,
    countIf(finish < start OR duration_sec < 0) AS invalid_grain_rows,
    toUInt64(0) AS up_bytes,
    toUInt64(0) AS down_bytes,
    toUInt64(0) AS unique_grain_rows
FROM flow.long_flows
PREWHERE start >= start_utc AND start < end_utc
WHERE up_bytes + down_bytes >= 1000000
