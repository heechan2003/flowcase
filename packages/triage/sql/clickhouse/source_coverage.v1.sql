/*
Bounded aggregate-only coverage and temporal-grain check for one UTC day.
Long-flow rows are restricted to the approved positive-evidence population.
*/
WITH
    {start:DateTime64(6, 'UTC')} AS start_utc,
    {end:DateTime64(6, 'UTC')} AS end_utc
SELECT
    'activity_1m' AS source_key,
    count() AS row_count,
    uniqExact(toStartOfMinute(time)) AS bucket_count,
    countIf(time != toStartOfMinute(time)) AS invalid_grain_rows
FROM flow.activity_1m
PREWHERE time >= start_utc AND time < end_utc
UNION ALL
SELECT
    'host_load_5m' AS source_key,
    count() AS row_count,
    uniqExact(toStartOfInterval(time, INTERVAL 5 MINUTE)) AS bucket_count,
    countIf(time != toStartOfInterval(time, INTERVAL 5 MINUTE)) AS invalid_grain_rows
FROM flow.host_load_5m
PREWHERE time >= start_utc AND time < end_utc
UNION ALL
SELECT
    'dns_pairs' AS source_key,
    count() AS row_count,
    uniqExact(toStartOfHour(time)) AS bucket_count,
    countIf(time != toStartOfHour(time)) AS invalid_grain_rows
FROM flow.dns_pairs
PREWHERE time >= start_utc AND time < end_utc
UNION ALL
SELECT
    'long_flows' AS source_key,
    count() AS row_count,
    toUInt64(0) AS bucket_count,
    countIf(finish < start OR duration_sec < 0) AS invalid_grain_rows
FROM flow.long_flows
PREWHERE start >= start_utc AND start < end_utc
WHERE up_bytes + down_bytes >= 1000000
