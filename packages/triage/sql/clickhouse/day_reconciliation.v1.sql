/* Versioned activity-to-rate additive-byte reconciliation for one UTC day. */
WITH
    {start:DateTime('UTC')} AS start_utc,
    {end:DateTime('UTC')} AS end_utc
SELECT
    'activity' AS source_key,
    sum(toUInt64(greatest(up_bytes, 0))) AS up_bytes,
    sum(toUInt64(greatest(down_bytes, 0))) AS down_bytes,
    count() AS row_count,
    uniqExact(tuple(
        time, client_ip, server_ip, server_port, transport_protocol, application,
        application_category, root_domain, sni, dns, asn
    )) AS unique_grain_rows
FROM flow.activity_1m
PREWHERE time >= start_utc AND time < end_utc
UNION ALL
SELECT
    'rate' AS source_key,
    sum(toUInt64(greatest(ifNull(up_bytes, 0), 0))) AS up_bytes,
    sum(toUInt64(greatest(ifNull(down_bytes, 0), 0))) AS down_bytes,
    toUInt64(0) AS row_count,
    toUInt64(0) AS unique_grain_rows
FROM flow.host_load_5m
PREWHERE time >= start_utc AND time < end_utc
