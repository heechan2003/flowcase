/*
Transient interval groups for positive long-flow evidence. Exact intervals are
required for service assignment; individual source rows are never transferred.
*/
WITH
    {start:DateTime64(6, 'UTC')} AS start_utc,
    {end:DateTime64(6, 'UTC')} AS end_utc
SELECT
    toUnixTimestamp64Micro(start) AS start_epoch_us,
    toUnixTimestamp64Micro(finish) AS finish_epoch_us,
    client_ip,
    server_ip,
    protocol,
    server_port,
    count() AS large_flow_count,
    sum(up_bytes) AS large_flow_up_bytes,
    max(up_bytes + down_bytes) AS max_large_flow_bytes,
    max(greatest(duration_sec, 0)) AS max_large_flow_duration_sec
FROM flow.long_flows
PREWHERE start >= start_utc AND start < end_utc
WHERE up_bytes + down_bytes >= 1000000
GROUP BY start_epoch_us, finish_epoch_us, client_ip, server_ip, protocol, server_port

