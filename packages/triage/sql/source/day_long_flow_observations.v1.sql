/*
Transient interval groups for positive long-flow evidence. Exact intervals are
required for service assignment; individual source rows are never transferred.
*/
SELECT
    epoch_us(start) AS start_epoch_us,
    epoch_us(finish) AS finish_epoch_us,
    client_ip,
    server_ip,
    protocol,
    server_port,
    count(*) AS large_flow_count,
    CAST(sum(up_bytes) AS UBIGINT) AS large_flow_up_bytes,
    max(up_bytes + down_bytes) AS max_large_flow_bytes,
    max(greatest(duration_sec, 0)) AS max_large_flow_duration_sec
FROM flow.long_flows
WHERE start >= {start:DateTime64(6, 'UTC')} AND start < {end:DateTime64(6, 'UTC')}
  AND up_bytes + down_bytes >= 1000000
GROUP BY ALL
