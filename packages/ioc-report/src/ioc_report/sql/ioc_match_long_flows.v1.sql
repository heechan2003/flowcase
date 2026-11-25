/*
Long flows of the matched (host, server) pairs that overlap one UTC day. The bounds start a day early
so a flow already open at midnight is found. One row per flow, as the feed carries them.
*/
SELECT
    flow_id,
    start,
    finish,
    duration_sec,
    client_ip,
    server_ip,
    client_port,
    server_port,
    protocol,
    CAST(sum(up_bytes) AS UBIGINT) AS sent_bytes,
    CAST(sum(down_bytes) AS UBIGINT) AS received_bytes
FROM flow.long_flows
WHERE start >= {start:DateTime64(6, 'UTC')} AND start < {end:DateTime64(6, 'UTC')}
  AND up_bytes + down_bytes >= 1000000
  AND finish >= {day_start:DateTime64(6, 'UTC')}
  AND list_contains({pairs:Array(String)}, concat(client_ip, ' ', server_ip))
GROUP BY flow_id, start, finish, duration_sec, client_ip, server_ip, client_port, server_port,
    protocol
ORDER BY start, flow_id
