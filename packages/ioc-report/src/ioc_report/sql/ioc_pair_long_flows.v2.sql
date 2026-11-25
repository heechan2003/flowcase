/*
Long flows between the report's (host, flagged server) pairs over one bounded window, aggregated per
pair, server port, protocol and start day. No individual flow row is returned. The sums are aliased
away from the source column names, so the byte filter always reads the columns.
*/
SELECT
    client_ip,
    server_ip,
    server_port,
    protocol,
    CAST(start AS DATE) AS start_day,
    count(*) AS flows,
    max(greatest(duration_sec, 0)) AS longest_sec,
    count(*) FILTER (WHERE duration_sec >= {held_open_sec:Float64}) AS held_open_flows,
    CAST(sum(up_bytes) AS UBIGINT) AS flow_up_bytes,
    CAST(sum(down_bytes) AS UBIGINT) AS flow_down_bytes,
    epoch_us(min(start)) AS first_start_us,
    epoch_us(max(finish)) AS last_finish_us
FROM flow.long_flows
WHERE start >= {start:DateTime64(6, 'UTC')} AND start < {end:DateTime64(6, 'UTC')}
  AND up_bytes + down_bytes >= 1000000
  AND list_contains({pairs:Array(String)}, concat(client_ip, ' ', server_ip))
GROUP BY client_ip, server_ip, server_port, protocol, start_day
