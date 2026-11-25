/*
Long flows between the report's (host, flagged server) pairs over one bounded window, aggregated per
pair, server port, protocol and start day. No individual flow row is returned. The sums are aliased
away from the source column names: an alias equal to a column would shadow it in WHERE and turn the
byte filter into an aggregate.
*/
SELECT
    client_ip,
    server_ip,
    server_port,
    protocol,
    toDate(start) AS start_day,
    count() AS flows,
    max(greatest(duration_sec, 0)) AS longest_sec,
    countIf(duration_sec >= {held_open_sec:Float64}) AS held_open_flows,
    sum(up_bytes) AS flow_up_bytes,
    sum(down_bytes) AS flow_down_bytes,
    toUnixTimestamp64Micro(min(start)) AS first_start_us,
    toUnixTimestamp64Micro(max(finish)) AS last_finish_us
FROM flow.long_flows
PREWHERE start >= {start:DateTime64(6, 'UTC')} AND start < {end:DateTime64(6, 'UTC')}
WHERE up_bytes + down_bytes >= 1000000
    AND has({pairs:Array(String)}, concat(client_ip, ' ', server_ip))
GROUP BY client_ip, server_ip, server_port, protocol, start_day
