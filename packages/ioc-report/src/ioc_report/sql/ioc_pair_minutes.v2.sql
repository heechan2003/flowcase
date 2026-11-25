/*
Minute contact between the report's (host, flagged server) pairs over one UTC day, split by what the
contact was: transport, port and the names the source attached to it. Only case pairs are returned.
The minute list is the pair's own active minutes, so timing is measured without a second query.
Aliases avoid the source's column names, so filters always read the columns.
*/
SELECT
    client_ip,
    server_ip,
    transport_protocol,
    server_port,
    sni,
    root_domain,
    dns,
    coalesce(any_value(asn), '') AS asn,
    count(DISTINCT time) AS active_minutes,
    list_sort(list(DISTINCT CAST(CAST(epoch(time) AS BIGINT) // 60 AS UINTEGER))) AS minute_epochs,
    CAST(sum(greatest(up_bytes, 0)) AS UBIGINT) AS sent_bytes,
    CAST(sum(greatest(down_bytes, 0)) AS UBIGINT) AS received_bytes,
    CAST(sum(flow_count) AS UBIGINT) AS flows
FROM flow.activity_1m
WHERE time >= {start:DateTime('UTC')} AND time < {end:DateTime('UTC')}
  AND list_contains({servers:Array(String)}, server_ip)
  AND list_contains({pairs:Array(String)}, concat(client_ip, ' ', server_ip))
GROUP BY client_ip, server_ip, transport_protocol, server_port, sni, root_domain, dns
