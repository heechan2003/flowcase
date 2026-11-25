/*
Minute contact between the report's (host, flagged server) pairs over one UTC day, split by what the
contact was: transport, port and the names the source attached to it. Only case pairs are returned.
The minute list is the pair's own active minutes, so timing is measured without a second query.
Aliases avoid the source's column names, which an alias would shadow in WHERE.
*/
SELECT
    client_ip,
    server_ip,
    transport_protocol,
    server_port,
    sni,
    root_domain,
    dns,
    ifNull(any(asn), '') AS asn,
    uniqExact(time) AS active_minutes,
    arraySort(groupUniqArray(toUInt32(intDiv(toUnixTimestamp(time), 60)))) AS minute_epochs,
    sum(toUInt64(greatest(up_bytes, 0))) AS sent_bytes,
    sum(toUInt64(greatest(down_bytes, 0))) AS received_bytes,
    sum(flow_count) AS flows
FROM flow.activity_1m
PREWHERE time >= {start:DateTime('UTC')} AND time < {end:DateTime('UTC')}
WHERE has({servers:Array(String)}, server_ip)
    AND has({pairs:Array(String)}, concat(client_ip, ' ', server_ip))
GROUP BY client_ip, server_ip, transport_protocol, server_port, sni, root_domain, dns
