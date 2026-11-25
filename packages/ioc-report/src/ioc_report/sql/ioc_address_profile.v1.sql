/*
How shared each flagged server address was over one UTC day: the campus hosts that exchanged traffic
with it, in either direction, and the registered domains it carried for them. This is the quantity
CASE_STUDY §14 measures campus-wide, under the same flow_count > 0 condition. Counts per flagged address only; no client or
domain leaves the server.
*/
SELECT
    server_ip,
    uniqExact(client_ip) AS campus_clients,
    uniqExactIf(root_domain, root_domain != '' AND NOT has({ech_names:Array(String)}, root_domain))
        AS registered_domains,
    uniqExactIf(client_ip, has({ech_names:Array(String)}, sni)) AS ech_clients,
    uniqExactIf(client_ip, transport_protocol = 17) AS udp_clients,
    arraySort(groupUniqArray(10)(ifNull(asn, ''))) AS asns
FROM flow.activity_1m
PREWHERE time >= {start:DateTime('UTC')} AND time < {end:DateTime('UTC')}
WHERE has({servers:Array(String)}, server_ip) AND flow_count > 0
GROUP BY server_ip
