/*
How shared each flagged server address was over one UTC day: the campus hosts that exchanged traffic
with it, in either direction, and the registered domains it carried for them. This is the quantity
CASE_STUDY §14 measures campus-wide, under the same flow_count > 0 condition. Counts per flagged
address only; no client or domain leaves the server.
*/
SELECT
    server_ip,
    count(DISTINCT client_ip) AS campus_clients,
    count(DISTINCT root_domain) FILTER (
        WHERE root_domain != '' AND NOT list_contains({ech_names:Array(String)}, root_domain)
    ) AS registered_domains,
    count(DISTINCT client_ip) FILTER (WHERE list_contains({ech_names:Array(String)}, sni))
        AS ech_clients,
    count(DISTINCT client_ip) FILTER (WHERE transport_protocol = 17) AS udp_clients,
    list_sort(list(DISTINCT coalesce(asn, '')))[1:10] AS asns
FROM flow.activity_1m
WHERE time >= {start:DateTime('UTC')} AND time < {end:DateTime('UTC')}
  AND list_contains({servers:Array(String)}, server_ip) AND flow_count > 0
GROUP BY server_ip
