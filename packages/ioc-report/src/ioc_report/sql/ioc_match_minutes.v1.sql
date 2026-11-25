/*
The minutes of one UTC day that touched a listed indicator: a listed address and port, or a listed
domain as the TLS name, the resolved name, the registered domain, or a parent of either name. One row
per minute grain; `ioc-match` writes each as a feed record. Only matched rows leave the source.
*/
SELECT
    time,
    client_ip,
    server_ip,
    server_port,
    transport_protocol,
    sni,
    dns,
    root_domain,
    coalesce(any_value(asn), '') AS asn,
    CAST(sum(up_bytes) AS BIGINT) AS sent_bytes,
    CAST(sum(down_bytes) AS BIGINT) AS received_bytes,
    CAST(sum(up_packets) AS BIGINT) AS sent_packets,
    CAST(sum(down_packets) AS BIGINT) AS received_packets,
    CAST(sum(flow_count) AS UBIGINT) AS flows
FROM flow.activity_1m
WHERE time >= {start:DateTime('UTC')} AND time < {end:DateTime('UTC')}
  AND (
    list_contains({endpoints:Array(String)}, concat(server_ip, ' ', CAST(server_port AS VARCHAR)))
    OR list_contains({names:Array(String)}, sni)
    OR list_contains({names:Array(String)}, dns)
    OR list_contains({names:Array(String)}, root_domain)
    OR len(list_filter({names:Array(String)},
                       name -> ends_with(sni, '.' || name) OR ends_with(dns, '.' || name))) > 0
  )
GROUP BY time, client_ip, server_ip, server_port, transport_protocol, sni, dns, root_domain
ORDER BY time, client_ip, server_ip, server_port, sni, dns
