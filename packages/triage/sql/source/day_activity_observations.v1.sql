/*
Transient five-minute activity observations for deterministic local normalization.
No row from this result is retained after day publication.
*/
SELECT
    (CAST(epoch(time) AS BIGINT) // 300) * 300 AS bucket_epoch,
    client_ip,
    server_ip,
    server_port,
    transport_protocol,
    root_domain,
    sni,
    dns,
    application,
    application_category,
    coalesce(asn, '') AS asn,
    CAST(sum(greatest(up_bytes, 0)) AS UBIGINT) AS up_bytes,
    CAST(sum(greatest(down_bytes, 0)) AS UBIGINT) AS down_bytes,
    CAST(sum(greatest(up_packets, 0)) AS UBIGINT) AS up_packets,
    CAST(sum(greatest(down_packets, 0)) AS UBIGINT) AS down_packets,
    CAST(sum(flow_count) AS UBIGINT) AS flow_count,
    list_sort(list(DISTINCT CAST((CAST(epoch(time) AS BIGINT) // 60) % 5 AS UTINYINT)))
        AS minute_offsets
FROM flow.activity_1m
WHERE time >= {start:DateTime('UTC')} AND time < {end:DateTime('UTC')}
GROUP BY ALL
