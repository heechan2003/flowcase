/*
Transient five-minute activity observations for deterministic local normalization.
No row from this result is retained after day publication.
*/
WITH
    {start:DateTime('UTC')} AS start_utc,
    {end:DateTime('UTC')} AS end_utc
SELECT
    toUnixTimestamp(toStartOfInterval(time, INTERVAL 5 MINUTE)) AS bucket_epoch,
    client_ip,
    server_ip,
    server_port,
    transport_protocol,
    root_domain,
    sni,
    dns,
    application,
    application_category,
    ifNull(asn, '') AS asn,
    sum(toUInt64(greatest(up_bytes, 0))) AS up_bytes,
    sum(toUInt64(greatest(down_bytes, 0))) AS down_bytes,
    sum(toUInt64(greatest(up_packets, 0))) AS up_packets,
    sum(toUInt64(greatest(down_packets, 0))) AS down_packets,
    sum(flow_count) AS flow_count,
    groupUniqArray(toUInt8(toMinute(time) % 5)) AS minute_offsets
FROM flow.activity_1m
PREWHERE time >= start_utc AND time < end_utc
GROUP BY
    bucket_epoch,
    client_ip,
    server_ip,
    server_port,
    transport_protocol,
    root_domain,
    sni,
    dns,
    application,
    application_category,
    asn

