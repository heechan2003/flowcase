/*
What else each review case's host did around its contact with a flagged address, over one UTC day:
per named five-minute window, the registered domains it exchanged traffic with, with active minutes,
distinct addresses and bytes. Only the windows in {windows} are returned, the flagged address first,
at most 60 domains each. v1 kept 15 by active minutes, which let a host's always-on services crowd
out the brief visits that led to the contact; the case file now ranks what comes back by the host's
and the campus's retained use. Run for review cases only, so nothing is read about hosts whose match
was explained.
*/
SELECT
    client_ip,
    bucket,
    root_domain,
    max(has({servers:Array(String)}, server_ip)) AS flagged,
    uniqExact(time) AS active_minutes,
    uniqExact(server_ip) AS addresses,
    sum(toUInt64(greatest(up_bytes, 0))) AS sent_bytes,
    sum(toUInt64(greatest(down_bytes, 0))) AS received_bytes
FROM (
    SELECT
        client_ip,
        server_ip,
        root_domain,
        time,
        up_bytes,
        down_bytes,
        toUInt32(intDiv(toUnixTimestamp(time), 300)) AS bucket
    FROM flow.activity_1m
    PREWHERE time >= {start:DateTime('UTC')} AND time < {end:DateTime('UTC')}
    WHERE has({hosts:Array(String)}, client_ip) AND flow_count > 0
)
WHERE has({windows:Array(String)}, concat(client_ip, ' ', toString(bucket)))
GROUP BY client_ip, bucket, root_domain
ORDER BY client_ip, bucket, flagged DESC, active_minutes DESC, root_domain
LIMIT 60 BY client_ip, bucket
