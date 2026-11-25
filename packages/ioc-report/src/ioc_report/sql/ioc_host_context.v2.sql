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
    bool_or(list_contains({servers:Array(String)}, server_ip)) AS flagged,
    count(DISTINCT time) AS active_minutes,
    count(DISTINCT server_ip) AS addresses,
    CAST(sum(greatest(up_bytes, 0)) AS UBIGINT) AS sent_bytes,
    CAST(sum(greatest(down_bytes, 0)) AS UBIGINT) AS received_bytes
FROM (
    SELECT
        client_ip,
        server_ip,
        root_domain,
        time,
        up_bytes,
        down_bytes,
        CAST(CAST(epoch(time) AS BIGINT) // 300 AS UINTEGER) AS bucket
    FROM flow.activity_1m
    WHERE time >= {start:DateTime('UTC')} AND time < {end:DateTime('UTC')}
      AND list_contains({hosts:Array(String)}, client_ip) AND flow_count > 0
)
WHERE list_contains({windows:Array(String)}, concat(client_ip, ' ', CAST(bucket AS VARCHAR)))
GROUP BY client_ip, bucket, root_domain
QUALIFY row_number() OVER (
    PARTITION BY client_ip, bucket
    ORDER BY flagged DESC, active_minutes DESC, root_domain
) <= 60
ORDER BY client_ip, bucket, flagged DESC, active_minutes DESC, root_domain
