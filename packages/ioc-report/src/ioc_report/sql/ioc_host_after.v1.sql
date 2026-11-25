/*
Every destination each review case's host exchanged traffic with, in either direction, over one UTC day, for the view of what
it did before and after its contact: per registered domain, or per serving network when the traffic
carried no name. Run once per day inside the minute horizon, batched across review hosts, so
nothing is read about hosts whose match was explained and no query covers more than one day.
*/
SELECT
    client_ip,
    root_domain,
    if(root_domain = '', ifNull(asn, ''), '') AS network,
    min(time) AS first_minute,
    uniqExact(time) AS active_minutes,
    sum(toUInt64(greatest(up_bytes, 0))) AS sent_bytes,
    sum(toUInt64(greatest(down_bytes, 0))) AS received_bytes
FROM flow.activity_1m
PREWHERE time >= {start:DateTime('UTC')} AND time < {end:DateTime('UTC')}
WHERE has({hosts:Array(String)}, client_ip) AND flow_count > 0
GROUP BY client_ip, root_domain, network
