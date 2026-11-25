/*
Every destination each review case's host exchanged traffic with, in either direction, over one UTC
day, for the view of what it did before and after its contact: per registered domain, or per serving
network when the traffic carried no name. Run once per day inside the minute horizon, batched across
review hosts, so nothing is read about hosts whose match was explained and no query covers more than
one day.
*/
SELECT
    client_ip,
    root_domain,
    CASE WHEN root_domain = '' THEN coalesce(asn, '') ELSE '' END AS network,
    min(time) AS first_minute,
    count(DISTINCT time) AS active_minutes,
    CAST(sum(greatest(up_bytes, 0)) AS UBIGINT) AS sent_bytes,
    CAST(sum(greatest(down_bytes, 0)) AS UBIGINT) AS received_bytes
FROM flow.activity_1m
WHERE time >= {start:DateTime('UTC')} AND time < {end:DateTime('UTC')}
  AND list_contains({hosts:Array(String)}, client_ip) AND flow_count > 0
GROUP BY client_ip, root_domain, network
