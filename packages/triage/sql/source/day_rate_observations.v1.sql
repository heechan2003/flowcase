/* One transient upstream-rate value per observed client and five-minute bucket. */
SELECT
    (CAST(epoch(time) AS BIGINT) // 300) * 300 AS bucket_epoch,
    client_ip,
    max(greatest(coalesce(up_rate_p95_bps, 0), 0)) AS up_rate_p95_bps
FROM flow.host_load_5m
WHERE time >= {start:DateTime('UTC')} AND time < {end:DateTime('UTC')}
GROUP BY ALL
