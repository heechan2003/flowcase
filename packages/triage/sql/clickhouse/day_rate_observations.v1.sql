/* One transient upstream-rate value per observed client and five-minute bucket. */
WITH
    {start:DateTime('UTC')} AS start_utc,
    {end:DateTime('UTC')} AS end_utc
SELECT
    toUnixTimestamp(toStartOfInterval(time, INTERVAL 5 MINUTE)) AS bucket_epoch,
    client_ip,
    max(greatest(ifNull(up_rate_p95_bps, 0), 0)) AS up_rate_p95_bps
FROM flow.host_load_5m
PREWHERE time >= start_utc AND time < end_utc
GROUP BY bucket_epoch, client_ip

