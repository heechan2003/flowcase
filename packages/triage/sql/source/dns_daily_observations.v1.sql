SELECT
    CAST(time AS DATE) AS day,
    client_ip,
    md5(server_ip) AS resolver_id,
    sum(complete_sessions) AS complete_sessions,
    sum(unanswered_sessions) AS unanswered_sessions,
    sum(unsolicited_sessions) AS unsolicited_sessions,
    sum(query_packets) AS query_packets,
    sum(response_packets) AS response_packets,
    sum(unanswered_query_packets) AS unanswered_query_packets,
    sum(unsolicited_response_packets) AS unsolicited_response_packets,
    sum(CAST(mean_service_nanos AS DOUBLE) * CAST(complete_sessions AS DOUBLE))
        AS weighted_service_nanos,
    sum(complete_sessions) AS weighted_service_sessions
FROM flow.dns_pairs
WHERE time >= {start:DateTime64(6, 'UTC')}
  AND time < {end:DateTime64(6, 'UTC')}
GROUP BY day, client_ip, resolver_id
ORDER BY day, client_ip, resolver_id
