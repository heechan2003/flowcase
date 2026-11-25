/* Metadata-only contract query. It reads no source-table rows. */
SELECT
    columns.database AS database,
    columns.table AS table,
    columns.name AS column_name,
    columns.type AS column_type,
    tables.engine AS engine
FROM system.columns AS columns
INNER JOIN system.tables AS tables
    ON columns.database = tables.database AND columns.table = tables.name
WHERE (columns.database, columns.table) IN (
    ('flow', 'activity_1m'),
    ('flow', 'host_load_5m'),
    ('flow', 'dns_pairs'),
    ('flow', 'long_flows')
)
AND columns.name IN (
    'time', 'client_ip', 'server_ip', 'server_port', 'transport_protocol',
    'application', 'application_category', 'root_domain', 'sni', 'dns',
    'asn', 'up_bytes', 'down_bytes',
    'up_packets', 'down_packets', 'flow_count', 'active_minutes',
    'up_rate_p95_bps', 'up_bytes',
    'down_bytes', 'complete_sessions',
    'unanswered_sessions', 'unsolicited_sessions', 'query_packets',
    'response_packets', 'unanswered_query_packets', 'unsolicited_response_packets',
    'mean_service_nanos', 'flow_id', 'start', 'finish', 'duration_sec',
    'client_port', 'protocol', 'up_bytes', 'down_bytes'
)
ORDER BY columns.database, columns.table, columns.position
