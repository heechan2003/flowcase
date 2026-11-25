CREATE SCHEMA history;

CREATE TABLE history.client_day (
    day DATE NOT NULL,
    client_ip VARCHAR NOT NULL,
    up_bytes UBIGINT NOT NULL,
    down_bytes UBIGINT NOT NULL,
    up_packets UBIGINT NOT NULL,
    down_packets UBIGINT NOT NULL,
    flow_count UBIGINT NOT NULL,
    active_minutes USMALLINT NOT NULL CHECK (active_minutes <= 1440),
    active_5m_buckets USMALLINT NOT NULL CHECK (active_5m_buckets <= 288),
    unique_servers UBIGINT NOT NULL,
    unique_services UBIGINT NOT NULL,
    unique_routes UBIGINT NOT NULL,
    unique_asns UBIGINT NOT NULL,
    unique_port_groups UBIGINT NOT NULL,
    top_service_up_bytes UBIGINT NOT NULL,
    top_service_total_bytes UBIGINT NOT NULL,
    opaque_bytes UBIGINT NOT NULL,
    p95_5m_up_bytes DOUBLE NOT NULL CHECK (p95_5m_up_bytes >= 0),
    max_5m_up_bytes UBIGINT NOT NULL,
    p95_5m_unique_servers DOUBLE NOT NULL CHECK (p95_5m_unique_servers >= 0),
    max_5m_unique_servers UBIGINT NOT NULL,
    p95_5m_unique_services DOUBLE NOT NULL CHECK (p95_5m_unique_services >= 0),
    max_5m_unique_services UBIGINT NOT NULL,
    p95_5m_unique_port_groups DOUBLE NOT NULL CHECK (p95_5m_unique_port_groups >= 0),
    max_5m_unique_port_groups UBIGINT NOT NULL,
    p95_bucket_up_rate_p95_bps DOUBLE NOT NULL CHECK (p95_bucket_up_rate_p95_bps >= 0),
    max_bucket_up_rate_p95_bps DOUBLE NOT NULL CHECK (max_bucket_up_rate_p95_bps >= 0),
    large_flow_count UBIGINT NOT NULL,
    large_flow_up_bytes UBIGINT NOT NULL,
    max_large_flow_bytes UBIGINT NOT NULL,
    max_large_flow_duration_sec DOUBLE NOT NULL CHECK (max_large_flow_duration_sec >= 0),
    PRIMARY KEY (day, client_ip)
);

CREATE TABLE history.client_service_day (
    day DATE NOT NULL,
    client_ip VARCHAR NOT NULL,
    service_id BLOB NOT NULL CHECK (octet_length(service_id) = 16),
    service_basis VARCHAR NOT NULL CHECK (
        service_basis IN ('domain', 'application_asn', 'asn', 'server_ip')
    ),
    asn_id UBIGINT NOT NULL,
    application_category_id UBIGINT NOT NULL,
    transport_protocol UTINYINT NOT NULL,
    port_group UINTEGER NOT NULL CHECK (port_group <= 65538),
    active_5m_bitmap BLOB NOT NULL CHECK (octet_length(active_5m_bitmap) = 36),
    up_bytes UBIGINT NOT NULL,
    down_bytes UBIGINT NOT NULL,
    flow_count UBIGINT NOT NULL,
    unique_servers UBIGINT NOT NULL,
    large_flow_count UBIGINT NOT NULL,
    large_flow_up_bytes UBIGINT NOT NULL,
    max_large_flow_bytes UBIGINT NOT NULL,
    max_large_flow_duration_sec DOUBLE NOT NULL CHECK (max_large_flow_duration_sec >= 0),
    PRIMARY KEY (
        day, client_ip, service_id, asn_id, application_category_id,
        transport_protocol, port_group
    )
);
