-- Phase 8C adds a forward-only complete-feed store. The existing detect tables
-- remain the pre-cutover selected queue and are exposed explicitly as legacy.
CREATE SCHEMA feed;

CREATE TABLE feed.daily_publication (
    day DATE PRIMARY KEY,
    feed_schema_version VARCHAR NOT NULL CHECK (length(feed_schema_version) > 0),
    published_at TIMESTAMPTZ NOT NULL,
    run_id UUID NOT NULL UNIQUE,
    detector_version VARCHAR NOT NULL CHECK (length(detector_version) > 0),
    ranking_version VARCHAR NOT NULL CHECK (length(ranking_version) > 0),
    candidate_count UBIGINT NOT NULL,
    evidence_count UBIGINT NOT NULL,
    serialized_bytes UBIGINT NOT NULL,
    feed_sha256 VARCHAR NOT NULL CHECK (length(feed_sha256) = 64)
);

CREATE TABLE feed.candidate_episode (
    candidate_id UUID PRIMARY KEY,
    run_id UUID NOT NULL,
    day DATE NOT NULL,
    detected_at TIMESTAMPTZ NOT NULL,
    client_ip VARCHAR NOT NULL,
    family VARCHAR NOT NULL CHECK (
        family IN ('transfer', 'relationship', 'fanout', 'dns', 'persistence')
    ),
    episode_start TIMESTAMPTZ NOT NULL,
    episode_end TIMESTAMPTZ NOT NULL,
    service_id BLOB CHECK (service_id IS NULL OR octet_length(service_id) = 16),
    asn_id UBIGINT,
    family_strength DOUBLE NOT NULL CHECK (family_strength BETWEEN 0 AND 100),
    priority_tier VARCHAR NOT NULL CHECK (priority_tier IN ('P1', 'P2', 'P3')),
    daily_rank UINTEGER NOT NULL CHECK (daily_rank > 0),
    priority_score UTINYINT NOT NULL CHECK (
        (priority_tier = 'P1' AND priority_score BETWEEN 80 AND 100)
        OR (priority_tier = 'P2' AND priority_score BETWEEN 55 AND 79)
        OR (priority_tier = 'P3' AND priority_score BETWEEN 30 AND 54)
    ),
    evidence_group_mask UBIGINT NOT NULL,
    history_confidence VARCHAR NOT NULL,
    data_quality_confidence VARCHAR NOT NULL,
    reason_code_mask UBIGINT NOT NULL,
    detector_version VARCHAR NOT NULL CHECK (length(detector_version) > 0),
    ranking_version VARCHAR NOT NULL CHECK (length(ranking_version) > 0),
    source_detail_expires_at TIMESTAMPTZ,
    CHECK (episode_end >= episode_start),
    CHECK (source_detail_expires_at IS NULL OR source_detail_expires_at >= detected_at),
    UNIQUE (day, daily_rank),
    FOREIGN KEY (day) REFERENCES feed.daily_publication(day)
);

CREATE TABLE feed.candidate_evidence (
    candidate_id UUID NOT NULL,
    evidence_group UTINYINT NOT NULL CHECK (evidence_group <= 17),
    metric_code VARCHAR NOT NULL CHECK (length(metric_code) > 0),
    observed_value DOUBLE NOT NULL,
    client_baseline_value DOUBLE,
    peer_reference_value DOUBLE,
    self_strength DOUBLE CHECK (self_strength BETWEEN 0 AND 100),
    peer_strength DOUBLE CHECK (peer_strength BETWEEN 0 AND 100),
    metric_strength DOUBLE CHECK (metric_strength BETWEEN 0 AND 100),
    support_count UBIGINT,
    PRIMARY KEY (candidate_id, evidence_group),
    FOREIGN KEY (candidate_id) REFERENCES feed.candidate_episode(candidate_id)
);

CREATE VIEW detect.legacy_selected_episode AS
SELECT 'legacy_selected'::VARCHAR AS publication_kind, candidate.*
FROM detect.candidate_episode AS candidate;

CREATE VIEW detect.legacy_selected_evidence AS
SELECT 'legacy_selected'::VARCHAR AS publication_kind, evidence.*
FROM detect.candidate_evidence AS evidence
JOIN detect.candidate_episode AS candidate USING (candidate_id);
