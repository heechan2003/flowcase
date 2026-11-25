CREATE SCHEMA detect;
CREATE SCHEMA review;
CREATE SCHEMA ops;

CREATE TABLE ops.pipeline_run (
    run_id UUID PRIMARY KEY,
    day DATE NOT NULL,
    status VARCHAR NOT NULL CHECK (status IN ('created', 'running', 'published', 'failed')),
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    source_sql_version VARCHAR NOT NULL,
    schema_version INTEGER NOT NULL,
    normalization_version VARCHAR NOT NULL,
    detector_version VARCHAR,
    failure_code VARCHAR,
    CHECK (completed_at IS NULL OR completed_at >= started_at)
);

CREATE TABLE detect.candidate_episode (
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
    priority_tier VARCHAR NOT NULL CHECK (priority_tier IN ('P1', 'P2', 'P3', 'diagnostic')),
    priority_score UTINYINT NOT NULL CHECK (priority_score <= 100),
    evidence_group_mask UBIGINT NOT NULL,
    history_confidence VARCHAR NOT NULL,
    data_quality_confidence VARCHAR NOT NULL,
    reason_code_mask UBIGINT NOT NULL,
    detector_version VARCHAR NOT NULL,
    selection_stratum VARCHAR NOT NULL CHECK (
        selection_stratum IN ('main_queue', 'random_eligible_audit', 'below_threshold_audit')
    ),
    investigate_by TIMESTAMPTZ NOT NULL,
    source_detail_expires_at TIMESTAMPTZ NOT NULL,
    CHECK (episode_end >= episode_start),
    CHECK (investigate_by >= detected_at),
    CHECK (source_detail_expires_at >= detected_at)
);

CREATE TABLE detect.candidate_evidence (
    candidate_id UUID NOT NULL,
    evidence_group UTINYINT NOT NULL CHECK (evidence_group <= 12),
    metric_code VARCHAR NOT NULL,
    observed_value DOUBLE NOT NULL,
    client_baseline_value DOUBLE,
    peer_reference_value DOUBLE,
    self_strength DOUBLE CHECK (self_strength BETWEEN 0 AND 100),
    peer_strength DOUBLE CHECK (peer_strength BETWEEN 0 AND 100),
    metric_strength DOUBLE NOT NULL CHECK (metric_strength BETWEEN 0 AND 100),
    support_count UBIGINT NOT NULL,
    PRIMARY KEY (candidate_id, evidence_group)
);

CREATE TABLE review.candidate_disposition (
    candidate_id UUID PRIMARY KEY,
    review_started_at TIMESTAMPTZ NOT NULL,
    reviewed_at TIMESTAMPTZ NOT NULL,
    review_duration_seconds DOUBLE NOT NULL CHECK (review_duration_seconds >= 0),
    disposition VARCHAR NOT NULL CHECK (
        disposition IN (
            'investigation_worthy', 'benign_understood', 'benign_unexplained',
            'insufficient_evidence', 'duplicate', 'data_quality_issue'
        )
    ),
    false_positive_code VARCHAR,
    review_policy_version VARCHAR NOT NULL,
    CHECK (reviewed_at >= review_started_at)
);
