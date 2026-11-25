-- Preserve the pre-revision Phase 8 evaluation cohort and its controlled review state.
-- These operational tables are not Product P0 inputs and cannot affect feed publication.
CREATE TABLE review.baseline_cohort_item (
    cohort_item_id UUID PRIMARY KEY,
    day DATE NOT NULL,
    client_ip VARCHAR NOT NULL,
    selection_version VARCHAR NOT NULL,
    selected_at TIMESTAMPTZ NOT NULL,
    queue_size UINTEGER NOT NULL CHECK (queue_size > 0),
    top_volume_rank UINTEGER CHECK (top_volume_rank > 0),
    top_fanout_rank UINTEGER CHECK (top_fanout_rank > 0),
    investigate_by TIMESTAMPTZ NOT NULL,
    source_detail_expires_at TIMESTAMPTZ NOT NULL,
    UNIQUE (day, client_ip, selection_version),
    CHECK (top_volume_rank IS NOT NULL OR top_fanout_rank IS NOT NULL),
    CHECK (source_detail_expires_at >= investigate_by)
);

CREATE TABLE review.baseline_review_session (
    cohort_item_id UUID PRIMARY KEY,
    review_started_at TIMESTAMPTZ NOT NULL,
    review_policy_version VARCHAR NOT NULL
);

CREATE TABLE review.baseline_disposition (
    cohort_item_id UUID PRIMARY KEY,
    review_started_at TIMESTAMPTZ NOT NULL,
    reviewed_at TIMESTAMPTZ NOT NULL,
    review_duration_seconds DOUBLE NOT NULL CHECK (review_duration_seconds >= 0),
    disposition VARCHAR NOT NULL CHECK (
        disposition IN (
            'investigation_worthy',
            'benign_understood',
            'benign_unexplained',
            'insufficient_evidence',
            'duplicate',
            'data_quality_issue'
        )
    ),
    false_positive_code VARCHAR,
    review_policy_version VARCHAR NOT NULL,
    CHECK (reviewed_at >= review_started_at)
);
