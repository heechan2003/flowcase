CREATE TABLE review.candidate_review_session (
    candidate_id UUID PRIMARY KEY,
    review_started_at TIMESTAMPTZ NOT NULL,
    selection_stratum VARCHAR NOT NULL CHECK (
        selection_stratum IN ('main_queue', 'random_eligible_audit', 'below_threshold_audit')
    ),
    review_policy_version VARCHAR NOT NULL
);
