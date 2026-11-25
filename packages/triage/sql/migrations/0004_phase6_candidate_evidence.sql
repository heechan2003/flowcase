-- Phase 5 metric evidence need not have a support count, while positive supporting
-- context need not invent a percentile strength. Phase 6 also separates independent
-- DNS concepts so every concept that affects eligibility can have one minimal row.
CREATE TABLE detect.candidate_evidence_phase6 (
    candidate_id UUID NOT NULL,
    evidence_group UTINYINT NOT NULL CHECK (evidence_group <= 17),
    metric_code VARCHAR NOT NULL,
    observed_value DOUBLE NOT NULL,
    client_baseline_value DOUBLE,
    peer_reference_value DOUBLE,
    self_strength DOUBLE CHECK (self_strength BETWEEN 0 AND 100),
    peer_strength DOUBLE CHECK (peer_strength BETWEEN 0 AND 100),
    metric_strength DOUBLE CHECK (metric_strength BETWEEN 0 AND 100),
    support_count UBIGINT,
    PRIMARY KEY (candidate_id, evidence_group)
);

INSERT INTO detect.candidate_evidence_phase6
SELECT * FROM detect.candidate_evidence;

DROP TABLE detect.candidate_evidence;
ALTER TABLE detect.candidate_evidence_phase6 RENAME TO candidate_evidence;
