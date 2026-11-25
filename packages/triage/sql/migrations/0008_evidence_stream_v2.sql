-- Stream schema v2 storage.
--
-- Strictly additive. Migrations 0001-0007 are untouched, and feed.candidate_episode /
-- feed.candidate_evidence keep every row published under daily-candidate-feed-v1. Those days are
-- reconstructed from their original tables and verified against their original digest, so a v1 day
-- published before this migration still streams back byte-for-byte. Tier 0 immutability depends on
-- not reinterpreting them.
--
-- Differences from the v1 tables and why:
--   * no daily_rank      -- a contiguous total order asserted discrimination the evidence lacks
--   * no priority_score  -- it was interpolated rank position, carrying no independent information
--   * sequence           -- file position only, for completeness checking
--   * tie_group          -- dense rank over the real ordering key; equal values are equivalent
--   * evidence_tier      -- E1/E2/E3, replacing P1/P2/P3
--   * service_domain     -- resolvable destination; permitted here, never in history.*

CREATE TABLE feed.episode (
    episode_id UUID PRIMARY KEY,
    run_id UUID NOT NULL,
    day DATE NOT NULL,
    detected_at TIMESTAMPTZ NOT NULL,
    client_ip VARCHAR NOT NULL CHECK (length(client_ip) > 0),
    family VARCHAR NOT NULL,
    episode_start TIMESTAMPTZ NOT NULL,
    episode_end TIMESTAMPTZ NOT NULL,
    service_id VARCHAR CHECK (service_id IS NULL OR length(service_id) = 32),
    service_domain VARCHAR CHECK (service_domain IS NULL OR length(service_domain) BETWEEN 1 AND 253),
    asn_id UBIGINT,
    family_strength DOUBLE NOT NULL CHECK (family_strength BETWEEN 0 AND 100),
    evidence_tier VARCHAR NOT NULL CHECK (evidence_tier IN ('E1', 'E2', 'E3')),
    sequence UINTEGER NOT NULL CHECK (sequence > 0),
    tie_group UINTEGER NOT NULL CHECK (tie_group > 0),
    evidence_group_mask UBIGINT NOT NULL,
    history_confidence VARCHAR NOT NULL,
    data_quality_confidence VARCHAR NOT NULL,
    reason_code_mask UBIGINT NOT NULL,
    detector_version VARCHAR NOT NULL CHECK (length(detector_version) > 0),
    ordering_version VARCHAR NOT NULL CHECK (length(ordering_version) > 0),
    source_detail_expires_at TIMESTAMPTZ,
    CHECK (episode_end >= episode_start),
    CHECK (source_detail_expires_at IS NULL OR source_detail_expires_at >= detected_at),
    -- A domain without a service to attach it to would be an unresolvable raw destination.
    CHECK (service_domain IS NULL OR service_id IS NOT NULL),
    UNIQUE (day, sequence),
    FOREIGN KEY (day) REFERENCES feed.daily_publication(day)
);

CREATE TABLE feed.episode_evidence (
    episode_id UUID NOT NULL,
    evidence_group UTINYINT NOT NULL CHECK (evidence_group <= 17),
    metric_code VARCHAR NOT NULL CHECK (length(metric_code) > 0),
    observed_value DOUBLE NOT NULL,
    client_baseline_value DOUBLE,
    peer_reference_value DOUBLE,
    self_strength DOUBLE CHECK (self_strength BETWEEN 0 AND 100),
    peer_strength DOUBLE CHECK (peer_strength BETWEEN 0 AND 100),
    metric_strength DOUBLE CHECK (metric_strength BETWEEN 0 AND 100),
    support_count UBIGINT,
    PRIMARY KEY (episode_id, evidence_group),
    FOREIGN KEY (episode_id) REFERENCES feed.episode(episode_id)
);
