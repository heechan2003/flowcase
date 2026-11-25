#!/usr/bin/env bash
#
# Re-derive one UTC day under the current implementation, in an isolated database.
#
#   scripts/replay_day.sh 2026-07-02
#   scripts/replay_day.sh 2026-07-02 /tmp/my-replay
#
# Seeds a fresh database at the current schema with history strictly before the target day, then
# publishes that day from source. The production database is opened read-only and never written.
#
# This is the mechanism behind held-out-day evaluation: the replay sees only history the original
# run would have seen, so its output is comparable. See docs/runbooks/backfill-and-replay.md and
# docs/EVALUATION.md §3.
#
# Source detail expires in roughly fifteen days (docs/CASE_STUDY.md §1). Older days cannot be
# replayed from source at all — only streamed back from storage.

set -euo pipefail

DAY="${1:-}"
if [[ ! "$DAY" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
  echo "usage: $0 <YYYY-MM-DD> [replay-dir]" >&2
  exit 64
fi

PRODUCTION_DB="${PRODUCTION_DB:-data/network_behaviour.duckdb}"
REPLAY_DIR="${2:-$(mktemp -d -t network-behaviour-replay)}"
REPLAY_DB="$REPLAY_DIR/replay-$DAY.duckdb"
REPLAY_FEED="$REPLAY_DIR/replay-$DAY.jsonl"

PYTHON="${PYTHON:-.venv/bin/python}"
CLI="${CLI:-.venv/bin/network-behaviour}"

if [[ ! -f "$PRODUCTION_DB" ]]; then
  echo "production database not found: $PRODUCTION_DB" >&2
  exit 66
fi

mkdir -p "$REPLAY_DIR"

if [[ -e "$REPLAY_DB" ]]; then
  echo "replay database already exists: $REPLAY_DB" >&2
  echo "remove it or choose another replay directory." >&2
  exit 73
fi

# Seed retained history strictly before the target day. day < D is the leakage boundary, and it
# lives in network_behaviour.evaluation.replay so this script and the evaluation harness cannot
# disagree about where it is.
NETWORK_BEHAVIOUR_DUCKDB_PATH="$PRODUCTION_DB" "$PYTHON" scripts/evaluate.py \
  seed --day "$DAY" --into "$REPLAY_DB"

# Publish the target day against the replay database only.
NETWORK_BEHAVIOUR_DUCKDB_PATH="$REPLAY_DB" "$CLI" run-day --day "$DAY" > "$REPLAY_FEED"

echo
echo "replay database: $REPLAY_DB"
echo "replay stream:   $REPLAY_FEED"
echo
echo "compare against the stored stream for the same day with:"
echo "  NETWORK_BEHAVIOUR_DUCKDB_PATH=$PRODUCTION_DB $CLI run-day --day $DAY > stored.jsonl"
echo "  python scripts/stream_stats.py --ties $REPLAY_FEED stored.jsonl"
