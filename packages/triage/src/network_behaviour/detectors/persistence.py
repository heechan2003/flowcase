"""Leakage-safe retained-bitmap reads for the persistence detector."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any

import duckdb
import pyarrow as pa

from network_behaviour.aggregation import ClientServiceDayRow
from network_behaviour.detectors.models import DetectorPolicy
from network_behaviour.normalization.bitmap import ActivityBitmap
from network_behaviour.time import UtcDay


@dataclass(frozen=True, slots=True)
class RelationshipBitmapDay:
    day: date
    client_ip: str
    service_id: bytes
    asn_id: int
    bitmap: ActivityBitmap


class PersistenceHistoryRepository:
    """Load only current relationship keys from the bounded retained history."""

    def __init__(
        self,
        connection: duckdb.DuckDBPyConnection,
        policy: DetectorPolicy | None = None,
    ) -> None:
        self._connection = connection
        self._policy = policy or DetectorPolicy()

    def load(
        self, day: UtcDay, current_services: tuple[ClientServiceDayRow, ...]
    ) -> tuple[RelationshipBitmapDay, ...]:
        keys = sorted(
            {(row.client_ip, row.service_id, row.asn_id) for row in current_services},
            key=lambda key: (key[0], key[1], key[2]),
        )
        if not keys:
            return ()
        registration = "_persistence_relationship_keys"
        self._connection.register(
            registration,
            pa.table(
                {
                    "client_ip": [key[0] for key in keys],
                    "service_id": pa.array([key[1] for key in keys], type=pa.binary(16)),
                    "asn_id": pa.array([key[2] for key in keys], type=pa.uint64()),
                }
            ),
        )
        sql = f"""
            SELECT h.day, h.client_ip, h.service_id, h.asn_id, h.active_5m_bitmap
            FROM history.client_service_day h
            JOIN {registration} k
              ON k.client_ip = h.client_ip AND k.service_id = h.service_id
             AND k.asn_id = h.asn_id
            WHERE h.day >= ? AND h.day < ?
            ORDER BY h.client_ip, h.service_id, h.asn_id, h.day
        """
        if "day < ?" not in sql:
            raise RuntimeError("persistence history query is missing the day < D boundary")
        try:
            rows = self._connection.execute(
                sql,
                [day.value - timedelta(days=self._policy.persistence_lookback_days), day.value],
            ).fetchall()
        finally:
            self._connection.unregister(registration)
        return _merge_component_bitmaps(rows)


def _merge_component_bitmaps(rows: list[tuple[Any, ...]]) -> tuple[RelationshipBitmapDay, ...]:
    merged: dict[tuple[date, str, bytes, int], ActivityBitmap] = {}
    for row in rows:
        history_day = row[0]
        if not isinstance(history_day, date):
            raise TypeError("DuckDB returned a non-date persistence value")
        key = (history_day, str(row[1]), bytes(row[2]), int(row[3]))
        bitmap = ActivityBitmap(bytes(row[4]))
        merged[key] = merged.get(key, ActivityBitmap()) | bitmap
    return tuple(
        RelationshipBitmapDay(day, client_ip, service_id, asn_id, bitmap)
        for (day, client_ip, service_id, asn_id), bitmap in sorted(
            merged.items(), key=lambda item: (item[0][1], item[0][2], item[0][3], item[0][0])
        )
    )
