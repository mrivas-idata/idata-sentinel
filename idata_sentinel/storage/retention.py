"""Política de retención de datos de escaneo (plan maestro §1.4).

Los reportes contienen información sensible del cliente, así que no se guardan
indefinidamente. La retención siempre **preserva el baseline** de cada objetivo:
sin él no habría contra qué comparar y el monitoreo continuo perdería sentido.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from idata_sentinel.storage.db import ScanStore

DEFAULT_RETENTION_DAYS = 365


@dataclass(frozen=True)
class RetentionResult:
    deleted: int
    kept_baselines: int
    cutoff: str


def apply_retention(
    store: ScanStore,
    *,
    days: int = DEFAULT_RETENTION_DAYS,
    now: str | None = None,
) -> RetentionResult:
    reference = datetime.fromisoformat(now) if now else datetime.now(timezone.utc)
    cutoff = (reference - timedelta(days=days)).isoformat()

    with store._connect() as conn:
        kept = conn.execute(
            "SELECT COUNT(*) AS n FROM scans WHERE scanned_at < ? AND is_baseline = 1", (cutoff,)
        ).fetchone()["n"]
        cursor = conn.execute(
            "DELETE FROM scans WHERE scanned_at < ? AND is_baseline = 0", (cutoff,)
        )
        deleted = cursor.rowcount

    return RetentionResult(deleted=deleted, kept_baselines=kept, cutoff=cutoff)
