"""Persistencia de escaneos y monitores (plan maestro §2, §6).

SQLite para el MVP local; el esquema es deliberadamente plano (JSON en columnas
de texto) para poder migrar a PostgreSQL/Supabase sin reescribir consultas
complejas (§11.3).

Todas las marcas de tiempo se reciben como parámetro en vez de leerse del reloj
interno: eso hace los tests deterministas y permite reconstruir históricos.
"""
from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from idata_sentinel.storage.crypto import ENV_KEY, Cipher, DecryptionError, cipher_from_env

#: En un contenedor redeployable el sistema de archivos es efímero: si la base
#: queda dentro de la imagen, cada despliegue borra la línea base de todos los
#: clientes y el monitoreo pierde su referencia. `IDATA_SENTINEL_DB` debe
#: apuntar a un volumen persistente (p. ej. /data/sentinel.db en Railway).
ENV_DB_PATH = "IDATA_SENTINEL_DB"
DEFAULT_DB_PATH = Path(os.environ.get(ENV_DB_PATH) or "idata_sentinel.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT    NOT NULL,
    mode        TEXT    NOT NULL,
    scanned_at  TEXT    NOT NULL,
    score       INTEGER NOT NULL,
    grade       TEXT    NOT NULL,
    findings    TEXT    NOT NULL,
    artifacts   TEXT    NOT NULL,
    is_baseline INTEGER NOT NULL DEFAULT 0,
    encrypted   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target, scanned_at);

CREATE TABLE IF NOT EXISTS monitors (
    target      TEXT PRIMARY KEY,
    schedule    TEXT NOT NULL,
    mode        TEXT NOT NULL DEFAULT 'passive',
    webhook_url TEXT,
    created_at  TEXT NOT NULL,
    last_run_at TEXT,
    active      INTEGER NOT NULL DEFAULT 1,
    modules     TEXT NOT NULL DEFAULT 'all'
);
"""

#: Columnas añadidas después de la primera versión del esquema. SQLite no tiene
#: "ADD COLUMN IF NOT EXISTS", así que se comprueba antes de aplicar.
_MIGRATIONS = (
    ("monitors", "modules", "TEXT NOT NULL DEFAULT 'all'"),
    ("scans", "encrypted", "INTEGER NOT NULL DEFAULT 0"),
)

SCHEDULES = {"daily": 1, "weekly": 7, "monthly": 30}


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class ScanRecord:
    id: int
    target: str
    mode: str
    scanned_at: str
    score: int
    grade: str
    findings: list[dict]
    artifacts: dict
    is_baseline: bool
    encrypted: bool = False

    def surface_map(self) -> dict | None:
        return self.artifacts.get("asset_inventory", {}).get("surface_map")


@dataclass(frozen=True)
class MonitorRecord:
    target: str
    schedule: str
    mode: str
    webhook_url: str | None
    created_at: str
    last_run_at: str | None
    active: bool
    modules: str = "all"

    def is_due(self, *, now: str) -> bool:
        if not self.active:
            return False
        if self.last_run_at is None:
            return True
        interval = timedelta(days=SCHEDULES.get(self.schedule, 7))
        return datetime.fromisoformat(now) - datetime.fromisoformat(self.last_run_at) >= interval


class ScanStore:
    """Acceso a la base. Abre y cierra la conexión por operación: los escaneos
    son esporádicos y así no hay estado compartido entre hilos del worker."""

    def __init__(self, path: Path | str = DEFAULT_DB_PATH, *, cipher: Cipher | None = None) -> None:
        self.path = Path(path)
        #: Sin clave configurada el cifrado queda inactivo y cada fila registra
        #: en qué modo se escribió (plan maestro §1.4).
        self.cipher = cipher if cipher is not None else cipher_from_env()
        self.initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            for table, column, definition in _MIGRATIONS:
                existing = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
                if column not in existing:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    # -- escaneos ----------------------------------------------------------

    def record_scan(
        self,
        *,
        target: str,
        mode: str,
        score: int,
        grade: str,
        findings: list[dict],
        artifacts: dict | None = None,
        scanned_at: str | None = None,
    ) -> ScanRecord:
        """El primer escaneo de un objetivo queda automáticamente como baseline (§6)."""
        scanned_at = scanned_at or utcnow()
        is_baseline = self.baseline(target) is None

        with self._connect() as conn:
            cursor = conn.execute(
                "INSERT INTO scans (target, mode, scanned_at, score, grade, findings, artifacts,"
                " is_baseline, encrypted) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    target, mode, scanned_at, score, grade,
                    self.cipher.encrypt(json.dumps(findings, ensure_ascii=False)),
                    self.cipher.encrypt(json.dumps(artifacts or {}, ensure_ascii=False)),
                    int(is_baseline),
                    int(self.cipher.enabled),
                ),
            )
            scan_id = cursor.lastrowid

        return ScanRecord(
            id=scan_id, target=target, mode=mode, scanned_at=scanned_at, score=score,
            grade=grade, findings=findings, artifacts=artifacts or {}, is_baseline=is_baseline,
        )

    def _row_to_scan(self, row: sqlite3.Row) -> ScanRecord:
        # La fila dice cómo se escribió: una base creada antes de activar el
        # cifrado se sigue leyendo sin tocarla.
        was_encrypted = "encrypted" in row.keys() and bool(row["encrypted"])
        if was_encrypted and not self.cipher.enabled:
            raise DecryptionError(
                f"El escaneo {row['id']} está cifrado y no hay clave configurada. "
                f"Define {ENV_KEY} para poder leerlo."
            )
        decode = self.cipher.decrypt if was_encrypted else (lambda value: value)

        return ScanRecord(
            id=row["id"], target=row["target"], mode=row["mode"], scanned_at=row["scanned_at"],
            score=row["score"], grade=row["grade"],
            findings=json.loads(decode(row["findings"])),
            artifacts=json.loads(decode(row["artifacts"])),
            is_baseline=bool(row["is_baseline"]),
            encrypted=was_encrypted,
        )

    def baseline(self, target: str) -> ScanRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM scans WHERE target = ? AND is_baseline = 1 ORDER BY id DESC LIMIT 1",
                (target,),
            ).fetchone()
        return self._row_to_scan(row) if row else None

    def latest_scan(self, target: str, *, before_id: int | None = None) -> ScanRecord | None:
        query = "SELECT * FROM scans WHERE target = ?"
        params: list = [target]
        if before_id is not None:
            query += " AND id < ?"
            params.append(before_id)
        query += " ORDER BY id DESC LIMIT 1"

        with self._connect() as conn:
            row = conn.execute(query, params).fetchone()
        return self._row_to_scan(row) if row else None

    def set_baseline(self, target: str, scan_id: int) -> None:
        with self._connect() as conn:
            conn.execute("UPDATE scans SET is_baseline = 0 WHERE target = ?", (target,))
            conn.execute("UPDATE scans SET is_baseline = 1 WHERE id = ? AND target = ?", (scan_id, target))

    def history(self, target: str, *, limit: int = 30) -> list[ScanRecord]:
        """Orden cronológico ascendente: así se grafica la tendencia directamente."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scans WHERE target = ? ORDER BY id DESC LIMIT ?", (target, limit)
            ).fetchall()
        return [self._row_to_scan(r) for r in reversed(rows)]

    def targets(self) -> list[str]:
        with self._connect() as conn:
            rows = conn.execute("SELECT DISTINCT target FROM scans ORDER BY target").fetchall()
        return [r["target"] for r in rows]

    # -- monitores ---------------------------------------------------------

    def add_monitor(
        self,
        *,
        target: str,
        schedule: str = "weekly",
        mode: str = "passive",
        webhook_url: str | None = None,
        created_at: str | None = None,
        modules: str = "all",
    ) -> MonitorRecord:
        if schedule not in SCHEDULES:
            raise ValueError(f"Cadencia inválida: {schedule!r}. Usa una de {sorted(SCHEDULES)}.")
        created_at = created_at or utcnow()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO monitors (target, schedule, mode, webhook_url, created_at, active, modules)"
                " VALUES (?, ?, ?, ?, ?, 1, ?)"
                " ON CONFLICT(target) DO UPDATE SET schedule = excluded.schedule,"
                " mode = excluded.mode, webhook_url = excluded.webhook_url,"
                " modules = excluded.modules, active = 1",
                (target, schedule, mode, webhook_url, created_at, modules),
            )
        return self.get_monitor(target)  # type: ignore[return-value]

    def _row_to_monitor(self, row: sqlite3.Row) -> MonitorRecord:
        return MonitorRecord(
            target=row["target"], schedule=row["schedule"], mode=row["mode"],
            webhook_url=row["webhook_url"], created_at=row["created_at"],
            last_run_at=row["last_run_at"], active=bool(row["active"]),
            modules=row["modules"] if "modules" in row.keys() else "all",
        )

    def get_monitor(self, target: str) -> MonitorRecord | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM monitors WHERE target = ?", (target,)).fetchone()
        return self._row_to_monitor(row) if row else None

    def list_monitors(self, *, only_active: bool = False) -> list[MonitorRecord]:
        query = "SELECT * FROM monitors"
        if only_active:
            query += " WHERE active = 1"
        query += " ORDER BY target"
        with self._connect() as conn:
            rows = conn.execute(query).fetchall()
        return [self._row_to_monitor(r) for r in rows]

    def remove_monitor(self, target: str) -> bool:
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM monitors WHERE target = ?", (target,))
        return cursor.rowcount > 0

    def mark_monitor_run(self, target: str, *, at: str | None = None) -> None:
        with self._connect() as conn:
            conn.execute("UPDATE monitors SET last_run_at = ? WHERE target = ?", (at or utcnow(), target))

    def due_monitors(self, *, now: str | None = None) -> list[MonitorRecord]:
        now = now or utcnow()
        return [m for m in self.list_monitors(only_active=True) if m.is_due(now=now)]
