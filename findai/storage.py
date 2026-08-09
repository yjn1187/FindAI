from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from .models import ServiceRecord


class ServiceStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._initialize()

    def _initialize(self) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS services (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    scheme TEXT NOT NULL,
                    base_url TEXT NOT NULL UNIQUE,
                    api_kind TEXT NOT NULL,
                    status TEXT NOT NULL,
                    auth_required INTEGER NOT NULL DEFAULT 0,
                    models_json TEXT NOT NULL DEFAULT '[]',
                    capabilities_json TEXT NOT NULL DEFAULT '{}',
                    latency_ms REAL,
                    last_seen REAL NOT NULL,
                    last_error TEXT,
                    failure_count INTEGER NOT NULL DEFAULT 0
                )
                """
            )

    @staticmethod
    def _from_row(row: sqlite3.Row) -> ServiceRecord:
        return ServiceRecord(
            id=row["id"],
            name=row["name"],
            host=row["host"],
            port=row["port"],
            scheme=row["scheme"],
            base_url=row["base_url"],
            api_kind=row["api_kind"],
            status=row["status"],
            auth_required=bool(row["auth_required"]),
            models=json.loads(row["models_json"]),
            capabilities=json.loads(row["capabilities_json"]),
            latency_ms=row["latency_ms"],
            last_seen=row["last_seen"],
            last_error=row["last_error"],
            failure_count=row["failure_count"],
        )

    def upsert(self, service: ServiceRecord) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO services (
                    id, name, host, port, scheme, base_url, api_kind, status,
                    auth_required, models_json, capabilities_json, latency_ms,
                    last_seen, last_error, failure_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name,
                    host=excluded.host,
                    port=excluded.port,
                    scheme=excluded.scheme,
                    base_url=excluded.base_url,
                    api_kind=excluded.api_kind,
                    status=excluded.status,
                    auth_required=excluded.auth_required,
                    models_json=excluded.models_json,
                    capabilities_json=excluded.capabilities_json,
                    latency_ms=excluded.latency_ms,
                    last_seen=excluded.last_seen,
                    last_error=excluded.last_error,
                    failure_count=excluded.failure_count
                """,
                (
                    service.id,
                    service.name,
                    service.host,
                    service.port,
                    service.scheme,
                    service.base_url,
                    service.api_kind,
                    service.status,
                    int(service.auth_required),
                    json.dumps(service.models, ensure_ascii=False),
                    json.dumps(service.capabilities, ensure_ascii=False),
                    service.latency_ms,
                    service.last_seen,
                    service.last_error,
                    service.failure_count,
                ),
            )

    def list(self, *, online_only: bool = False) -> list[ServiceRecord]:
        query = "SELECT * FROM services"
        parameters: tuple[object, ...] = ()
        if online_only:
            query += " WHERE status = ?"
            parameters = ("online",)
        query += " ORDER BY status DESC, latency_ms IS NULL, latency_ms, name"
        with self._lock:
            rows = self._connection.execute(query, parameters).fetchall()
        return [self._from_row(row) for row in rows]

    def get(self, service_id: str) -> ServiceRecord | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM services WHERE id = ?", (service_id,)
            ).fetchone()
        return self._from_row(row) if row else None

    def get_by_base_url(self, base_url: str) -> ServiceRecord | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM services WHERE base_url = ?", (base_url.rstrip("/"),)
            ).fetchone()
        return self._from_row(row) if row else None

    def mark_failed(self, service_id: str, error: str) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                UPDATE services
                SET status = 'offline', last_error = ?, failure_count = failure_count + 1
                WHERE id = ?
                """,
                (error[:500], service_id),
            )

    def reconcile(self, scanned_base_urls: set[str], alive_base_urls: set[str]) -> None:
        offline = scanned_base_urls - alive_base_urls
        if not offline:
            return
        with self._lock, self._connection:
            self._connection.executemany(
                """
                UPDATE services
                SET status = 'offline', last_error = 'No compatible service detected during latest scan',
                    failure_count = failure_count + 1
                WHERE base_url = ?
                """,
                [(base_url,) for base_url in offline],
            )

    def close(self) -> None:
        with self._lock:
            self._connection.close()

