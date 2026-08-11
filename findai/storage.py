from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from .credentials import LocalCredentialFile
from .models import ServiceRecord, credential_fingerprint


class ServiceStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._credential_file = LocalCredentialFile(path.parent / "credentials.json")
        self._initialize()

    def _initialize(self) -> None:
        with self._lock, self._connection:
            table = self._connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'services'"
            ).fetchone()
            if table is None:
                self._create_services_table("services")
            elif self._requires_multi_credential_migration():
                self._migrate_to_multi_credential_schema()
            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_services_base_url ON services(base_url)"
            )

    def _create_services_table(self, table_name: str) -> None:
        self._connection.execute(
            f"""
            CREATE TABLE {table_name} (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                scheme TEXT NOT NULL,
                base_url TEXT NOT NULL,
                api_kind TEXT NOT NULL,
                status TEXT NOT NULL,
                auth_required INTEGER NOT NULL DEFAULT 0,
                models_json TEXT NOT NULL DEFAULT '[]',
                capabilities_json TEXT NOT NULL DEFAULT '{{}}',
                latency_ms REAL,
                last_seen REAL NOT NULL,
                last_error TEXT,
                failure_count INTEGER NOT NULL DEFAULT 0,
                credential_name TEXT,
                credential_id TEXT
            )
            """
        )

    def _requires_multi_credential_migration(self) -> bool:
        columns = {
            row["name"] for row in self._connection.execute("PRAGMA table_info(services)")
        }
        if "credential_name" not in columns or "credential_id" not in columns:
            return True
        for index in self._connection.execute("PRAGMA index_list(services)"):
            if not index["unique"]:
                continue
            indexed_columns = {
                row["name"]
                for row in self._connection.execute(
                    f"PRAGMA index_info('{index['name']}')"
                )
            }
            if indexed_columns == {"base_url"}:
                return True
        return False

    def _migrate_to_multi_credential_schema(self) -> None:
        columns = {
            row["name"] for row in self._connection.execute("PRAGMA table_info(services)")
        }
        self._connection.execute("DROP TABLE IF EXISTS services_multi_credential")
        self._create_services_table("services_multi_credential")
        credential_expression = "credential_name" if "credential_name" in columns else "NULL"
        credential_id_expression = "credential_id" if "credential_id" in columns else "NULL"
        self._connection.execute(
            f"""
            INSERT INTO services_multi_credential (
                id, name, host, port, scheme, base_url, api_kind, status,
                auth_required, models_json, capabilities_json, latency_ms,
                last_seen, last_error, failure_count, credential_name, credential_id
            )
            SELECT
                id, name, host, port, scheme, base_url, api_kind, status,
                auth_required, models_json, capabilities_json, latency_ms,
                last_seen, last_error, failure_count, {credential_expression},
                {credential_id_expression}
            FROM services
            """
        )
        self._connection.execute("DROP TABLE services")
        self._connection.execute(
            "ALTER TABLE services_multi_credential RENAME TO services"
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
            credential_name=row["credential_name"],
            credential_id=row["credential_id"],
        )

    def upsert(self, service: ServiceRecord) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO services (
                    id, name, host, port, scheme, base_url, api_kind, status,
                    auth_required, models_json, capabilities_json, latency_ms,
                    last_seen, last_error, failure_count, credential_name, credential_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    failure_count=excluded.failure_count,
                    credential_name=excluded.credential_name,
                    credential_id=excluded.credential_id
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
                    service.credential_name,
                    service.credential_id,
                ),
            )

    @property
    def credential_protection_mode(self) -> str:
        return "file"

    @property
    def credential_file_path(self) -> Path:
        return self._credential_file.path

    def save_credential(self, api_key: str, name: str | None = None) -> str:
        credential_id = credential_fingerprint(api_key)
        normalized_name = (name or "").strip()[:60]
        with self._lock:
            self._credential_file.save(credential_id, normalized_name, api_key)
        return credential_id

    def get_credential(self, credential_id: str) -> str | None:
        with self._lock:
            return self._credential_file.get(credential_id)

    def list_credentials(self) -> list[tuple[str, str, str]]:
        with self._lock:
            return self._credential_file.list()

    def delete_credential(self, credential_id: str) -> bool:
        with self._lock, self._connection:
            self._connection.execute(
                """
                UPDATE services
                SET credential_id = NULL, status = 'offline',
                    last_error = 'Stored credential was deleted'
                WHERE credential_id = ?
                """,
                (credential_id,),
            )
            return self._credential_file.delete(credential_id)

    def assign_credential(self, service_id: str, credential_id: str) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                "UPDATE services SET credential_id = ? WHERE id = ?",
                (credential_id, service_id),
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
        services = self.list_by_base_url(base_url)
        return services[0] if services else None

    def list_by_base_url(self, base_url: str) -> list[ServiceRecord]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM services WHERE base_url = ? ORDER BY id",
                (base_url.rstrip("/"),),
            ).fetchall()
        return [self._from_row(row) for row in rows]

    def delete(self, service_id: str) -> bool:
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "DELETE FROM services WHERE id = ?", (service_id,)
            )
        return cursor.rowcount > 0

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

    def reconcile(self, scanned_service_ids: set[str], alive_service_ids: set[str]) -> None:
        offline = scanned_service_ids - alive_service_ids
        if not offline:
            return
        with self._lock, self._connection:
            self._connection.executemany(
                """
                UPDATE services
                SET status = 'offline', last_error = 'No compatible service detected during latest scan',
                    failure_count = failure_count + 1
                WHERE id = ?
                """,
                [(service_id,) for service_id in offline],
            )

    def clear(self) -> int:
        with self._lock, self._connection:
            cursor = self._connection.execute("DELETE FROM services")
        return max(cursor.rowcount, 0)

    def close(self) -> None:
        with self._lock:
            self._connection.close()
