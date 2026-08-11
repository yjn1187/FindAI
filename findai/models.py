from __future__ import annotations

import hashlib
import time
from dataclasses import asdict, dataclass, field
from typing import Any


def credential_fingerprint(api_key: str) -> str:
    """Return a stable SHA-256 fingerprint without retaining the raw credential."""

    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def service_id_for(base_url: str, credential_id: str | None = None) -> str:
    normalized = base_url.rstrip("/").lower()
    identity = normalized if not credential_id else f"{normalized}\ncredential:{credential_id}"
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12]


@dataclass(slots=True)
class ServiceRecord:
    id: str
    name: str
    host: str
    port: int
    scheme: str
    base_url: str
    api_kind: str
    status: str = "online"
    auth_required: bool = False
    models: list[str] = field(default_factory=list)
    capabilities: dict[str, Any] = field(default_factory=dict)
    latency_ms: float | None = None
    last_seen: float = field(default_factory=time.time)
    last_error: str | None = None
    failure_count: int = 0
    credential_name: str | None = None
    credential_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("credential_id", None)
        return data


@dataclass(slots=True)
class ProbeResult:
    matched: bool
    api_kind: str = "unknown"
    name: str = "Unknown model service"
    models: list[str] = field(default_factory=list)
    auth_required: bool = False
    capabilities: dict[str, Any] = field(default_factory=dict)
    latency_ms: float | None = None
    error: str | None = None


@dataclass(slots=True)
class ScanLogEntry:
    timestamp: float
    level: str
    message: str


@dataclass(slots=True)
class ScanState:
    status: str = "idle"
    cidrs: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    total: int = 0
    scanned: int = 0
    open_ports: int = 0
    discovered: int = 0
    started_at: float | None = None
    finished_at: float | None = None
    error: str | None = None
    logs: list[ScanLogEntry] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["progress"] = round(self.scanned / self.total * 100, 1) if self.total else 0.0
        return data
