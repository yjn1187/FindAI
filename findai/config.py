from __future__ import annotations

import json
import os
import socket
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

from dotenv import load_dotenv


DEFAULT_PORTS = (11434, 1234, 8080, 8000, 8001, 5000, 3000, 8888, 80)


def load_env_file(path: Path | None = None) -> Path | None:
    """Load FindAI's dotenv file without overriding process environment values."""

    configured_path = os.getenv("FINDAI_ENV_FILE")
    env_path = path or (Path(configured_path) if configured_path else Path.cwd() / ".env")
    env_path = env_path.expanduser().resolve()
    if not env_path.is_file():
        return None
    load_dotenv(dotenv_path=env_path, override=False)
    return env_path


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def parse_ports(value: str | None) -> tuple[int, ...]:
    if not value:
        return DEFAULT_PORTS
    ports: set[int] = set()
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        if "-" in item:
            start_text, end_text = item.split("-", 1)
            start, end = int(start_text), int(end_text)
            if start > end or end - start > 1000:
                raise ValueError(f"Invalid or overly broad port range: {item}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(item))
    if not ports or any(port < 1 or port > 65535 for port in ports):
        raise ValueError("Ports must be between 1 and 65535")
    return tuple(sorted(ports))


def parse_allowed_public_cidrs(value: str | None) -> tuple[str, ...]:
    """Parse explicitly trusted public IPv4 hosts.

    Public scanning is intentionally limited to individual /32 hosts so an
    operator cannot accidentally turn FindAI into a broad internet scanner.
    """

    if not value:
        return ()
    networks: set[str] = set()
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        network = IPv4Network(item, strict=False)
        if network.prefixlen != 32 or not network.network_address.is_global:
            raise ValueError(
                "FINDAI_ALLOWED_PUBLIC_CIDRS entries must be public IPv4 hosts using /32"
            )
        networks.add(str(network))
    return tuple(sorted(networks))


def parse_scan_cidr_presets(value: str | None) -> dict[str, str]:
    """Parse named scan ranges displayed by the dashboard's CIDR selector."""

    if not value:
        return {}
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError("FINDAI_SCAN_CIDR_PRESETS must be a JSON object") from exc
    if not isinstance(payload, dict):
        raise ValueError("FINDAI_SCAN_CIDR_PRESETS must be a JSON object")
    if len(payload) > 50:
        raise ValueError("FINDAI_SCAN_CIDR_PRESETS supports at most 50 entries")

    presets: dict[str, str] = {}
    for raw_name, raw_cidrs in payload.items():
        name = str(raw_name).strip()
        if not name or len(name) > 60:
            raise ValueError(
                "FINDAI_SCAN_CIDR_PRESETS names must contain 1 to 60 characters"
            )
        if isinstance(raw_cidrs, str):
            values = raw_cidrs.split(",")
        elif isinstance(raw_cidrs, list) and all(
            isinstance(item, str) for item in raw_cidrs
        ):
            values = [part for item in raw_cidrs for part in item.split(",")]
        else:
            raise ValueError(
                "FINDAI_SCAN_CIDR_PRESETS values must be CIDR strings or string arrays"
            )

        normalized: list[str] = []
        seen: set[str] = set()
        for item in values:
            item = item.strip()
            if not item:
                continue
            try:
                network = str(IPv4Network(item, strict=False))
            except ValueError as exc:
                raise ValueError(
                    f"FINDAI_SCAN_CIDR_PRESETS contains an invalid IPv4 range: {item}"
                ) from exc
            if network not in seen:
                seen.add(network)
                normalized.append(network)
        if not normalized:
            raise ValueError(
                f"FINDAI_SCAN_CIDR_PRESETS entry {name!r} has no IPv4 ranges"
            )
        presets[name] = ",".join(normalized)
    return presets


def infer_local_cidrs() -> tuple[str, ...]:
    """Infer useful IPv4 scan ranges without platform-specific dependencies.

    Python's socket API does not expose interface netmasks portably, so inferred
    private addresses intentionally use a conservative /24. Operators can set
    FINDAI_SCAN_CIDRS when their LAN uses another prefix.
    """

    addresses: set[IPv4Address] = set()
    try:
        for result in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addresses.add(IPv4Address(result[4][0]))
    except (OSError, ValueError):
        pass

    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))
        addresses.add(IPv4Address(probe.getsockname()[0]))
    except (OSError, ValueError):
        pass
    finally:
        probe.close()

    networks = {
        str(IPv4Network(f"{address}/24", strict=False))
        for address in addresses
        if address.is_private and not address.is_loopback and not address.is_link_local
    }
    return tuple(sorted(networks)) or ("127.0.0.1/32",)


@dataclass(slots=True)
class Settings:
    host: str = "127.0.0.1"
    port: int = 7070
    db_path: Path = Path("data/findai.db")
    scan_cidrs: tuple[str, ...] = field(default_factory=infer_local_cidrs)
    scan_cidr_presets: dict[str, str] = field(default_factory=dict)
    allowed_public_cidrs: tuple[str, ...] = ()
    scan_ports: tuple[int, ...] = DEFAULT_PORTS
    scan_interval_seconds: int = 0
    connect_timeout_seconds: float = 0.35
    probe_timeout_seconds: float = 2.0
    proxy_timeout_seconds: float = 300.0
    tls_verify: bool = False
    max_concurrency: int = 256
    max_hosts: int = 1024
    max_targets: int = 20000
    scan_on_startup: bool = False
    gateway_key: str | None = None
    upstream_keys: dict[str, str] = field(default_factory=dict)
    log_path: Path = Path("data/logs/findai.log")
    log_level: str = "INFO"
    log_max_bytes: int = 10 * 1024 * 1024
    log_backup_count: int = 5

    @classmethod
    def from_env(cls, env_file: Path | None = None) -> "Settings":
        load_env_file(env_file)
        cidrs_value = os.getenv("FINDAI_SCAN_CIDRS", "")
        cidrs = tuple(item.strip() for item in cidrs_value.split(",") if item.strip())
        keys_value = os.getenv("FINDAI_UPSTREAM_KEYS", "{}")
        try:
            upstream_keys = json.loads(keys_value)
            if not isinstance(upstream_keys, dict):
                raise ValueError("must be a JSON object")
        except (json.JSONDecodeError, ValueError) as exc:
            raise ValueError("FINDAI_UPSTREAM_KEYS must be a JSON object") from exc

        return cls(
            host=os.getenv("FINDAI_HOST", "127.0.0.1"),
            port=int(os.getenv("FINDAI_PORT", "7070")),
            db_path=Path(os.getenv("FINDAI_DB_PATH", "data/findai.db")),
            scan_cidrs=cidrs or infer_local_cidrs(),
            scan_cidr_presets=parse_scan_cidr_presets(
                os.getenv("FINDAI_SCAN_CIDR_PRESETS")
            ),
            allowed_public_cidrs=parse_allowed_public_cidrs(
                os.getenv("FINDAI_ALLOWED_PUBLIC_CIDRS")
            ),
            scan_ports=parse_ports(os.getenv("FINDAI_SCAN_PORTS")),
            scan_interval_seconds=int(os.getenv("FINDAI_SCAN_INTERVAL", "0")),
            connect_timeout_seconds=float(os.getenv("FINDAI_CONNECT_TIMEOUT", "0.35")),
            probe_timeout_seconds=float(os.getenv("FINDAI_PROBE_TIMEOUT", "2")),
            proxy_timeout_seconds=float(os.getenv("FINDAI_PROXY_TIMEOUT", "300")),
            tls_verify=_env_bool("FINDAI_TLS_VERIFY", False),
            max_concurrency=int(os.getenv("FINDAI_MAX_CONCURRENCY", "256")),
            max_hosts=int(os.getenv("FINDAI_MAX_HOSTS", "1024")),
            max_targets=int(os.getenv("FINDAI_MAX_TARGETS", "20000")),
            scan_on_startup=_env_bool("FINDAI_SCAN_ON_STARTUP", False),
            gateway_key=os.getenv("FINDAI_GATEWAY_KEY") or None,
            upstream_keys={str(key).rstrip("/"): str(value) for key, value in upstream_keys.items()},
            log_path=Path(os.getenv("FINDAI_LOG_PATH", "data/logs/findai.log")),
            log_level=os.getenv("FINDAI_LOG_LEVEL", "INFO"),
            log_max_bytes=int(os.getenv("FINDAI_LOG_MAX_BYTES", str(10 * 1024 * 1024))),
            log_backup_count=int(os.getenv("FINDAI_LOG_BACKUP_COUNT", "5")),
        )
