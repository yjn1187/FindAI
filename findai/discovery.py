from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Iterable
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
from math import ceil
from urllib.parse import urlsplit

import httpx

from .config import Settings
from .models import ProbeResult, ScanLogEntry, ScanState, ServiceRecord, service_id_for
from .storage import ServiceStore


logger = logging.getLogger(__name__)
SCAN_LOG_LIMIT = 200


@dataclass(slots=True)
class _RangeScanProgress:
    total: int
    thresholds: tuple[int, ...]
    scanned: int = 0
    open_ports: int = 0
    services: int = 0
    threshold_index: int = 0


def _model_ids(payload: object, key: str) -> list[str]:
    if not isinstance(payload, dict):
        return []
    values = payload.get(key)
    if not isinstance(values, list):
        return []
    result: list[str] = []
    for value in values:
        if isinstance(value, str):
            result.append(value)
        elif isinstance(value, dict):
            model_id = value.get("id") or value.get("name") or value.get("model")
            if isinstance(model_id, str) and model_id:
                result.append(model_id)
    return sorted(set(result))


def _looks_like_openai_auth_error(response: httpx.Response) -> bool:
    challenge = response.headers.get("www-authenticate", "").lower()
    if "bearer" in challenge:
        return True
    try:
        payload = response.json()
    except (json.JSONDecodeError, ValueError):
        return False
    return isinstance(payload, dict) and isinstance(payload.get("error"), (dict, str))


class ProtocolProber:
    def __init__(self, client: httpx.AsyncClient, timeout_seconds: float):
        self.client = client
        self.timeout = httpx.Timeout(timeout_seconds)

    async def probe(self, base_url: str, api_key: str | None = None) -> ProbeResult:
        started = time.perf_counter()
        headers = {"Accept": "application/json", "User-Agent": "FindAI/1.0 discovery"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        openai_error: str | None = None
        try:
            response = await self.client.get(
                f"{base_url.rstrip('/')}/v1/models", headers=headers, timeout=self.timeout
            )
            latency = (time.perf_counter() - started) * 1000
            logger.debug(
                "OpenAI probe base_url=%s status=%d latency_ms=%.1f authenticated=%s",
                base_url,
                response.status_code,
                latency,
                bool(api_key),
            )
            if response.status_code == 200:
                try:
                    payload = response.json()
                except (json.JSONDecodeError, ValueError):
                    payload = None
                if isinstance(payload, dict) and isinstance(payload.get("data"), list):
                    models = _model_ids(payload, "data")
                    server = response.headers.get("server", "").lower()
                    vendor = "Ollama" if "ollama" in server else "OpenAI-compatible"
                    return ProbeResult(
                        matched=True,
                        api_kind="openai",
                        name=vendor,
                        models=models,
                        capabilities={
                            "models": True,
                            "chat_completions": True,
                            "streaming": True,
                            "openai_models": True,
                        },
                        latency_ms=latency,
                    )
                openai_error = "The /v1/models response was not an OpenAI model list"
            elif response.status_code in {401, 403} and _looks_like_openai_auth_error(response):
                logger.info(
                    "Protected OpenAI-compatible service detected base_url=%s status=%d",
                    base_url,
                    response.status_code,
                )
                return ProbeResult(
                    matched=True,
                    api_kind="openai",
                    name="Protected OpenAI-compatible service",
                    auth_required=True,
                    capabilities={
                        "models": False,
                        "chat_completions": True,
                        "streaming": True,
                        "openai_models": True,
                    },
                    latency_ms=latency,
                    error="API key required or rejected",
                )
            else:
                openai_error = f"/v1/models returned HTTP {response.status_code}"
        except httpx.HTTPError as exc:
            openai_error = str(exc)
            logger.debug("OpenAI probe failed base_url=%s error=%s", base_url, exc)

        # Ollama's native model-list endpoint lets FindAI discover older Ollama
        # releases that do not expose the OpenAI-compatible models endpoint.
        try:
            response = await self.client.get(
                f"{base_url.rstrip('/')}/api/tags", headers=headers, timeout=self.timeout
            )
            latency = (time.perf_counter() - started) * 1000
            if response.status_code == 200:
                try:
                    payload = response.json()
                except (json.JSONDecodeError, ValueError):
                    payload = None
                if isinstance(payload, dict) and isinstance(payload.get("models"), list):
                    logger.info("Native Ollama service detected base_url=%s", base_url)
                    return ProbeResult(
                        matched=True,
                        api_kind="ollama",
                        name="Ollama",
                        models=_model_ids(payload, "models"),
                        capabilities={
                            "models": True,
                            "chat_completions": True,
                            "streaming": True,
                            "openai_models": False,
                            "native_ollama": True,
                        },
                        latency_ms=latency,
                    )
        except httpx.HTTPError:
            pass

        return ProbeResult(matched=False, error=openai_error or "No compatible API fingerprint")


class DiscoveryManager:
    def __init__(
        self,
        settings: Settings,
        store: ServiceStore,
        client: httpx.AsyncClient,
    ):
        self.settings = settings
        self.store = store
        self.prober = ProtocolProber(client, settings.probe_timeout_seconds)
        self.state = ScanState()
        self._scan_task: asyncio.Task[None] | None = None
        self._periodic_task: asyncio.Task[None] | None = None
        self._credentials: dict[str, str] = {}

    def set_credential(self, service_id: str, api_key: str) -> None:
        self._credentials[service_id] = api_key

    def clear_credentials(self) -> None:
        self._credentials.clear()

    def _record_scan_log(self, message: str, level: str = "info") -> None:
        self.state.logs.append(
            ScanLogEntry(timestamp=time.time(), level=level, message=message)
        )
        if len(self.state.logs) > SCAN_LOG_LIMIT:
            del self.state.logs[:-SCAN_LOG_LIMIT]
        logger.info("Scan event level=%s message=%s", level, message)

    def credential_for(self, service: ServiceRecord | str, service_id: str | None = None) -> str | None:
        if isinstance(service, ServiceRecord):
            base_url, identifier = service.base_url, service.id
        else:
            base_url, identifier = service, service_id
        return self._credentials.get(identifier or "") or self.settings.upstream_keys.get(
            base_url.rstrip("/")
        )

    @staticmethod
    def validate_targets(
        cidrs: Iterable[str],
        ports: Iterable[int],
        schemes: Iterable[str],
        max_hosts: int,
        allowed_public_cidrs: Iterable[str] = (),
    ) -> tuple[list[IPv4Network], list[int], list[str]]:
        allowed_public_networks: list[IPv4Network] = []
        for value in allowed_public_cidrs:
            allowed = IPv4Network(value, strict=False)
            if allowed.prefixlen != 32 or not allowed.network_address.is_global:
                raise ValueError("Allowed public scan targets must be public IPv4 /32 hosts")
            allowed_public_networks.append(allowed)

        networks: list[IPv4Network] = []
        for value in cidrs:
            network = IPv4Network(value, strict=False)
            is_local = network.network_address.is_private or network.network_address.is_loopback
            is_explicitly_allowed = any(
                network.subnet_of(allowed) for allowed in allowed_public_networks
            )
            if not (is_local or is_explicitly_allowed):
                raise ValueError(
                    "Only private or loopback IPv4 networks may be scanned unless explicitly "
                    f"allowed by FINDAI_ALLOWED_PUBLIC_CIDRS: {network}"
                )
            networks.append(network)
        if not networks:
            raise ValueError("At least one CIDR is required")
        if sum(network.num_addresses for network in networks) > max_hosts:
            raise ValueError(f"Scan exceeds the configured limit of {max_hosts} IP addresses")

        normalized_ports = sorted(set(int(port) for port in ports))
        if not normalized_ports or any(port < 1 or port > 65535 for port in normalized_ports):
            raise ValueError("Ports must be between 1 and 65535")
        normalized_schemes = sorted(set(schemes))
        if not normalized_schemes or any(item not in {"http", "https"} for item in normalized_schemes):
            raise ValueError("Schemes must be http or https")
        return networks, normalized_ports, normalized_schemes

    async def _tcp_open(self, host: str, port: int) -> bool:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), self.settings.connect_timeout_seconds
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (TimeoutError, OSError):
            return False

    async def _probe_target(self, host: str, port: int, scheme: str) -> tuple[str | None, bool]:
        if not await self._tcp_open(host, port):
            return None, False
        self.state.open_ports += 1
        base_url = f"{scheme}://{host}:{port}"
        self._record_scan_log(
            f"TCP 端口开放：{base_url}；请求 GET /v1/models，未匹配时继续 GET /api/tags",
            "open",
        )
        identifier = service_id_for(base_url)
        result = await self.prober.probe(base_url, self.credential_for(base_url, identifier))
        if not result.matched:
            logger.debug("Open port is not a compatible model API base_url=%s error=%s", base_url, result.error)
            self._record_scan_log(
                f"未识别模型服务：{base_url}；已尝试 /v1/models 与 /api/tags",
                "info",
            )
            return None, True
        name = f"{result.name} · {host}:{port}"
        service = ServiceRecord(
            id=identifier,
            name=name,
            host=host,
            port=port,
            scheme=scheme,
            base_url=base_url,
            api_kind=result.api_kind,
            auth_required=result.auth_required,
            models=result.models,
            capabilities=result.capabilities,
            latency_ms=result.latency_ms,
            last_error=result.error,
        )
        self.store.upsert(service)
        logger.info(
            "Model service registered id=%s base_url=%s kind=%s models=%d auth_required=%s latency_ms=%s",
            service.id,
            service.base_url,
            service.api_kind,
            len(service.models),
            service.auth_required,
            round(service.latency_ms, 1) if service.latency_ms is not None else None,
        )
        endpoint = "/api/tags" if result.capabilities.get("native_ollama") else "/v1/models"
        auth_note = " · 需要 API Key" if result.auth_required else ""
        self._record_scan_log(
            f"命中模型服务：{base_url} · {result.api_kind} · {len(result.models)} 个模型"
            f"{auth_note} · 来源 GET {endpoint}",
            "success",
        )
        return base_url, True

    async def _run_scan(
        self, networks: list[IPv4Network], ports: list[int], schemes: list[str]
    ) -> None:
        alive: set[str] = set()
        known_in_scope = {
            service.base_url
            for service in self.store.list()
            if any(IPv4Address(service.host) in network for network in networks)
            and service.port in ports
            and service.scheme in schemes
        }
        queue: asyncio.Queue[
            tuple[str, int, str, tuple[str, int, str]] | None
        ] = asyncio.Queue()
        range_progress: dict[tuple[str, int, str], _RangeScanProgress] = {}
        for network in networks:
            addresses = [str(address) for address in network.hosts()]
            for port in ports:
                for scheme in schemes:
                    range_key = (str(network), port, scheme)
                    thresholds = tuple(sorted({
                        max(1, ceil(len(addresses) * fraction))
                        for fraction in (0.25, 0.5, 0.75, 1.0)
                    }))
                    range_progress[range_key] = _RangeScanProgress(
                        total=len(addresses), thresholds=thresholds
                    )
                    for address in addresses:
                        queue.put_nowait((address, port, scheme, range_key))

        async def worker() -> None:
            while True:
                target = await queue.get()
                if target is None:
                    queue.task_done()
                    return
                host, port, scheme, range_key = target
                progress = range_progress[range_key]
                try:
                    found, open_port = await self._probe_target(host, port, scheme)
                    if open_port:
                        progress.open_ports += 1
                    if found:
                        alive.add(found)
                        progress.services += 1
                        self.state.discovered = len(alive)
                except Exception as exc:
                    # A malformed response from one host must not strand the
                    # worker queue or abort the rest of the LAN scan.
                    logger.warning(
                        "Target probe raised an unexpected error host=%s port=%d scheme=%s error=%s",
                        host,
                        port,
                        scheme,
                        exc,
                    )
                finally:
                    progress.scanned += 1
                    self.state.scanned += 1
                    while (
                        progress.threshold_index < len(progress.thresholds)
                        and progress.scanned >= progress.thresholds[progress.threshold_index]
                    ):
                        completed = progress.scanned >= progress.total
                        label = "范围完成" if completed else "范围进度"
                        self._record_scan_log(
                            f"{label}：{range_key[0]} · {range_key[2]}:{range_key[1]} · "
                            f"{progress.scanned}/{progress.total} 地址；开放 "
                            f"{progress.open_ports}，服务 {progress.services}",
                            "active" if completed else "progress",
                        )
                        progress.threshold_index += 1
                    queue.task_done()

        workers = [
            asyncio.create_task(worker())
            for _ in range(
                min(max(self.settings.max_concurrency, 1), max(queue.qsize(), 1))
            )
        ]
        for _ in workers:
            queue.put_nowait(None)

        try:
            await queue.join()
            await asyncio.gather(*workers)
            self.store.reconcile(known_in_scope, alive)
            self.state.discovered = len(alive)
            self.state.status = "completed"
            self._record_scan_log(
                f"扫描完成：检查 {self.state.scanned} 个目标，开放 "
                f"{self.state.open_ports} 个端口，发现 {self.state.discovered} 个模型服务",
                "success",
            )
            logger.info(
                "LAN scan completed scanned=%d open_ports=%d discovered=%d duration_seconds=%.2f",
                self.state.scanned,
                self.state.open_ports,
                self.state.discovered,
                time.time() - (self.state.started_at or time.time()),
            )
        except asyncio.CancelledError:
            self.state.status = "cancelled"
            self._record_scan_log("扫描已取消", "error")
            for worker_task in workers:
                worker_task.cancel()
            raise
        except Exception as exc:  # keep the scheduler alive after one failed scan
            self.state.status = "failed"
            self.state.error = str(exc)
            self._record_scan_log(f"扫描失败：{exc}", "error")
            logger.exception("LAN scan failed")
        finally:
            self.state.finished_at = time.time()

    def start_scan(
        self,
        cidrs: Iterable[str] | None = None,
        ports: Iterable[int] | None = None,
        schemes: Iterable[str] | None = None,
    ) -> ScanState:
        if self._scan_task and not self._scan_task.done():
            raise RuntimeError("A scan is already running")
        networks, normalized_ports, normalized_schemes = self.validate_targets(
            cidrs or self.settings.scan_cidrs,
            ports or self.settings.scan_ports,
            schemes or ("http",),
            self.settings.max_hosts,
            self.settings.allowed_public_cidrs,
        )
        total_addresses = sum(sum(1 for _ in network.hosts()) for network in networks)
        total_targets = total_addresses * len(normalized_ports) * len(normalized_schemes)
        if total_targets > self.settings.max_targets:
            raise ValueError(
                f"Scan expands to {total_targets} host/port targets; "
                f"the configured limit is {self.settings.max_targets}"
            )
        self.state = ScanState(
            status="running",
            cidrs=[str(network) for network in networks],
            ports=normalized_ports,
            total=total_targets,
            started_at=time.time(),
        )
        self._record_scan_log(
            f"开始扫描：{', '.join(self.state.cidrs)} · {len(normalized_ports)} 个端口 · "
            f"{total_targets} 个目标",
            "active",
        )
        self._record_scan_log(
            "探测流程：TCP 连接 → GET /v1/models → 未匹配时 GET /api/tags；"
            "关闭端口仅计入范围汇总，不逐条记录",
            "info",
        )
        logger.info(
            "LAN scan started cidrs=%s ports=%s schemes=%s targets=%d concurrency=%d",
            ",".join(str(network) for network in networks),
            ",".join(str(port) for port in normalized_ports),
            ",".join(normalized_schemes),
            total_targets,
            max(self.settings.max_concurrency, 1),
        )
        self._scan_task = asyncio.create_task(
            self._run_scan(networks, normalized_ports, normalized_schemes),
            name="findai-lan-scan",
        )
        return self.state

    async def probe_service(self, service: ServiceRecord) -> ServiceRecord:
        result = await self.prober.probe(service.base_url, self.credential_for(service))
        if not result.matched:
            self.store.mark_failed(service.id, result.error or "Probe failed")
            logger.warning(
                "Registered service probe failed id=%s base_url=%s error=%s",
                service.id,
                service.base_url,
                result.error,
            )
        else:
            service.name = f"{result.name} · {service.host}:{service.port}"
            service.api_kind = result.api_kind
            service.status = "online"
            service.auth_required = result.auth_required
            service.models = result.models
            service.capabilities = result.capabilities
            service.latency_ms = result.latency_ms
            service.last_seen = time.time()
            service.last_error = result.error
            service.failure_count = 0
            self.store.upsert(service)
            logger.info(
                "Registered service refreshed id=%s base_url=%s models=%d auth_required=%s",
                service.id,
                service.base_url,
                len(service.models),
                service.auth_required,
            )
        return self.store.get(service.id) or service

    async def add_manual(self, base_url: str, api_key: str | None = None) -> ServiceRecord:
        parts = urlsplit(base_url.rstrip("/"))
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ValueError("base_url must be an http(s) URL")
        if parts.username or parts.password:
            raise ValueError("Credentials must not be embedded in base_url")
        try:
            port = parts.port or (443 if parts.scheme == "https" else 80)
        except ValueError as exc:
            raise ValueError("base_url contains an invalid port") from exc
        try:
            addresses = {item[4][0] for item in await asyncio.get_running_loop().getaddrinfo(
                parts.hostname, port, family=2, type=1
            )}
        except OSError as exc:
            raise ValueError(f"Unable to resolve host: {parts.hostname}") from exc
        allowed_public_networks = [
            IPv4Network(value, strict=False) for value in self.settings.allowed_public_cidrs
        ]
        if not addresses or any(
            not (
                IPv4Address(address).is_private
                or IPv4Address(address).is_loopback
                or any(IPv4Address(address) in network for network in allowed_public_networks)
            )
            for address in addresses
        ):
            raise ValueError(
                "Manual services must resolve only to private, loopback, or explicitly allowed "
                "public IPv4 addresses"
            )
        # Pin the validated address to prevent a later DNS change from turning
        # a registered hostname into a proxy target outside the approved set.
        pinned_address = sorted(addresses)[0]
        normalized = f"{parts.scheme}://{pinned_address}:{port}"
        identifier = service_id_for(normalized)
        if api_key:
            self.set_credential(identifier, api_key)
        result = await self.prober.probe(normalized, self.credential_for(normalized, identifier))
        if not result.matched:
            raise ValueError(result.error or "No compatible service found")
        service = ServiceRecord(
            id=identifier,
            name=f"{result.name} · {parts.hostname}:{port}",
            host=pinned_address,
            port=port,
            scheme=parts.scheme,
            base_url=normalized,
            api_kind=result.api_kind,
            auth_required=result.auth_required,
            models=result.models,
            capabilities=result.capabilities,
            latency_ms=result.latency_ms,
            last_error=result.error,
        )
        self.store.upsert(service)
        logger.info(
            "Manual service registered id=%s base_url=%s models=%d auth_required=%s",
            service.id,
            service.base_url,
            len(service.models),
            service.auth_required,
        )
        return service

    async def _periodic_loop(self) -> None:
        if self.settings.scan_on_startup:
            await asyncio.sleep(0.2)
            try:
                self.start_scan()
            except (RuntimeError, ValueError):
                pass
        if self.settings.scan_interval_seconds <= 0:
            return
        while True:
            await asyncio.sleep(max(self.settings.scan_interval_seconds, 10))
            if not self._scan_task or self._scan_task.done():
                try:
                    self.start_scan()
                except (RuntimeError, ValueError):
                    pass

    def start_periodic(self) -> None:
        if not self.settings.scan_on_startup and self.settings.scan_interval_seconds <= 0:
            return
        self._periodic_task = asyncio.create_task(
            self._periodic_loop(), name="findai-periodic-discovery"
        )

    async def stop(self) -> None:
        tasks = [task for task in (self._scan_task, self._periodic_task) if task and not task.done()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
