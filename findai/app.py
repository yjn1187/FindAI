from __future__ import annotations

import hmac
import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .config import Settings
from .discovery import DiscoveryManager
from .gateway import ModelGateway, RouteError
from .storage import ServiceStore


class ScanRequest(BaseModel):
    cidrs: list[str] | None = None
    ports: list[int] | None = None
    schemes: list[str] = Field(default_factory=lambda: ["http"])


class CredentialRequest(BaseModel):
    api_key: str = Field(min_length=1, max_length=4096)


class ManualServiceRequest(BaseModel):
    base_url: str = Field(min_length=8, max_length=2048)
    api_key: str | None = Field(default=None, max_length=4096)


def _provided_key(request: Request) -> str | None:
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return request.headers.get("x-findai-key")


def _error(message: str, status_code: int, error_type: str = "findai_error") -> JSONResponse:
    return JSONResponse(
        {"error": {"message": message, "type": error_type, "param": None, "code": None}},
        status_code=status_code,
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    store = ServiceStore(settings.db_path)
    limits = httpx.Limits(
        max_connections=max(settings.max_concurrency + 32, 64),
        max_keepalive_connections=64,
        keepalive_expiry=20.0,
    )
    client = httpx.AsyncClient(
        limits=limits,
        follow_redirects=False,
        trust_env=False,
        verify=settings.tls_verify,
    )
    discovery = DiscoveryManager(settings, store, client)
    gateway = ModelGateway(store, discovery, client, settings.proxy_timeout_seconds)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        discovery.start_periodic()
        try:
            yield
        finally:
            await discovery.stop()
            await client.aclose()
            store.close()

    app = FastAPI(
        title="FindAI",
        version="1.0.0",
        description="LAN model discovery and OpenAI-compatible routing gateway.",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.store = store
    app.state.discovery = discovery
    app.state.gateway = gateway
    app.state.http_client = client

    @app.middleware("http")
    async def disable_dashboard_cache(request: Request, call_next):
        response = await call_next(request)
        if (
            request.url.path == "/"
            or request.url.path.startswith("/assets/")
            or request.url.path == "/api/scan"
        ):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        return response

    web_dir = Path(__file__).resolve().parent / "web"
    app.mount("/assets", StaticFiles(directory=web_dir), name="assets")

    async def require_admin(request: Request) -> None:
        # The dashboard is intentionally passwordless on loopback by default.
        # If a gateway key is configured it protects both management and proxy APIs.
        if settings.gateway_key:
            provided = _provided_key(request)
            if not provided or not hmac.compare_digest(provided, settings.gateway_key):
                raise HTTPException(status_code=401, detail="Invalid FindAI key")

    async def require_gateway(request: Request) -> None:
        if settings.gateway_key:
            provided = _provided_key(request)
            if not provided or not hmac.compare_digest(provided, settings.gateway_key):
                raise HTTPException(status_code=401, detail="Invalid FindAI key")

    @app.get("/", include_in_schema=False)
    async def dashboard() -> FileResponse:
        return FileResponse(web_dir / "index.html")

    @app.get("/healthz")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/config", dependencies=[Depends(require_admin)])
    async def config(request: Request) -> dict[str, Any]:
        return {
            "scan_cidrs": list(settings.scan_cidrs),
            "scan_ports": list(settings.scan_ports),
            "scan_interval_seconds": settings.scan_interval_seconds,
            "max_hosts": settings.max_hosts,
            "max_targets": settings.max_targets,
            "log_path": str(settings.log_path.expanduser().resolve()),
            "log_level": settings.log_level.upper(),
            "gateway_base_url": f"{str(request.base_url).rstrip('/')}/v1",
            "authentication_enabled": bool(settings.gateway_key),
        }

    @app.get("/api/services", dependencies=[Depends(require_admin)])
    async def list_services() -> dict[str, Any]:
        services = []
        for service in store.list():
            item = service.to_dict()
            item["routed_models"] = [f"{service.id}::{model}" for model in service.models]
            item["credential_loaded"] = bool(discovery.credential_for(service))
            services.append(item)
        return {"data": services}

    @app.delete("/api/services", dependencies=[Depends(require_admin)])
    async def clear_services() -> dict[str, int]:
        if discovery.state.status == "running":
            raise HTTPException(status_code=409, detail="扫描进行中，暂时不能清空服务列表")
        deleted = store.clear()
        discovery.clear_credentials()
        return {"deleted": deleted}

    @app.get("/api/scan", dependencies=[Depends(require_admin)])
    async def scan_status() -> dict[str, Any]:
        return discovery.state.to_dict()

    @app.post("/api/scan", status_code=202, dependencies=[Depends(require_admin)])
    async def start_scan(body: ScanRequest) -> dict[str, Any]:
        try:
            state = discovery.start_scan(body.cidrs, body.ports, body.schemes)
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return state.to_dict()

    @app.post("/api/services/manual", dependencies=[Depends(require_admin)])
    async def add_manual(body: ManualServiceRequest) -> dict[str, Any]:
        try:
            service = await discovery.add_manual(body.base_url, body.api_key)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return service.to_dict()

    @app.post("/api/services/{service_id}/probe", dependencies=[Depends(require_admin)])
    async def probe_service(service_id: str) -> dict[str, Any]:
        service = store.get(service_id)
        if not service:
            raise HTTPException(status_code=404, detail="Service not found")
        return (await discovery.probe_service(service)).to_dict()

    @app.put("/api/services/{service_id}/credential", dependencies=[Depends(require_admin)])
    async def set_credential(service_id: str, body: CredentialRequest) -> dict[str, Any]:
        service = store.get(service_id)
        if not service:
            raise HTTPException(status_code=404, detail="Service not found")
        discovery.set_credential(service_id, body.api_key)
        refreshed = await discovery.probe_service(service)
        return {"service": refreshed.to_dict(), "credential_loaded": True, "persisted": False}

    @app.get("/v1/models", dependencies=[Depends(require_gateway)])
    async def models() -> dict[str, Any]:
        return {"object": "list", "data": gateway.catalog()}

    @app.post("/v1/{path:path}", dependencies=[Depends(require_gateway)])
    async def proxy(path: str, request: Request) -> Response:
        try:
            payload = await request.json()
        except (json.JSONDecodeError, UnicodeDecodeError):
            return _error("Request body must be valid JSON", 400, "invalid_request_error")
        if not isinstance(payload, dict):
            return _error("Request body must be a JSON object", 400, "invalid_request_error")

        try:
            upstream, service, requested_model, upstream_model, ollama_native = (
                await gateway.open_upstream(path, payload)
            )
        except RouteError as exc:
            return _error(str(exc), 503, "findai_route_error")

        response_headers = {
            "X-FindAI-Service": service.id,
            "X-FindAI-Upstream-Model": quote(upstream_model, safe=":/._-"),
        }
        request_id = upstream.headers.get("x-request-id")
        if request_id:
            response_headers["X-Upstream-Request-Id"] = request_id

        if upstream.status_code >= 400:
            try:
                content = await upstream.aread()
            finally:
                await upstream.aclose()
            return Response(
                content=content,
                status_code=upstream.status_code,
                media_type=upstream.headers.get("content-type", "application/json"),
                headers=response_headers,
            )

        wants_stream = bool(payload.get("stream"))
        content_type = upstream.headers.get("content-type", "application/json")
        if ollama_native and wants_stream:
            return StreamingResponse(
                gateway.ollama_stream(upstream, requested_model),
                status_code=upstream.status_code,
                media_type="text/event-stream",
                headers=response_headers,
            )
        if ollama_native:
            content, media_type = await gateway.read_ollama_response(upstream, requested_model)
            return Response(
                content=content,
                status_code=upstream.status_code,
                media_type=media_type,
                headers=response_headers,
            )
        if wants_stream or "text/event-stream" in content_type:
            return StreamingResponse(
                gateway.passthrough_stream(upstream),
                status_code=upstream.status_code,
                media_type=content_type,
                headers=response_headers,
            )

        try:
            content = await upstream.aread()
        finally:
            await upstream.aclose()
        return Response(
            content=content,
            status_code=upstream.status_code,
            media_type=content_type,
            headers=response_headers,
        )

    return app
