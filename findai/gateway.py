from __future__ import annotations

import json
import logging
import time
import uuid
from collections.abc import AsyncIterator
from typing import Any

import httpx

from .discovery import DiscoveryManager
from .models import ServiceRecord
from .storage import ServiceStore


logger = logging.getLogger(__name__)


class RouteError(ValueError):
    pass


class ModelGateway:
    def __init__(
        self,
        store: ServiceStore,
        discovery: DiscoveryManager,
        client: httpx.AsyncClient,
        proxy_timeout_seconds: float,
    ):
        self.store = store
        self.discovery = discovery
        self.client = client
        self.proxy_timeout = httpx.Timeout(proxy_timeout_seconds, connect=10.0)

    def catalog(self) -> list[dict[str, Any]]:
        now = int(time.time())
        models: list[dict[str, Any]] = []
        for service in self.store.list(online_only=True):
            for model in service.models:
                models.append(
                    {
                        "id": f"{service.id}::{model}",
                        "object": "model",
                        "created": int(service.last_seen) if service.last_seen else now,
                        "owned_by": f"findai/{service.api_kind}",
                        "findai": {
                            "service_id": service.id,
                            "service_name": service.name,
                            "upstream_model": model,
                        },
                    }
                )
        return models

    def resolve(self, model: str) -> tuple[ServiceRecord, str]:
        if "::" in model:
            service_id, upstream_model = model.split("::", 1)
            service = self.store.get(service_id)
            if not service or service.status != "online":
                raise RouteError(f"Service {service_id!r} is unavailable")
            if not upstream_model:
                raise RouteError("The routed model name is empty")
            return service, upstream_model

        candidates = [
            service
            for service in self.store.list(online_only=True)
            if model in service.models
        ]
        if not candidates:
            raise RouteError(
                f"No online service advertises model {model!r}; use GET /v1/models for routed IDs"
            )
        candidates.sort(
            key=lambda item: (
                item.failure_count,
                item.latency_ms is None,
                item.latency_ms if item.latency_ms is not None else float("inf"),
            )
        )
        return candidates[0], model

    def upstream_headers(self, service: ServiceRecord) -> dict[str, str]:
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "User-Agent": "FindAI/1.0 gateway",
        }
        api_key = self.discovery.credential_for(service)
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        return headers

    @staticmethod
    def _ollama_payload(payload: dict[str, Any], upstream_model: str) -> dict[str, Any]:
        translated: dict[str, Any] = {
            "model": upstream_model,
            "messages": payload.get("messages", []),
            "stream": bool(payload.get("stream", False)),
        }
        for key in ("tools", "tool_choice", "keep_alive"):
            if key in payload:
                translated[key] = payload[key]
        options: dict[str, Any] = {}
        for source, target in (
            ("temperature", "temperature"),
            ("top_p", "top_p"),
            ("seed", "seed"),
            ("stop", "stop"),
            ("max_tokens", "num_predict"),
            ("max_completion_tokens", "num_predict"),
        ):
            if source in payload:
                options[target] = payload[source]
        if options:
            translated["options"] = options
        response_format = payload.get("response_format")
        if isinstance(response_format, dict) and response_format.get("type") == "json_object":
            translated["format"] = "json"
        return translated

    @staticmethod
    def _ollama_non_stream(payload: dict[str, Any], requested_model: str) -> dict[str, Any]:
        message = payload.get("message") if isinstance(payload.get("message"), dict) else {}
        prompt_tokens = payload.get("prompt_eval_count", 0) or 0
        completion_tokens = payload.get("eval_count", 0) or 0
        return {
            "id": f"chatcmpl-findai-{uuid.uuid4().hex[:16]}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": requested_model,
            "choices": [
                {
                    "index": 0,
                    "message": message,
                    "finish_reason": "stop" if payload.get("done") else None,
                }
            ],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
            },
        }

    @staticmethod
    async def _ollama_stream(
        response: httpx.Response, requested_model: str
    ) -> AsyncIterator[bytes]:
        stream_id = f"chatcmpl-findai-{uuid.uuid4().hex[:16]}"
        try:
            async for line in response.aiter_lines():
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                message = payload.get("message") if isinstance(payload.get("message"), dict) else {}
                chunk = {
                    "id": stream_id,
                    "object": "chat.completion.chunk",
                    "created": int(time.time()),
                    "model": requested_model,
                    "choices": [
                        {
                            "index": 0,
                            "delta": message,
                            "finish_reason": "stop" if payload.get("done") else None,
                        }
                    ],
                }
                yield f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n".encode("utf-8")
            yield b"data: [DONE]\n\n"
        finally:
            await response.aclose()

    async def open_upstream(
        self, path: str, payload: dict[str, Any]
    ) -> tuple[httpx.Response, ServiceRecord, str, str, bool]:
        segments = path.replace("\\", "/").split("/")
        if not path or "\\" in path or any(segment in {".", ".."} for segment in segments):
            raise RouteError("Invalid upstream API path")
        requested_model = payload.get("model")
        if not isinstance(requested_model, str) or not requested_model:
            raise RouteError("A non-empty JSON model field is required")
        service, upstream_model = self.resolve(requested_model)
        forwarded = dict(payload)
        forwarded["model"] = upstream_model
        ollama_native = service.api_kind == "ollama" and path == "chat/completions"
        if ollama_native:
            endpoint = f"{service.base_url}/api/chat"
            forwarded = self._ollama_payload(payload, upstream_model)
        else:
            endpoint = f"{service.base_url}/v1/{path.lstrip('/')}"

        request = self.client.build_request(
            "POST",
            endpoint,
            headers=self.upstream_headers(service),
            json=forwarded,
            timeout=self.proxy_timeout,
        )
        try:
            response = await self.client.send(request, stream=True)
        except httpx.HTTPError as exc:
            self.store.mark_failed(service.id, str(exc))
            logger.error(
                "Upstream request failed service_id=%s base_url=%s path=%s model=%s error=%s",
                service.id,
                service.base_url,
                path,
                upstream_model,
                exc,
            )
            raise RouteError(f"Upstream {service.name} could not be reached: {exc}") from exc
        logger.info(
            "Request routed service_id=%s base_url=%s path=%s model=%s status=%d stream=%s",
            service.id,
            service.base_url,
            path,
            upstream_model,
            response.status_code,
            bool(payload.get("stream")),
        )
        return response, service, requested_model, upstream_model, ollama_native

    async def read_ollama_response(
        self, response: httpx.Response, requested_model: str
    ) -> tuple[bytes, str]:
        try:
            raw = await response.aread()
            if response.status_code >= 400:
                return raw, response.headers.get("content-type", "application/json")
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                return raw, response.headers.get("content-type", "application/json")
            translated = self._ollama_non_stream(payload, requested_model)
            return json.dumps(translated, ensure_ascii=False).encode("utf-8"), "application/json"
        finally:
            await response.aclose()

    def ollama_stream(
        self, response: httpx.Response, requested_model: str
    ) -> AsyncIterator[bytes]:
        return self._ollama_stream(response, requested_model)

    @staticmethod
    async def passthrough_stream(response: httpx.Response) -> AsyncIterator[bytes]:
        try:
            async for chunk in response.aiter_raw():
                yield chunk
        finally:
            await response.aclose()
