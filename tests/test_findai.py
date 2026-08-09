from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

from findai.app import create_app
from findai.config import Settings, parse_ports
from findai.discovery import DiscoveryManager, ProtocolProber
from findai.gateway import ModelGateway
from findai.models import ServiceRecord, service_id_for
from findai.storage import ServiceStore


class MockAsyncStream(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes]):
        self.chunks = chunks

    async def __aiter__(self):
        for chunk in self.chunks:
            yield chunk


class ConfigTests(unittest.TestCase):
    def test_parse_ports_supports_ranges_and_deduplicates(self) -> None:
        self.assertEqual(parse_ports("8001,8000-8002,11434"), (8000, 8001, 8002, 11434))

    def test_scan_rejects_public_network(self) -> None:
        from findai.discovery import DiscoveryManager

        with self.assertRaises(ValueError):
            DiscoveryManager.validate_targets(["8.8.8.0/24"], [80], ["http"], 1024)

    def test_scan_treats_bare_ipv4_address_as_32_host(self) -> None:
        networks, _, _ = DiscoveryManager.validate_targets(
            ["192.168.110.241"], [12434], ["http"], 1024
        )
        self.assertEqual([str(network) for network in networks], ["192.168.110.241/32"])

    def test_scan_allows_explicit_public_host(self) -> None:
        from findai.discovery import DiscoveryManager

        networks, ports, schemes = DiscoveryManager.validate_targets(
            ["121.48.164.135/32"],
            [12434],
            ["http"],
            1024,
            ["121.48.164.135/32"],
        )
        self.assertEqual([str(network) for network in networks], ["121.48.164.135/32"])
        self.assertEqual(ports, [12434])
        self.assertEqual(schemes, ["http"])

    def test_public_allowlist_rejects_broad_networks(self) -> None:
        from findai.config import parse_allowed_public_cidrs

        with self.assertRaises(ValueError):
            parse_allowed_public_cidrs("121.48.164.0/24")

    def test_dotenv_loads_but_does_not_override_process_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            env_file.write_text(
                "FINDAI_HOST=0.0.0.0\nFINDAI_PORT=7070\nFINDAI_SCAN_CIDRS=192.168.9.0/24\n",
                encoding="utf-8",
            )
            with patch.dict("os.environ", {"FINDAI_PORT": "9090"}, clear=True):
                settings = Settings.from_env(env_file)
            self.assertEqual(settings.host, "0.0.0.0")
            self.assertEqual(settings.port, 9090)
            self.assertEqual(settings.scan_cidrs, ("192.168.9.0/24",))

    def test_dotenv_loads_explicit_public_host_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            env_file.write_text(
                "FINDAI_SCAN_CIDRS=121.48.164.135/32\n"
                "FINDAI_ALLOWED_PUBLIC_CIDRS=121.48.164.135/32\n",
                encoding="utf-8",
            )
            with patch.dict("os.environ", {}, clear=True):
                settings = Settings.from_env(env_file)
            self.assertEqual(settings.allowed_public_cidrs, ("121.48.164.135/32",))


class ProbeTests(unittest.IsolatedAsyncioTestCase):
    async def test_openai_model_list_is_recognized(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.url.path, "/v1/models")
            return httpx.Response(
                200,
                json={
                    "object": "list",
                    "data": [{"id": "qwen2.5:7b"}, {"id": "embed-small"}],
                },
            )

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await ProtocolProber(client, 1).probe("http://10.0.0.8:8000")
        self.assertTrue(result.matched)
        self.assertEqual(result.api_kind, "openai")
        self.assertEqual(result.models, ["embed-small", "qwen2.5:7b"])

    async def test_native_ollama_fallback_is_recognized(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/v1/models":
                return httpx.Response(404, json={"error": "not found"})
            return httpx.Response(200, json={"models": [{"name": "llama3.2:3b"}]})

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await ProtocolProber(client, 1).probe("http://10.0.0.9:11434")
        self.assertTrue(result.matched)
        self.assertEqual(result.api_kind, "ollama")
        self.assertEqual(result.models, ["llama3.2:3b"])

    async def test_bearer_protected_endpoint_is_kept_for_credential_entry(self) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                401,
                headers={"WWW-Authenticate": "Bearer"},
                json={"error": {"message": "API key required"}},
            )

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await ProtocolProber(client, 1).probe("http://10.0.0.10:8080")
        self.assertTrue(result.matched)
        self.assertTrue(result.auth_required)


class DiscoveryScanTests(unittest.IsolatedAsyncioTestCase):
    async def test_scan_records_serializable_range_logs(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        settings = Settings(
            db_path=Path(temporary.name) / "scan.db",
            scan_cidrs=("127.0.0.1/32",),
            scan_ports=(65534,),
            scan_on_startup=False,
            max_concurrency=1,
        )
        store = ServiceStore(settings.db_path)
        client = httpx.AsyncClient()
        discovery = DiscoveryManager(settings, store, client)

        async def closed_target(_: str, __: int, ___: str) -> tuple[None, bool]:
            return None, False

        discovery._probe_target = closed_target  # type: ignore[method-assign]
        try:
            discovery.start_scan()
            self.assertIsNotNone(discovery._scan_task)
            await discovery._scan_task

            state = discovery.state.to_dict()
            self.assertEqual(state["status"], "completed")
            self.assertEqual(state["scanned"], 1)
            self.assertTrue(all(isinstance(entry, dict) for entry in state["logs"]))
            messages = [entry["message"] for entry in state["logs"]]
            self.assertTrue(any("探测流程" in message for message in messages))
            self.assertTrue(any("范围完成" in message for message in messages))
            self.assertTrue(any("扫描完成" in message for message in messages))
        finally:
            await client.aclose()
            store.close()
            temporary.cleanup()

    async def test_scan_log_keeps_only_latest_two_hundred_entries(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        settings = Settings(
            db_path=Path(temporary.name) / "scan.db",
            scan_on_startup=False,
        )
        store = ServiceStore(settings.db_path)
        client = httpx.AsyncClient()
        discovery = DiscoveryManager(settings, store, client)
        try:
            for index in range(205):
                discovery._record_scan_log(f"event-{index}")
            self.assertEqual(len(discovery.state.logs), 200)
            self.assertEqual(discovery.state.logs[0].message, "event-5")
            self.assertEqual(discovery.state.logs[-1].message, "event-204")
        finally:
            await client.aclose()
            store.close()
            temporary.cleanup()


class StorageTests(unittest.TestCase):
    def test_service_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ServiceStore(Path(directory) / "findai.db")
            base_url = "http://10.0.0.2:8000"
            expected = ServiceRecord(
                id=service_id_for(base_url),
                name="Test service",
                host="10.0.0.2",
                port=8000,
                scheme="http",
                base_url=base_url,
                api_kind="openai",
                models=["model-a"],
            )
            store.upsert(expected)
            actual = store.get(expected.id)
            self.assertIsNotNone(actual)
            self.assertEqual(actual.models, ["model-a"])
            self.assertEqual(store.clear(), 1)
            self.assertEqual(store.list(), [])
            store.close()


class GatewayApiTests(unittest.IsolatedAsyncioTestCase):
    async def test_dashboard_and_scan_responses_disable_browser_cache(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        settings = Settings(
            db_path=Path(temporary.name) / "app.db",
            scan_cidrs=("127.0.0.1/32",),
            scan_ports=(65534,),
            scan_on_startup=False,
        )
        app = create_app(settings)
        transport = httpx.ASGITransport(app=app)
        try:
            async with httpx.AsyncClient(transport=transport, base_url="http://findai.test") as client:
                for path in ("/", "/assets/app.js", "/assets/favicon.png", "/api/scan"):
                    response = await client.get(path)
                    self.assertEqual(response.status_code, 200)
                    self.assertIn("no-store", response.headers["cache-control"])
        finally:
            await app.state.http_client.aclose()
            app.state.store.close()
            temporary.cleanup()

    async def test_clear_services_endpoint(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        settings = Settings(
            db_path=Path(temporary.name) / "app.db",
            scan_cidrs=("127.0.0.1/32",),
            scan_ports=(65534,),
            scan_on_startup=False,
        )
        app = create_app(settings)
        base_url = "http://10.0.0.20:8000"
        service = ServiceRecord(
            id=service_id_for(base_url),
            name="Mock OpenAI service",
            host="10.0.0.20",
            port=8000,
            scheme="http",
            base_url=base_url,
            api_kind="openai",
            models=["local-chat"],
        )
        app.state.store.upsert(service)
        app.state.discovery.set_credential(service.id, "temporary-key")
        transport = httpx.ASGITransport(app=app)
        try:
            async with httpx.AsyncClient(transport=transport, base_url="http://findai.test") as client:
                response = await client.delete("/api/services")
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json(), {"deleted": 1})
                self.assertEqual(app.state.store.list(), [])
                self.assertIsNone(app.state.discovery.credential_for(service))

                app.state.store.upsert(service)
                app.state.discovery.state.status = "running"
                blocked = await client.delete("/api/services")
                self.assertEqual(blocked.status_code, 409)
                self.assertEqual(len(app.state.store.list()), 1)
        finally:
            await app.state.http_client.aclose()
            app.state.store.close()
            temporary.cleanup()

    async def test_catalog_and_chat_proxy(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        settings = Settings(
            db_path=Path(temporary.name) / "app.db",
            scan_cidrs=("127.0.0.1/32",),
            scan_ports=(65534,),
            scan_on_startup=False,
        )
        app = create_app(settings)
        base_url = "http://10.0.0.20:8000"
        service = ServiceRecord(
            id=service_id_for(base_url),
            name="Mock OpenAI service",
            host="10.0.0.20",
            port=8000,
            scheme="http",
            base_url=base_url,
            api_kind="openai",
            models=["local-chat"],
        )
        app.state.store.upsert(service)

        def upstream_handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.url.path, "/v1/chat/completions")
            body = json.loads(request.content)
            self.assertEqual(body["model"], "local-chat")
            if body.get("stream"):
                return httpx.Response(
                    200,
                    headers={"content-type": "text/event-stream"},
                    stream=MockAsyncStream([
                        b'data: {"choices":[{"delta":{"content":"ok"}}]}\n\n',
                        b'data: [DONE]\n\n',
                    ]),
                )
            return httpx.Response(
                200,
                json={
                    "id": "chatcmpl-local",
                    "object": "chat.completion",
                    "model": "local-chat",
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
                },
            )

        upstream_client = httpx.AsyncClient(transport=httpx.MockTransport(upstream_handler))
        original_client = app.state.http_client
        app.state.gateway.client = upstream_client
        transport = httpx.ASGITransport(app=app)
        try:
            async with httpx.AsyncClient(transport=transport, base_url="http://findai.test") as client:
                models = await client.get("/v1/models")
                self.assertEqual(models.status_code, 200)
                routed_model = models.json()["data"][0]["id"]
                response = await client.post(
                    "/v1/chat/completions",
                    json={"model": routed_model, "messages": [{"role": "user", "content": "hi"}]},
                )
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()["choices"][0]["message"]["content"], "ok")
                self.assertEqual(response.headers["x-findai-upstream-model"], "local-chat")
                streamed = await client.post(
                    "/v1/chat/completions",
                    json={"model": routed_model, "messages": [], "stream": True},
                )
                self.assertIn("data: [DONE]", streamed.text)
        finally:
            await upstream_client.aclose()
            await original_client.aclose()
            app.state.store.close()
            temporary.cleanup()

    async def test_ollama_translation_shapes(self) -> None:
        request = ModelGateway._ollama_payload(
            {
                "model": "route::llama",
                "messages": [{"role": "user", "content": "hi"}],
                "temperature": 0.2,
                "max_tokens": 32,
            },
            "llama3.2:3b",
        )
        self.assertEqual(request["model"], "llama3.2:3b")
        self.assertEqual(request["options"]["num_predict"], 32)
        response = ModelGateway._ollama_non_stream(
            {
                "message": {"role": "assistant", "content": "hello"},
                "done": True,
                "prompt_eval_count": 4,
                "eval_count": 2,
            },
            "route::llama",
        )
        self.assertEqual(response["model"], "route::llama")
        self.assertEqual(response["usage"]["total_tokens"], 6)


if __name__ == "__main__":
    unittest.main()
