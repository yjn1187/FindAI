from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

from findai.app import create_app
from findai.config import Settings, parse_ports, parse_scan_cidr_presets
from findai.discovery import CredentialCandidate, DiscoveryManager, ProtocolProber
from findai.gateway import ModelGateway
from findai.models import ServiceRecord, credential_fingerprint, service_id_for
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

    def test_scan_cidr_presets_support_named_single_and_grouped_ranges(self) -> None:
        self.assertEqual(
            parse_scan_cidr_presets(
                '{"办公室":"192.168.1.8","实验室":["10.20.0.0/24","10.21.0.0/24"]}'
            ),
            {
                "办公室": "192.168.1.8/32",
                "实验室": "10.20.0.0/24,10.21.0.0/24",
            },
        )

    def test_scan_cidr_presets_reject_invalid_configuration(self) -> None:
        with self.assertRaises(ValueError):
            parse_scan_cidr_presets('["192.168.1.0/24"]')
        with self.assertRaises(ValueError):
            parse_scan_cidr_presets('{"错误网段":"not-an-ip"}')

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

    def test_dotenv_loads_scan_cidr_presets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            env_file.write_text(
                "FINDAI_SCAN_CIDR_PRESETS="
                "'{\"办公室\":\"192.168.8.0/24\",\"设备区\":\"10.8.0.5\"}'\n",
                encoding="utf-8",
            )
            with patch.dict("os.environ", {}, clear=True):
                settings = Settings.from_env(env_file)
            self.assertEqual(
                settings.scan_cidr_presets,
                {"办公室": "192.168.8.0/24", "设备区": "10.8.0.5/32"},
            )

    def test_default_scan_mode_is_manual_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            env_file.write_text("", encoding="utf-8")
            with patch.dict("os.environ", {}, clear=True):
                settings = Settings.from_env(env_file)
            self.assertFalse(settings.scan_on_startup)
            self.assertEqual(settings.scan_interval_seconds, 0)


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
    async def test_manual_only_mode_does_not_create_periodic_task(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        settings = Settings(
            db_path=Path(temporary.name) / "scan.db",
            scan_on_startup=False,
            scan_interval_seconds=0,
        )
        store = ServiceStore(settings.db_path)
        client = httpx.AsyncClient()
        discovery = DiscoveryManager(settings, store, client)
        try:
            discovery.start_periodic()
            self.assertIsNone(discovery._periodic_task)
            self.assertEqual(discovery.state.status, "idle")
        finally:
            await client.aclose()
            store.close()
            temporary.cleanup()

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

    async def test_scan_matches_multiple_saved_credentials_for_one_address(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        settings = Settings(
            db_path=Path(temporary.name) / "scan.db",
            scan_cidrs=("127.0.0.1/32",),
            scan_ports=(8000,),
            scan_on_startup=False,
            max_concurrency=1,
        )
        store = ServiceStore(settings.db_path)

        def handler(request: httpx.Request) -> httpx.Response:
            authorization = request.headers.get("authorization")
            if authorization == "Bearer key-a":
                return httpx.Response(
                    200, json={"object": "list", "data": [{"id": "model-a"}]}
                )
            if authorization == "Bearer key-b":
                return httpx.Response(
                    200, json={"object": "list", "data": [{"id": "model-b"}]}
                )
            return httpx.Response(
                401,
                headers={"WWW-Authenticate": "Bearer"},
                json={"error": {"message": "API key required"}},
            )

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        discovery = DiscoveryManager(settings, store, client)

        async def open_target(_: str, __: int) -> bool:
            return True

        discovery._tcp_open = open_target  # type: ignore[method-assign]
        try:
            discovery.start_scan(
                credentials=(
                    CredentialCandidate("团队 A", "key-a"),
                    CredentialCandidate("团队 B", "key-b"),
                    CredentialCandidate("无效密钥", "bad-key"),
                ),
                match_credentials=True,
            )
            self.assertIsNotNone(discovery._scan_task)
            await discovery._scan_task

            services = sorted(store.list(), key=lambda item: item.credential_name or "")
            self.assertEqual(discovery.state.discovered, 2)
            self.assertEqual([item.models for item in services], [["model-a"], ["model-b"]])
            self.assertEqual([item.credential_name for item in services], ["团队 A", "团队 B"])
            self.assertEqual({item.base_url for item in services}, {"http://127.0.0.1:8000"})
            self.assertEqual(
                {item.id for item in services},
                {
                    service_id_for(
                        "http://127.0.0.1:8000", credential_fingerprint("key-a")
                    ),
                    service_id_for(
                        "http://127.0.0.1:8000", credential_fingerprint("key-b")
                    ),
                },
            )
            self.assertEqual(discovery.credential_for(services[0]), "key-a")
            self.assertEqual(discovery.credential_for(services[1]), "key-b")
        finally:
            await client.aclose()
            store.close()
            temporary.cleanup()

    async def test_public_models_are_not_duplicated_for_saved_credentials(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        settings = Settings(
            db_path=Path(temporary.name) / "scan.db",
            scan_cidrs=("127.0.0.1/32",),
            scan_ports=(8000,),
            scan_on_startup=False,
            max_concurrency=1,
        )
        store = ServiceStore(settings.db_path)

        authorization_headers: list[str | None] = []

        def handler(request: httpx.Request) -> httpx.Response:
            authorization_headers.append(request.headers.get("authorization"))
            return httpx.Response(
                200, json={"object": "list", "data": [{"id": "public-model"}]}
            )

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        discovery = DiscoveryManager(settings, store, client)

        async def open_target(_: str, __: int) -> bool:
            return True

        discovery._tcp_open = open_target  # type: ignore[method-assign]
        try:
            discovery.start_scan(
                credentials=(
                    CredentialCandidate("密钥 A", "key-a"),
                    CredentialCandidate("密钥 B", "key-b"),
                ),
                match_credentials=True,
            )
            self.assertIsNotNone(discovery._scan_task)
            await discovery._scan_task
            services = store.list()
            self.assertEqual(len(services), 1)
            self.assertEqual(services[0].id, service_id_for("http://127.0.0.1:8000"))
            self.assertEqual(services[0].models, ["public-model"])
            self.assertEqual(authorization_headers, [None])
        finally:
            await client.aclose()
            store.close()
            temporary.cleanup()

    async def test_staged_scan_never_sends_credentials_to_unknown_web_ports(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        settings = Settings(
            db_path=Path(temporary.name) / "scan.db",
            scan_cidrs=("127.0.0.1/32",),
            scan_ports=(8080,),
            scan_on_startup=False,
            max_concurrency=1,
        )
        store = ServiceStore(settings.db_path)
        requests: list[tuple[str, str | None]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append((request.url.path, request.headers.get("authorization")))
            return httpx.Response(404, text="Not found")

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        discovery = DiscoveryManager(settings, store, client)

        async def open_target(_: str, __: int) -> bool:
            return True

        discovery._tcp_open = open_target  # type: ignore[method-assign]
        try:
            discovery.start_scan(
                credentials=(CredentialCandidate("不应发送", "secret-key"),),
                match_credentials=True,
            )
            self.assertIsNotNone(discovery._scan_task)
            await discovery._scan_task

            self.assertEqual(
                requests,
                [("/v1/models", None), ("/api/tags", None)],
            )
            self.assertEqual(store.list(), [])
            self.assertEqual(discovery.state.discovered, 0)
        finally:
            await client.aclose()
            store.close()
            temporary.cleanup()

    async def test_fast_rescan_preserves_existing_credential_services(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        settings = Settings(
            db_path=Path(temporary.name) / "scan.db",
            scan_cidrs=("127.0.0.1/32",),
            scan_ports=(8000,),
            scan_on_startup=False,
            max_concurrency=1,
        )
        store = ServiceStore(settings.db_path)
        base_url = "http://127.0.0.1:8000"
        for name, api_key, model in (
            ("团队 A", "key-a", "model-a"),
            ("团队 B", "key-b", "model-b"),
        ):
            credential_id = store.save_credential(api_key, name)
            store.upsert(
                ServiceRecord(
                    id=service_id_for(base_url, credential_id),
                    name=f"OpenAI-compatible · 127.0.0.1:8000 · {name}",
                    host="127.0.0.1",
                    port=8000,
                    scheme="http",
                    base_url=base_url,
                    api_kind="openai",
                    auth_required=True,
                    models=[model],
                    credential_name=name,
                    credential_id=credential_id,
                )
            )

        authorization_headers: list[str | None] = []

        def handler(request: httpx.Request) -> httpx.Response:
            authorization_headers.append(request.headers.get("authorization"))
            return httpx.Response(
                401,
                headers={"WWW-Authenticate": "Bearer"},
                json={"error": {"message": "API key required"}},
            )

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        discovery = DiscoveryManager(settings, store, client)

        async def open_target(_: str, __: int) -> bool:
            return True

        discovery._tcp_open = open_target  # type: ignore[method-assign]
        try:
            discovery.start_scan()
            self.assertIsNotNone(discovery._scan_task)
            await discovery._scan_task

            services = sorted(store.list(), key=lambda item: item.credential_name or "")
            self.assertEqual(authorization_headers, [None])
            self.assertEqual(len(services), 2)
            self.assertEqual([service.status for service in services], ["online", "online"])
            self.assertEqual([service.models for service in services], [["model-a"], ["model-b"]])
            self.assertEqual(discovery.state.discovered, 2)
        finally:
            await client.aclose()
            store.close()
            temporary.cleanup()

    async def test_persisted_local_credential_is_used_after_restart(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        db_path = Path(temporary.name) / "scan.db"
        initial_store = ServiceStore(db_path)
        initial_store.save_credential("persisted-key", "持久化密钥")
        initial_store.close()

        settings = Settings(
            db_path=db_path,
            scan_cidrs=("127.0.0.1/32",),
            scan_ports=(8000,),
            scan_on_startup=False,
            max_concurrency=1,
        )
        store = ServiceStore(db_path)

        authorization_headers: list[str | None] = []

        def handler(request: httpx.Request) -> httpx.Response:
            authorization_headers.append(request.headers.get("authorization"))
            if request.headers.get("authorization") == "Bearer persisted-key":
                return httpx.Response(
                    200,
                    json={"object": "list", "data": [{"id": "persisted-model"}]},
                )
            return httpx.Response(
                401,
                headers={"WWW-Authenticate": "Bearer"},
                json={"error": {"message": "API key required"}},
            )

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        discovery = DiscoveryManager(settings, store, client)

        async def open_target(_: str, __: int) -> bool:
            return True

        discovery._tcp_open = open_target  # type: ignore[method-assign]
        try:
            discovery.start_scan()
            self.assertIsNotNone(discovery._scan_task)
            await discovery._scan_task

            services = store.list()
            self.assertEqual(len(services), 1)
            self.assertEqual(services[0].models, [])
            self.assertTrue(services[0].auth_required)
            self.assertIsNone(services[0].credential_name)
            self.assertEqual(authorization_headers, [None])

            matched = await discovery.match_saved_credentials()
            self.assertEqual(matched["addresses"], 1)
            self.assertEqual(matched["attempts"], 1)
            self.assertEqual(matched["matched_services"], 1)

            services = store.list()
            self.assertEqual(len(services), 1)
            self.assertEqual(services[0].models, ["persisted-model"])
            self.assertEqual(services[0].credential_name, "持久化密钥")
            self.assertEqual(discovery.credential_for(services[0]), "persisted-key")
            self.assertEqual(authorization_headers, [None, "Bearer persisted-key"])
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

    def test_old_unique_base_url_schema_is_migrated_for_multiple_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "findai.db"
            connection = sqlite3.connect(db_path)
            connection.execute(
                """
                CREATE TABLE services (
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
            connection.execute(
                """
                INSERT INTO services (
                    id, name, host, port, scheme, base_url, api_kind, status,
                    auth_required, models_json, capabilities_json, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "legacy",
                    "Legacy service",
                    "10.0.0.2",
                    8000,
                    "http",
                    "http://10.0.0.2:8000",
                    "openai",
                    "online",
                    0,
                    '["legacy-model"]',
                    "{}",
                    1.0,
                ),
            )
            connection.commit()
            connection.close()

            store = ServiceStore(db_path)
            second = ServiceRecord(
                id="credential-variant",
                name="Credential service",
                host="10.0.0.2",
                port=8000,
                scheme="http",
                base_url="http://10.0.0.2:8000",
                api_kind="openai",
                models=["secured-model"],
                credential_name="团队密钥",
            )
            store.upsert(second)
            services = store.list_by_base_url("http://10.0.0.2:8000")
            self.assertEqual(len(services), 2)
            self.assertEqual(
                {model for service in services for model in service.models},
                {"legacy-model", "secured-model"},
            )
            store.close()

    def test_local_credential_round_trip_uses_json_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "findai.db"
            store = ServiceStore(db_path)
            credential_id = store.save_credential("local-secret-key", "工作室")
            service = ServiceRecord(
                id="secured-service",
                name="Secured service",
                host="10.0.0.3",
                port=8000,
                scheme="http",
                base_url="http://10.0.0.3:8000",
                api_kind="openai",
                auth_required=True,
                models=["secured-model"],
                credential_name="工作室",
                credential_id=credential_id,
            )
            store.upsert(service)
            store.close()

            credential_path = db_path.parent / "credentials.json"
            self.assertTrue(credential_path.exists())
            self.assertIn(
                "local-secret-key", credential_path.read_text(encoding="utf-8")
            )
            self.assertNotIn(b"local-secret-key", db_path.read_bytes())

            reopened = ServiceStore(db_path)
            actual = reopened.get(service.id)
            self.assertIsNotNone(actual)
            self.assertEqual(reopened.get_credential(credential_id), "local-secret-key")
            self.assertEqual(
                reopened.list_credentials(),
                [(credential_id, "工作室", "local-secret-key")],
            )
            self.assertNotIn("credential_id", actual.to_dict())
            self.assertTrue(reopened.delete_credential(credential_id))
            self.assertIsNone(reopened.get_credential(credential_id))
            self.assertEqual(reopened.get(service.id).status, "offline")
            reopened.close()


class GatewayApiTests(unittest.IsolatedAsyncioTestCase):
    async def test_dashboard_and_scan_responses_disable_browser_cache(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        settings = Settings(
            db_path=Path(temporary.name) / "app.db",
            scan_cidrs=("127.0.0.1/32",),
            scan_cidr_presets={
                "办公室": "192.168.8.0/24",
                "实验室": "10.20.0.0/24,10.21.0.0/24",
            },
            scan_ports=(65534,),
            scan_on_startup=False,
        )
        app = create_app(settings)
        transport = httpx.ASGITransport(app=app)
        try:
            async with httpx.AsyncClient(transport=transport, base_url="http://findai.test") as client:
                for path in (
                    "/",
                    "/assets/app.js",
                    "/assets/favicon.png",
                    "/api/scan",
                    "/api/credentials",
                ):
                    response = await client.get(path)
                    self.assertEqual(response.status_code, 200)
                    self.assertIn("no-store", response.headers["cache-control"])
                dashboard = await client.get("/")
                self.assertIn('id="credential-dialog"', dashboard.text)
                self.assertIn('id="credential-saved-key"', dashboard.text)
                self.assertIn('list="scan-cidr-presets"', dashboard.text)
                self.assertIn('id="scan-cidr-presets"', dashboard.text)
                self.assertIn("FindAI 1.0 · local-first model infrastructure", dashboard.text)
                script = await client.get("/assets/app.js")
                self.assertIn("serviceRevealDelay", script.text)
                self.assertIn("renderCredentialKeyOptions", script.text)
                self.assertIn("renderScanCidrPresets", script.text)
                self.assertIn("scan-match-credentials", script.text)
                self.assertIn("match_credentials", script.text)
                self.assertIn("/api/services/match-credentials", script.text)
                self.assertIn('api("/api/credentials"', script.text)
                self.assertIn("data-copy-key", script.text)
                self.assertIn('service.credential_loaded ? "更换密钥" : "密钥"', script.text)
                self.assertNotIn("window.prompt(", script.text)
                config = await client.get("/api/config")
                self.assertEqual(
                    config.json()["scan_cidr_presets"],
                    [
                        {"name": "默认扫描范围", "cidrs": ["127.0.0.1/32"]},
                        {"name": "办公室", "cidrs": ["192.168.8.0/24"]},
                        {
                            "name": "实验室",
                            "cidrs": ["10.20.0.0/24", "10.21.0.0/24"],
                        },
                    ],
                )
        finally:
            await app.state.http_client.aclose()
            app.state.store.close()
            temporary.cleanup()

    async def test_service_credential_is_applied_and_refetches_models(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        settings = Settings(
            db_path=Path(temporary.name) / "app.db",
            scan_cidrs=("127.0.0.1/32",),
            scan_ports=(65534,),
            scan_on_startup=False,
        )
        app = create_app(settings)
        base_url = "http://10.0.0.21:8000"
        service = ServiceRecord(
            id=service_id_for(base_url),
            name="Protected OpenAI service",
            host="10.0.0.21",
            port=8000,
            scheme="http",
            base_url=base_url,
            api_kind="openai",
            auth_required=True,
        )
        app.state.store.upsert(service)

        def upstream_handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.url.path, "/v1/models")
            self.assertEqual(request.headers.get("authorization"), "Bearer common-upstream-key")
            return httpx.Response(
                200,
                json={"object": "list", "data": [{"id": "secured-chat"}]},
            )

        upstream_client = httpx.AsyncClient(transport=httpx.MockTransport(upstream_handler))
        app.state.discovery.prober.client = upstream_client
        transport = httpx.ASGITransport(app=app)
        try:
            async with httpx.AsyncClient(transport=transport, base_url="http://findai.test") as client:
                response = await client.put(
                    f"/api/services/{service.id}/credential",
                    json={"api_key": "common-upstream-key"},
                )
                self.assertEqual(response.status_code, 200)
                payload = response.json()
                self.assertTrue(payload["credential_loaded"])
                self.assertTrue(payload["persisted"])
                self.assertEqual(payload["service"]["models"], ["secured-chat"])
                services = await client.get("/api/services")
                self.assertTrue(services.json()["data"][0]["credential_loaded"])
        finally:
            await upstream_client.aclose()
            await app.state.http_client.aclose()
            app.state.store.close()
            temporary.cleanup()

    async def test_match_saved_credentials_endpoint_updates_scanned_services(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        settings = Settings(
            db_path=Path(temporary.name) / "app.db",
            scan_on_startup=False,
        )
        app = create_app(settings)
        base_url = "http://10.0.0.22:8000"
        placeholder = ServiceRecord(
            id=service_id_for(base_url),
            name="Protected OpenAI service",
            host="10.0.0.22",
            port=8000,
            scheme="http",
            base_url=base_url,
            api_kind="openai",
            auth_required=True,
        )
        app.state.store.upsert(placeholder)
        app.state.store.save_credential("matched-key", "团队模型密钥")
        authorization_headers: list[str | None] = []

        def upstream_handler(request: httpx.Request) -> httpx.Response:
            authorization_headers.append(request.headers.get("authorization"))
            if request.headers.get("authorization") == "Bearer matched-key":
                return httpx.Response(
                    200,
                    json={"object": "list", "data": [{"id": "team-model"}]},
                )
            return httpx.Response(401, headers={"WWW-Authenticate": "Bearer"})

        upstream_client = httpx.AsyncClient(
            transport=httpx.MockTransport(upstream_handler)
        )
        app.state.discovery.prober.client = upstream_client
        transport = httpx.ASGITransport(app=app)
        try:
            async with httpx.AsyncClient(
                transport=transport, base_url="http://findai.test"
            ) as client:
                response = await client.post(
                    "/api/services/match-credentials", json={}
                )
                self.assertEqual(response.status_code, 200)
                self.assertEqual(
                    response.json(),
                    {"addresses": 1, "attempts": 1, "matched_services": 1},
                )
                services = (await client.get("/api/services")).json()["data"]
                self.assertEqual(len(services), 1)
                self.assertEqual(services[0]["models"], ["team-model"])
                self.assertEqual(services[0]["credential_name"], "团队模型密钥")
                self.assertEqual(authorization_headers, ["Bearer matched-key"])
        finally:
            await upstream_client.aclose()
            await app.state.http_client.aclose()
            app.state.store.close()
            temporary.cleanup()

    async def test_local_credential_api_supports_copy_value_and_delete(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        settings = Settings(
            db_path=Path(temporary.name) / "app.db",
            scan_on_startup=False,
        )
        app = create_app(settings)
        transport = httpx.ASGITransport(app=app)
        try:
            async with httpx.AsyncClient(
                transport=transport, base_url="http://findai.test"
            ) as client:
                saved = await client.post(
                    "/api/credentials",
                    json={"name": "本机密钥", "api_key": "api-secret-1234"},
                )
                self.assertEqual(saved.status_code, 200)
                self.assertTrue(saved.json()["persisted"])

                listed = await client.get("/api/credentials")
                self.assertEqual(listed.status_code, 200)
                self.assertEqual(listed.json()["data"][0]["name"], "本机密钥")
                self.assertTrue(listed.json()["data"][0]["masked"].endswith("1234"))
                self.assertEqual(
                    listed.json()["data"][0]["api_key"], "api-secret-1234"
                )

                config = await client.get("/api/config")
                self.assertEqual(config.json()["credential_storage"], "file")
                self.assertEqual(
                    Path(config.json()["credential_path"]),
                    settings.db_path.parent / "credentials.json",
                )

                deleted = await client.request(
                    "DELETE",
                    "/api/credentials",
                    json={"api_key": "api-secret-1234"},
                )
                self.assertEqual(deleted.status_code, 200)
                self.assertTrue(deleted.json()["deleted"])
                self.assertEqual((await client.get("/api/credentials")).json()["data"], [])
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
