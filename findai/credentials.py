from __future__ import annotations

import json
import os
from pathlib import Path


class LocalCredentialFile:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _load(self) -> dict[str, dict[str, str]]:
        if not self.path.exists():
            return {}
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Unable to read local credential file: {self.path}") from exc
        values = payload.get("credentials", []) if isinstance(payload, dict) else []
        if not isinstance(values, list):
            raise ValueError(f"Invalid local credential file: {self.path}")
        credentials: dict[str, dict[str, str]] = {}
        for value in values:
            if not isinstance(value, dict):
                continue
            credential_id = value.get("id")
            api_key = value.get("api_key")
            if not isinstance(credential_id, str) or not isinstance(api_key, str):
                continue
            credentials[credential_id] = {
                "id": credential_id,
                "name": str(value.get("name") or "本机密钥")[:60],
                "api_key": api_key,
            }
        return credentials

    def _write(self, credentials: dict[str, dict[str, str]]) -> None:
        payload = {
            "version": 1,
            "credentials": sorted(
                credentials.values(), key=lambda item: (item["name"], item["id"])
            ),
        }
        temporary_path = self.path.with_suffix(f"{self.path.suffix}.tmp")
        temporary_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        try:
            os.chmod(temporary_path, 0o600)
        except OSError:
            pass
        os.replace(temporary_path, self.path)

    def save(self, credential_id: str, name: str, api_key: str) -> None:
        credentials = self._load()
        existing_name = credentials.get(credential_id, {}).get("name", "本机密钥")
        credentials[credential_id] = {
            "id": credential_id,
            "name": name.strip()[:60] or existing_name,
            "api_key": api_key,
        }
        self._write(credentials)

    def get(self, credential_id: str) -> str | None:
        credential = self._load().get(credential_id)
        return credential["api_key"] if credential else None

    def list(self) -> list[tuple[str, str, str]]:
        return [
            (item["id"], item["name"], item["api_key"])
            for item in sorted(
                self._load().values(), key=lambda value: (value["name"], value["id"])
            )
        ]

    def delete(self, credential_id: str) -> bool:
        credentials = self._load()
        if credential_id not in credentials:
            return False
        del credentials[credential_id]
        self._write(credentials)
        return True
