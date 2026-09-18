"""Explicit, validated configuration. No development credentials are embedded."""

import json
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


MAX_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True)
class Destination:
    kind: str
    url: str | None = None


@dataclass(frozen=True)
class Config:
    admin_key: str
    client_keys: dict[str, str]
    destinations: dict[str, Destination]
    db_path: Path
    ollama_model: str | None = None
    ollama_url: str = "http://127.0.0.1:11434/api/generate"

    def __post_init__(self) -> None:
        keys = [self.admin_key, *self.client_keys.values()]
        if not self.client_keys or any(len(key) < 24 or key.startswith("replace-") for key in keys):
            raise ValueError("Set random, distinct admin and client keys (at least 24 characters)")
        if len(keys) != len(set(keys)) or any(not actor or len(actor) > 80 for actor in self.client_keys):
            raise ValueError("Keys and actor names must be distinct and valid")
        for name, dest in self.destinations.items():
            if not name or len(name) > 80 or dest.kind not in {"internal", "external"}:
                raise ValueError("Invalid destination name/kind")
            if dest.url:
                parsed = urlparse(dest.url)
                if (parsed.scheme != "https" and not
                    (parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"})):
                    raise ValueError("Destination URL must be HTTPS or loopback HTTP")
                if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
                    raise ValueError("Destination URL must not contain credentials/query/fragment")
        parsed = urlparse(self.ollama_url)
        if parsed.scheme != "http" or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("The model endpoint must be local loopback HTTP")

    @classmethod
    def from_env(cls) -> "Config":
        clients = json.loads(os.environ.get("DLP_CLIENT_KEYS_JSON", "{}"))
        raw_destinations = json.loads(os.environ.get("DLP_DESTINATIONS_JSON", '{"internal-demo":{"kind":"internal"},"external-demo":{"kind":"external"}}'))
        if not isinstance(clients, dict) or not isinstance(raw_destinations, dict):
            raise ValueError("Keys and destinations must be JSON objects")
        return cls(
            admin_key=os.environ.get("DLP_ADMIN_KEY", ""),
            client_keys=clients,
            destinations={name: Destination(**value) for name, value in raw_destinations.items()},
            db_path=Path(os.environ.get("DLP_DB_PATH", "./var/dlp.db")),
            ollama_model=os.environ.get("DLP_OLLAMA_MODEL") or None,
            ollama_url=os.environ.get("DLP_OLLAMA_URL", "http://127.0.0.1:11434/api/generate"),
        )
