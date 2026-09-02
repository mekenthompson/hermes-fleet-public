"""Profile-bound 1Password Connect sink for rotated Linear OAuth state."""
from __future__ import annotations

import json
import os
import re
import stat
import time
import urllib.request
from collections.abc import Callable, Collection
from typing import Any
from urllib.parse import urlsplit

_ID = re.compile(r"[A-Za-z0-9-]{3,64}")
_PROFILE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")


def _connect_origins(raw: str) -> frozenset[str]:
    origins = frozenset(value.strip() for value in raw.split(",") if value.strip())
    if not origins or len(origins) > 8:
        raise RuntimeError("Linear OAuth Connect host allowlist is invalid")
    for origin in origins:
        parsed = urlsplit(origin)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
            or origin != f"{parsed.scheme}://{parsed.netloc}"
        ):
            raise RuntimeError("Linear OAuth Connect host allowlist is invalid")
    return origins


def load_connect_environment(path: os.PathLike[str]) -> tuple[str, str, frozenset[str]]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError("Linear OAuth Connect environment is unavailable") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("Linear OAuth Connect environment must be regular")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise RuntimeError("Linear OAuth Connect environment permissions are too broad")
        if metadata.st_uid != os.geteuid():
            raise RuntimeError("Linear OAuth Connect environment owner is invalid")
        if metadata.st_size > 65_536:
            raise RuntimeError("Linear OAuth Connect environment is too large")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, 65_537 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > 65_536:
                raise RuntimeError("Linear OAuth Connect environment is too large")
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    values: dict[str, str] = {}
    for line in raw.decode("utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise RuntimeError("Linear OAuth Connect environment is invalid")
        key, value = line.split("=", 1)
        if key in values:
            raise RuntimeError("Linear OAuth Connect environment is invalid")
        values[key] = value
    host = values.get("OP_CONNECT_HOST", "")
    token = values.get("OP_CONNECT_TOKEN", "")
    allowed_raw = values.get("OP_CONNECT_ALLOWED_HOSTS", "")
    if not host or not token:
        raise RuntimeError("Linear OAuth Connect environment is incomplete")
    if not allowed_raw:
        raise RuntimeError("Linear OAuth Connect host allowlist is unavailable")
    approved_hosts = _connect_origins(allowed_raw)
    if host not in approved_hosts:
        raise RuntimeError("Linear OAuth Connect host is not approved")
    return host, token, approved_hosts


class OnePasswordLinearRefreshSink:
    def __init__(
        self,
        *,
        connect_host: str,
        connect_token: str,
        approved_connect_hosts: Collection[str],
        profile: str,
        vault_id: str,
        item_id: str,
        transport: Callable[[str, str, dict[str, str], bytes | None], Any] | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        approved_hosts = frozenset(approved_connect_hosts)
        if not approved_hosts or connect_host not in approved_hosts:
            raise ValueError("Linear OAuth Connect host is not approved")
        if not connect_token:
            raise ValueError("Linear OAuth Connect token is unavailable")
        if _PROFILE.fullmatch(profile) is None or _ID.fullmatch(vault_id) is None or _ID.fullmatch(item_id) is None:
            raise ValueError("Linear OAuth profile or item binding is invalid")
        self._host = connect_host
        self._token = connect_token
        self._profile = profile
        self._vault_id = vault_id
        self._item_id = item_id
        self._transport = transport or self._http_transport
        self._sleep = sleep

    @staticmethod
    def _http_transport(method: str, url: str, headers: dict[str, str], body: bytes | None = None) -> Any:
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        with urllib.request.urlopen(request, timeout=15) as response:  # nosec B310: exact allowlisted host
            return json.load(response)

    def _request(self, method: str, path: str, body: bytes | None = None) -> Any:
        try:
            return self._transport(
                method,
                self._host + path,
                {"Authorization": "Bearer " + self._token, "Content-Type": "application/json"},
                body,
            )
        except Exception as exc:
            raise RuntimeError("Linear OAuth durable store request failed") from exc

    @staticmethod
    def _refresh_field(item: Any) -> dict[str, Any]:
        if not isinstance(item, dict):
            raise RuntimeError("Linear OAuth durable item is invalid")
        matches = [
            field for field in item.get("fields", [])
            if isinstance(field, dict)
            and str(field.get("label") or field.get("id") or "").lower() == "refresh_token"
        ]
        if len(matches) != 1 or not matches[0].get("id"):
            raise RuntimeError("Linear OAuth durable item lacks one refresh field")
        return matches[0]

    def _read_bound_item(self) -> tuple[str, dict[str, Any]]:
        vaults = self._request("GET", "/v1/vaults")
        if not isinstance(vaults, list) or [str(v.get("id") or "") for v in vaults if isinstance(v, dict)] != [self._vault_id]:
            raise RuntimeError("Linear OAuth Connect vault scope does not match profile policy")
        path = f"/v1/vaults/{self._vault_id}/items/{self._item_id}"
        item = self._request("GET", path)
        if (
            not isinstance(item, dict)
            or str(item.get("id") or "") != self._item_id
            or str((item.get("vault") or {}).get("id") or "") != self._vault_id
            or str(item.get("title") or "") != "Linear Client"
        ):
            raise RuntimeError("Linear OAuth durable item binding does not match profile policy")
        return path, item

    def read_credentials(self) -> dict[str, str]:
        _path, item = self._read_bound_item()
        credentials: dict[str, str] = {}
        aliases = {"username": "client_id", "credential": "client_secret"}
        for name in ("client_id", "client_secret", "refresh_token"):
            matches = []
            for field in item.get("fields", []):
                if not isinstance(field, dict):
                    continue
                identifier = str(field.get("id") or "").lower()
                label = str(field.get("label") or "").lower()
                canonical = aliases.get(identifier, aliases.get(label, label))
                if canonical == name:
                    matches.append(field)
            if len(matches) != 1 or not str(matches[0].get("value") or "").strip():
                raise RuntimeError("Linear OAuth durable item credentials are incomplete")
            credentials[name] = str(matches[0]["value"])
        return credentials

    def __call__(self, refresh_token: str) -> None:
        if not refresh_token:
            raise ValueError("rotated Linear refresh token is empty")
        path, item = self._read_bound_item()
        field = self._refresh_field(item)
        patch = json.dumps([{
            "op": "replace",
            "path": f"/fields/{field['id']}/value",
            "value": refresh_token,
        }], separators=(",", ":")).encode("utf-8")
        self._request("PATCH", path, patch)
        for _ in range(20):
            current = self._request("GET", path)
            if str(self._refresh_field(current).get("value") or "").strip() == refresh_token:
                return
            self._sleep(0.5)
        raise RuntimeError("Linear OAuth durable store did not confirm rotation")
