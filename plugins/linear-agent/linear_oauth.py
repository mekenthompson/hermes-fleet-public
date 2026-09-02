"""Refreshable profile-local Linear OAuth credential provider."""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import stat
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path

_TOKEN_ENDPOINT = "https://api.linear.app/oauth/token"
# Linear documents idempotent replay of the consumed refresh token for 30 minutes:
# https://linear.app/developers/oauth-2-0-authentication
_REFRESH_RECOVERY_WINDOW_SECONDS = 1800


def validate_no_symlink_ancestors(path: Path) -> None:
    absolute = path.absolute()
    components = list(reversed(absolute.parents)) + [absolute]
    for component in components:
        try:
            info = component.lstat()
        except OSError as exc:
            raise RuntimeError("Linear OAuth path ancestor is unavailable") from exc
        if stat.S_ISLNK(info.st_mode):
            raise RuntimeError("Linear OAuth path ancestor must not be a symlink")
        if not stat.S_ISDIR(info.st_mode):
            raise RuntimeError("Linear OAuth path ancestor must be a directory")


def _validate_existing_ancestors(path: Path) -> None:
    absolute = path.absolute()
    for component in list(reversed(absolute.parents)) + [absolute]:
        try:
            info = component.lstat()
        except FileNotFoundError:
            return
        except OSError as exc:
            raise RuntimeError("Linear OAuth path ancestor is unavailable") from exc
        if stat.S_ISLNK(info.st_mode):
            raise RuntimeError("Linear OAuth path ancestor must not be a symlink")
        if not stat.S_ISDIR(info.st_mode):
            raise RuntimeError("Linear OAuth path ancestor must be a directory")


def validate_private_directory(path: Path) -> None:
    validate_no_symlink_ancestors(path)
    try:
        info = path.lstat()
    except OSError as exc:
        raise RuntimeError("Linear OAuth private directory is unavailable") from exc
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise RuntimeError("Linear OAuth private directory must be a non-symlink directory")
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise RuntimeError("Linear OAuth private directory ownership or permissions are unsafe")


def _state_private_root(path: Path) -> Path:
    return path.parent.parent if path.parent.name == "secrets" else path.parent


def _atomic_write(path: Path, value: dict[str, object]) -> None:
    validate_private_directory(_state_private_root(path))
    _validate_existing_ancestors(path.parent)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    validate_private_directory(path.parent)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            os.chmod(stream.name, 0o600)
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def initialize_oauth_state(path: Path, credentials: dict[str, str]) -> None:
    required = ("client_id", "client_secret", "refresh_token")
    if path.exists() or path.is_symlink():
        raise RuntimeError("Linear OAuth state already exists")
    if not all(isinstance(credentials.get(key), str) and credentials[key] for key in required):
        raise ValueError("Linear OAuth refresh credentials are incomplete")
    _atomic_write(path, {
        "access_token": "",
        "expires_at": 0,
        "client_id": credentials["client_id"],
        "client_secret": credentials["client_secret"],
        "refresh_token": credentials["refresh_token"],
    })


def read_oauth_state(path: Path) -> dict[str, object]:
    validate_private_directory(_state_private_root(path))
    validate_private_directory(path.parent)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError("Linear OAuth file is unavailable") from exc
    with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Linear OAuth file must be regular")
        if info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise ValueError("Linear OAuth file permissions are too broad")
        if info.st_uid != os.geteuid():
            raise ValueError("Linear OAuth file owner is invalid")
        try:
            value = json.load(stream)
        except json.JSONDecodeError as exc:
            raise ValueError("Linear OAuth file is invalid") from exc
    if not isinstance(value, dict):
        raise ValueError("Linear OAuth file must contain an object")
    return value


class LinearOAuthToken:
    def __init__(
        self,
        path: Path,
        *,
        now: Callable[[], float] = time.time,
        transport: Callable[[str, dict[str, str], bytes], bytes] | None = None,
        refresh_sink: Callable[[str], None] | None = None,
    ) -> None:
        self._path = path
        self._now = now
        self._transport = transport or self._http_transport
        self._refresh_sink = refresh_sink
        self._lock = threading.Lock()

    @contextmanager
    def _process_lock(self):
        validate_private_directory(self._path.parent)
        lock_path = self._path.parent / ".linear-oauth.lock"
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(lock_path, flags, 0o600)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise RuntimeError("Linear OAuth lock file is unsafe")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            os.close(descriptor)

    @staticmethod
    def _http_transport(url: str, headers: dict[str, str], body: bytes) -> bytes:
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(request, timeout=15) as response:  # nosec B310: fixed HTTPS endpoint
            return response.read()

    def _read(self) -> dict[str, object]:
        return read_oauth_state(self._path)

    def _write(self, value: dict[str, object]) -> None:
        _atomic_write(self._path, value)

    def invalidate(self) -> None:
        with self._lock, self._process_lock():
            value = self._read()
            value["expires_at"] = 0
            self._write(value)

    def _reconcile_pending(self, value: dict[str, object]) -> str | None:
        pending_refresh = value.get("pending_refresh_token")
        pending_access = value.get("pending_access_token")
        pending_expires = value.get("pending_expires_at")
        pending_keys = {"pending_refresh_token", "pending_access_token", "pending_expires_at"}
        present_pending = pending_keys.intersection(value)
        if not present_pending:
            return None
        valid_pending = all((isinstance(pending_refresh, str) and pending_refresh,
                             isinstance(pending_access, str) and pending_access,
                             isinstance(pending_expires, (int, float))))
        if not pending_keys.issubset(value) or not valid_pending:
            raise RuntimeError("Linear OAuth pending rotation state is incomplete")
        if self._refresh_sink is None:
            raise RuntimeError("Linear OAuth durable store is unavailable")
        try:
            self._refresh_sink(pending_refresh)
        except Exception as exc:
            raise RuntimeError("Linear OAuth durable store reconciliation failed") from exc
        value["refresh_token"] = pending_refresh
        if float(pending_expires) > self._now():  # type: ignore[arg-type]
            value["access_token"] = pending_access
            value["expires_at"] = pending_expires
            result: str | None = str(pending_access)
        else:
            value["access_token"] = ""
            value["expires_at"] = 0
            result = None
        for key in ("pending_refresh_token", "pending_access_token", "pending_expires_at"):
            value.pop(key, None)
        self._write(value)
        return result

    def __call__(self) -> str:
        with self._lock, self._process_lock():
            return self._get_token()

    def _get_token(self) -> str:
        value = self._read()
        reconciled = self._reconcile_pending(value)
        if reconciled is not None:
            return reconciled
        access_token = value.get("access_token")
        expires_at = value.get("expires_at")
        if (
            isinstance(access_token, str)
            and access_token
            and isinstance(expires_at, (int, float))
            and float(expires_at) > self._now()
        ):
            return access_token

        required = ("refresh_token", "client_id", "client_secret")
        if not all(isinstance(value.get(key), str) and value.get(key) for key in required):
            raise ValueError("Linear OAuth refresh credentials are incomplete")
        refresh_token = str(value["refresh_token"])
        intent_digest = hashlib.sha256(refresh_token.encode("utf-8")).hexdigest()
        existing_intent = value.get("refresh_intent_at")
        if existing_intent is not None:
            stored_digest = value.get("refresh_intent_digest")
            if not isinstance(existing_intent, (int, float)) or not isinstance(stored_digest, str) or not hmac.compare_digest(stored_digest, intent_digest):
                raise RuntimeError("Linear OAuth refresh intent is invalid")
            if self._now() - float(existing_intent) >= _REFRESH_RECOVERY_WINDOW_SECONDS:
                raise RuntimeError("Linear OAuth refresh recovery window expired; reauthorization is required")
        else:
            value["refresh_intent_at"] = self._now()
            value["refresh_intent_digest"] = intent_digest
            self._write(value)
        body = urllib.parse.urlencode({
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": value["client_id"],
            "client_secret": value["client_secret"],
        }).encode("utf-8")
        raw = self._transport(
            _TOKEN_ENDPOINT,
            {"Content-Type": "application/x-www-form-urlencoded"},
            body,
        )
        refreshed = json.loads(raw)
        new_access_token = refreshed.get("access_token") if isinstance(refreshed, dict) else None
        if not isinstance(new_access_token, str) or not new_access_token:
            raise RuntimeError("Linear OAuth refresh returned no access token")
        new_refresh_token = refreshed.get("refresh_token")
        if not isinstance(new_refresh_token, str) or not new_refresh_token:
            raise RuntimeError("Linear OAuth refresh returned no rotated refresh token")
        expires_at = self._now() + int(refreshed.get("expires_in", 3600)) - 60
        value.pop("refresh_intent_at", None)
        value.pop("refresh_intent_digest", None)
        if self._refresh_sink is not None:
            value["pending_access_token"] = new_access_token
            value["pending_refresh_token"] = new_refresh_token
            value["pending_expires_at"] = expires_at
            self._write(value)
            reconciled = self._reconcile_pending(value)
            if reconciled is None:
                raise RuntimeError("Linear OAuth durable store reconciliation failed")
            return reconciled
        value["access_token"] = new_access_token
        value["refresh_token"] = new_refresh_token
        value["expires_at"] = expires_at
        self._write(value)
        return new_access_token
