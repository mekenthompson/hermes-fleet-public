from __future__ import annotations

import dataclasses
import hashlib
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path


@dataclasses.dataclass(frozen=True)
class Route:
    logical_agent: str
    profile: str
    path: str
    secret_file: Path
    inbox: Path


class IngressStore:
    """Synthetic producer for the public worker/ingress SQLite contract."""

    def __init__(self, database: Path) -> None:
        database.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.database = database
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute(
                """CREATE TABLE IF NOT EXISTS deliveries (
                    logical_agent TEXT NOT NULL,
                    delivery_id TEXT NOT NULL,
                    profile TEXT NOT NULL,
                    payload BLOB NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    received_at INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (logical_agent, delivery_id)
                )"""
            )

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.database, isolation_level=None, timeout=5.0)
        try:
            yield connection
        finally:
            connection.close()

    def enqueue(self, route: Route, delivery_id: str, body: bytes) -> bool:
        digest = hashlib.sha256(body).hexdigest()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT payload_sha256 FROM deliveries "
                "WHERE logical_agent = ? AND delivery_id = ?",
                (route.logical_agent, delivery_id),
            ).fetchone()
            if existing is not None:
                connection.execute("COMMIT")
                if existing[0] != digest:
                    raise ValueError("delivery id was reused with different content")
                return True
            connection.execute(
                """INSERT INTO deliveries
                (logical_agent, delivery_id, profile, payload, payload_sha256, received_at)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    route.logical_agent,
                    delivery_id,
                    route.profile,
                    body,
                    digest,
                    int(time.time()),
                ),
            )
            connection.execute("COMMIT")
        return False
