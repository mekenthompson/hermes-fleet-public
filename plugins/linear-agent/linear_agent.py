"""Profile-local durable state machine for Linear Agent Sessions."""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
import uuid
from collections.abc import Callable, Iterable
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path

_SUMMARY_LIMIT = 8_000
_SENSITIVE_KEY = (
    r"(?:access[_ -]?token|refresh[_ -]?token|api[_ -]?key|apikey|token|"
    r"client[_ -]?secret|clientsecret|authorization|password|passwd|secret|"
    r"cookie|session[_ -]?id|sessionid)"
)
_SECRET_ASSIGNMENT_RE = re.compile(
    rf"(?im)([\"']?{_SENSITIVE_KEY}[\"']?\s*[:=]\s*)"
    r"(?:\"[^\"\n]*\"|'[^'\n]*'|[^\s,}\n]+)"
)
_AUTH_HEADER_RE = re.compile(r"(?im)^(\s*authorization\s*:\s*).+$")
_COOKIE_HEADER_RE = re.compile(r"(?im)^(\s*(?:set-)?cookie\s*:\s*).+$")
_URL_USERINFO_RE = re.compile(r"(?i)(https?://)[^/\s:@]+:[^/\s@]+@")
_BEARER_RE = re.compile(r"(?i)\b(?:Bearer|Basic)\s+\S+")
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [^-\n]*PRIVATE KEY-----.*?-----END [^-\n]*PRIVATE KEY-----",
    re.DOTALL,
)
_TOKEN_PREFIX_RE = re.compile(r"\b(?:gh[pousr]_|lin_api_|sk-)[A-Za-z0-9_-]{8,}")
_SENSITIVE_LINE_RE = re.compile(_SENSITIVE_KEY, re.IGNORECASE)
_SENSITIVE_BLOCK_START_RE = re.compile(
    rf"^(\s*[\"']?{_SENSITIVE_KEY}[\"']?\s*[:=])\s*(.*)$",
    re.IGNORECASE,
)
_LINEAR_AUTHORIZATION_DENIAL = (
    "This agent is restricted to approved workspace users."
)


class _LinearAuthorizationRejection(ValueError):
    def __init__(
        self,
        *,
        linear_session_id: str,
        event_key: str,
        requester_user_id: str | None,
        reason: str,
    ) -> None:
        super().__init__(reason)
        self.linear_session_id = linear_session_id
        self.event_key = event_key
        self.requester_user_id = requester_user_id
        self.reason = reason


def _canonical_linear_user_id(value: object) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ValueError("Linear user ID must be a canonical UUID")
    parsed = uuid.UUID(value)
    canonical = str(parsed)
    if canonical != value:
        raise ValueError("Linear user ID must be a canonical UUID")
    return canonical


def _redact_multiline_secret_values(text: str) -> str:
    redacted: list[str] = []
    secret_indent: int | None = None
    for line in text.splitlines():
        stripped = line.strip()
        indentation = len(line) - len(line.lstrip())
        if secret_indent is not None:
            if not stripped:
                redacted.append(line)
                continue
            if indentation > secret_indent or stripped.startswith("-"):
                redacted.append(" " * indentation + "[REDACTED]")
                continue
            secret_indent = None
        match = _SENSITIVE_BLOCK_START_RE.match(line)
        if match and match.group(2).strip() in {"", "|", ">", "|-", ">-"}:
            redacted.append(match.group(1) + " [REDACTED]")
            secret_indent = indentation
        else:
            redacted.append(line)
    return "\n".join(redacted)


def _summary_comment(response: str) -> str:
    redacted = _redact_multiline_secret_values(response)
    redacted = _PRIVATE_KEY_RE.sub("[REDACTED PRIVATE KEY]", redacted)
    redacted = _AUTH_HEADER_RE.sub(r"\1[REDACTED]", redacted)
    redacted = _COOKIE_HEADER_RE.sub(r"\1[REDACTED]", redacted)
    redacted = _URL_USERINFO_RE.sub(r"\1[REDACTED]@", redacted)
    redacted = _SECRET_ASSIGNMENT_RE.sub(r"\1[REDACTED]", redacted)
    redacted = _BEARER_RE.sub("Authorization [REDACTED]", redacted)
    redacted = _TOKEN_PREFIX_RE.sub("[REDACTED]", redacted)
    redacted = "\n".join(
        "[REDACTED SENSITIVE LINE]"
        if _SENSITIVE_LINE_RE.search(line) and "[REDACTED]" not in line
        else line
        for line in redacted.splitlines()
    )
    comment = f"### Agent session summary\n\n{redacted}"
    if len(comment) > _SUMMARY_LIMIT:
        return comment[: _SUMMARY_LIMIT - 1] + "…"
    return comment


@dataclass(frozen=True)
class QueuedLinearJob:
    delivery_id: str
    linear_session_id: str
    hermes_session_key: str
    prompt: str
    issue_id: str | None = None


class LinearWorker:
    """Consumes one profile's inbox and produces an idempotent response outbox."""

    def __init__(
        self,
        database: Path,
        *,
        profile: str,
        workspace: str,
        allowed_linear_user_ids: Iterable[str] | None = None,
    ) -> None:
        if not profile or not workspace:
            raise ValueError("profile and workspace are required")
        database.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.database = database
        self.profile = profile
        self.workspace = workspace
        if allowed_linear_user_ids is None:
            self.allowed_linear_user_ids = None
        else:
            configured_user_ids = tuple(allowed_linear_user_ids)
            try:
                canonical_user_ids = tuple(
                    _canonical_linear_user_id(value)
                    for value in configured_user_ids
                )
            except (AttributeError, TypeError, ValueError) as exc:
                raise ValueError(
                    "allowed_linear_user_ids must contain canonical UUIDs"
                ) from exc
            if (
                not canonical_user_ids
                or len(set(canonical_user_ids)) != len(canonical_user_ids)
            ):
                raise ValueError(
                    "allowed_linear_user_ids must be non-empty and unique"
                )
            self.allowed_linear_user_ids = frozenset(canonical_user_ids)
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS deliveries (
                    delivery_id TEXT PRIMARY KEY,
                    payload BLOB NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'pending',
                    created_at INTEGER NOT NULL,
                    issue_id TEXT,
                    requester_user_id TEXT,
                    rejection_reason TEXT
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    profile TEXT NOT NULL,
                    workspace TEXT NOT NULL,
                    linear_session_id TEXT NOT NULL,
                    hermes_session_key TEXT NOT NULL,
                    PRIMARY KEY (profile, workspace, linear_session_id)
                );
                CREATE TABLE IF NOT EXISTS event_receipts (
                    event_key TEXT PRIMARY KEY,
                    delivery_id TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS outbox (
                    delivery_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    linear_session_id TEXT NOT NULL,
                    body TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'pending',
                    sequence INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (delivery_id, kind)
                );
                CREATE TABLE IF NOT EXISTS outbox_sequence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT
                );
            """)
            delivery_columns = {
                str(row[1]) for row in conn.execute("PRAGMA table_info(deliveries)")
            }
            if "issue_id" not in delivery_columns:
                conn.execute("ALTER TABLE deliveries ADD COLUMN issue_id TEXT")
            if "requester_user_id" not in delivery_columns:
                conn.execute(
                    "ALTER TABLE deliveries ADD COLUMN requester_user_id TEXT"
                )
            if "rejection_reason" not in delivery_columns:
                conn.execute(
                    "ALTER TABLE deliveries ADD COLUMN rejection_reason TEXT"
                )
            outbox_columns = {
                str(row[1]) for row in conn.execute("PRAGMA table_info(outbox)")
            }
            if "sequence" not in outbox_columns:
                conn.execute(
                    "ALTER TABLE outbox ADD COLUMN sequence INTEGER NOT NULL DEFAULT 0"
                )
            conn.execute("UPDATE outbox SET sequence = rowid WHERE sequence = 0")
            max_sequence = int(
                conn.execute("SELECT COALESCE(MAX(sequence), 0) FROM outbox").fetchone()[0]
            )
            allocator_empty = conn.execute(
                "SELECT 1 FROM outbox_sequence LIMIT 1"
            ).fetchone() is None
            if allocator_empty and max_sequence:
                conn.execute(
                    "INSERT INTO outbox_sequence (id) VALUES (?)",
                    (max_sequence,),
                )
            # Status assignments are idempotent and safe to retry after a crash.
            # Creation operations remain quarantined because repeating them can
            # duplicate user-visible activity or comments.
            conn.execute(
                "UPDATE outbox SET state = CASE "
                "WHEN kind LIKE 'issue_status_%' THEN 'pending' "
                "ELSE 'ambiguous' END WHERE state = 'sending'"
            )
            # A running delivery may have completed agent-side work before the
            # process died. Do not execute it again. Surface the uncertainty to
            # Linear using the supported terminal response activity.
            running = conn.execute(
                "SELECT delivery_id, payload FROM deliveries WHERE state = 'running'"
            ).fetchall()
            for delivery_id, raw in running:
                try:
                    event = json.loads(bytes(raw))
                    if event.get("type") == "AgentSessionEvent":
                        session = event["agentSession"]
                    else:
                        session = event["data"]["agentSession"]
                    session_id = str(session["id"])
                    issue = session.get("issue") if isinstance(session, dict) else None
                    issue_id = (
                        str(issue["id"])
                        if isinstance(issue, dict) and issue.get("id")
                        else None
                    )
                    response = (
                        "The agent was interrupted before its status could be "
                        "confirmed. Please retry this request."
                    )
                    if session_id:
                        self._insert_outbox(
                            conn,
                            str(delivery_id),
                            "response",
                            session_id,
                            response,
                        )
                    if issue_id:
                        self._insert_outbox(
                            conn,
                            str(delivery_id),
                            "issue_comment",
                            issue_id,
                            _summary_comment(response),
                        )
                        self._insert_outbox(
                            conn,
                            str(delivery_id),
                            "issue_status_failure",
                            issue_id,
                            "failure",
                        )
                except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
                    pass
            conn.execute("UPDATE deliveries SET state = 'ambiguous' WHERE state = 'running'")

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.database, isolation_level=None, timeout=5.0)
        try:
            yield connection
        finally:
            connection.close()

    def _insert_outbox(
        self,
        conn: sqlite3.Connection,
        delivery_id: str,
        kind: str,
        target_id: str,
        body: str,
    ) -> None:
        sequence_row = conn.execute(
            "INSERT INTO outbox_sequence DEFAULT VALUES"
        )
        if sequence_row.lastrowid is None:
            raise RuntimeError("failed to allocate durable outbox sequence")
        sequence = int(sequence_row.lastrowid)
        conn.execute(
            "INSERT OR IGNORE INTO outbox "
            "(delivery_id, kind, linear_session_id, body, sequence) "
            "VALUES (?, ?, ?, ?, ?)",
            (delivery_id, kind, target_id, body, sequence),
        )

    def add_delivery(self, delivery_id: str, payload: bytes) -> None:
        if not delivery_id:
            raise ValueError("delivery id is required")
        with self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO deliveries (delivery_id, payload, payload_sha256, created_at) VALUES (?, ?, ?, ?)",
                (delivery_id, payload, hashlib.sha256(payload).hexdigest(), int(time.time())),
            )

    def import_from_ingress_once(self, ingress_database: Path) -> bool:
        """Copy one committed delivery from this profile's ingress inbox."""
        with closing(sqlite3.connect(ingress_database, isolation_level=None, timeout=5.0)) as ingress:
            ingress.execute("BEGIN IMMEDIATE")
            row = ingress.execute(
                "SELECT logical_agent, delivery_id, payload FROM deliveries WHERE profile = ? AND status = 'pending' ORDER BY received_at, delivery_id LIMIT 1",
                (self.profile,),
            ).fetchone()
            if row is None:
                ingress.execute("COMMIT")
                return False
            try:
                logical_agent, delivery_id, payload = str(row[0]), str(row[1]), bytes(row[2])
                self.add_delivery(delivery_id, payload)
                ingress.execute(
                    "UPDATE deliveries SET status = 'imported' WHERE logical_agent = ? AND delivery_id = ?",
                    (logical_agent, delivery_id),
                )
                ingress.execute("COMMIT")
            except Exception:
                ingress.execute("ROLLBACK")
                raise
        return True

    def _requester_user_id(
        self,
        *,
        event: dict[str, object],
        session: dict[str, object],
        action: object,
        linear_session_id: str,
        event_key: str,
    ) -> str | None:
        if self.allowed_linear_user_ids is None:
            return None
        primary: object = None
        consistency_values: list[object] = []
        if action == "created":
            primary = session.get("creatorId")
            creator = session.get("creator")
            if creator is not None and not isinstance(creator, dict):
                consistency_values.append(creator)
            elif isinstance(creator, dict) and creator.get("id") is not None:
                consistency_values.append(creator.get("id"))
        elif action == "prompted":
            activity = event.get("agentActivity")
            if isinstance(activity, dict):
                primary = activity.get("userId")
                user = activity.get("user")
                if user is not None and not isinstance(user, dict):
                    consistency_values.append(user)
                elif isinstance(user, dict) and user.get("id") is not None:
                    consistency_values.append(user.get("id"))

        requester_user_id: str | None = None
        if primary is None:
            reason = "linear_user_identity_missing"
        else:
            try:
                requester_user_id = _canonical_linear_user_id(primary)
            except (AttributeError, TypeError, ValueError):
                reason = "linear_user_identity_invalid"
            else:
                try:
                    consistency_ids = [
                        _canonical_linear_user_id(value)
                        for value in consistency_values
                    ]
                except (AttributeError, TypeError, ValueError):
                    reason = "linear_user_identity_invalid"
                else:
                    if any(
                        value != requester_user_id
                        for value in consistency_ids
                    ):
                        reason = "linear_user_identity_conflict"
                    elif requester_user_id not in self.allowed_linear_user_ids:
                        reason = "linear_user_not_allowed"
                    else:
                        return requester_user_id
        raise _LinearAuthorizationRejection(
            linear_session_id=linear_session_id,
            event_key=event_key,
            requester_user_id=requester_user_id,
            reason=reason,
        )

    def _record_authorization_rejection(
        self,
        conn: sqlite3.Connection,
        delivery_id: str,
        rejection: _LinearAuthorizationRejection,
    ) -> None:
        receipt = conn.execute(
            "SELECT delivery_id FROM event_receipts WHERE event_key = ?",
            (rejection.event_key,),
        ).fetchone()
        receipt_delivery_id = str(receipt[0]) if receipt is not None else None
        conn.execute(
            "UPDATE outbox SET state = 'suppressed' "
            "WHERE delivery_id = ? AND state IN ('pending', 'sending', 'ambiguous') "
            "AND NOT (kind = 'response' AND body = ?)",
            (delivery_id, _LINEAR_AUTHORIZATION_DENIAL),
        )
        if receipt_delivery_id is None:
            conn.execute(
                "INSERT INTO event_receipts (event_key, delivery_id) VALUES (?, ?)",
                (rejection.event_key, delivery_id),
            )
        if receipt_delivery_id in (None, delivery_id):
            response = conn.execute(
                "SELECT state, body FROM outbox "
                "WHERE delivery_id = ? AND kind = 'response'",
                (delivery_id,),
            ).fetchone()
            if response is None:
                self._insert_outbox(
                    conn,
                    delivery_id,
                    "response",
                    rejection.linear_session_id,
                    _LINEAR_AUTHORIZATION_DENIAL,
                )
            elif str(response[1]) == _LINEAR_AUTHORIZATION_DENIAL:
                if str(response[0]) != "sent":
                    conn.execute(
                        "UPDATE outbox SET state = 'pending' "
                        "WHERE delivery_id = ? AND kind = 'response'",
                        (delivery_id,),
                    )
            elif str(response[0]) != "sent":
                sequence_row = conn.execute(
                    "INSERT INTO outbox_sequence DEFAULT VALUES"
                )
                if sequence_row.lastrowid is None:
                    raise RuntimeError("failed to allocate durable outbox sequence")
                conn.execute(
                    "UPDATE outbox SET linear_session_id = ?, body = ?, "
                    "state = 'pending', sequence = ? "
                    "WHERE delivery_id = ? AND kind = 'response'",
                    (
                        rejection.linear_session_id,
                        _LINEAR_AUTHORIZATION_DENIAL,
                        int(sequence_row.lastrowid),
                        delivery_id,
                    ),
                )
        conn.execute(
            "UPDATE deliveries SET state = 'rejected', requester_user_id = ?, "
            "rejection_reason = ? WHERE delivery_id = ?",
            (rejection.requester_user_id, rejection.reason, delivery_id),
        )

    def _standard_job_from_payload(
        self,
        delivery_id: str,
        raw: bytes,
    ) -> tuple[QueuedLinearJob, str, bool]:
        """Parse one standard Linear Agent Session event without side effects."""
        try:
            event = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid Linear event") from exc
        if not isinstance(event, dict) or event.get("type") != "AgentSessionEvent":
            raise ValueError("unsupported Linear event")
        session = event.get("agentSession")
        if not isinstance(session, dict) or not session.get("id"):
            raise ValueError("AgentSessionEvent is missing session")
        linear_session_id = str(session["id"])
        issue = session.get("issue")
        issue_id = (
            str(issue["id"])
            if isinstance(issue, dict) and issue.get("id")
            else None
        )
        action = event.get("action")
        is_created = action == "created"
        if is_created:
            event_key = f"created:{linear_session_id}"
            prompt = str(event.get("promptContext") or "")
            if not prompt:
                comment = session.get("comment")
                if isinstance(comment, dict):
                    prompt = str(comment.get("body") or "")
        elif action == "prompted":
            activity = event.get("agentActivity")
            if not isinstance(activity, dict) or not activity.get("id"):
                raise ValueError("prompted AgentSessionEvent is missing activity")
            event_key = f"prompted:{activity['id']}"
            prompt = str(activity.get("body") or "")
            if not prompt:
                content = activity.get("content")
                if isinstance(content, dict):
                    prompt = str(content.get("body") or "")
                elif isinstance(content, str):
                    prompt = content
        else:
            raise ValueError("unsupported AgentSessionEvent action")
        self._requester_user_id(
            event=event,
            session=session,
            action=action,
            linear_session_id=linear_session_id,
            event_key=event_key,
        )
        if not prompt:
            raise ValueError("AgentSessionEvent is missing prompt")
        return (
            QueuedLinearJob(
                delivery_id=delivery_id,
                linear_session_id=linear_session_id,
                hermes_session_key=f"linear:{self.workspace}:{linear_session_id}",
                prompt=prompt,
                issue_id=issue_id,
            ),
            event_key,
            is_created,
        )

    def admit_once(self) -> tuple[bool, QueuedLinearJob | None]:
        """Durably admit one event to the FIFO without starting agent work."""
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT delivery_id, payload FROM deliveries "
                "WHERE state = 'pending' ORDER BY rowid LIMIT 1"
            ).fetchone()
            if row is None:
                conn.execute("COMMIT")
                return False, None
            delivery_id, raw = str(row[0]), bytes(row[1])
            try:
                job, event_key, _is_created = self._standard_job_from_payload(
                    delivery_id,
                    raw,
                )
            except _LinearAuthorizationRejection as rejection:
                self._record_authorization_rejection(conn, delivery_id, rejection)
                conn.execute("COMMIT")
                return True, None
            except ValueError:
                conn.execute(
                    "UPDATE deliveries SET state = 'rejected' WHERE delivery_id = ?",
                    (delivery_id,),
                )
                conn.execute("COMMIT")
                return True, None

            existing = conn.execute(
                "SELECT delivery_id FROM event_receipts WHERE event_key = ?",
                (event_key,),
            ).fetchone()
            if existing is not None:
                conn.execute(
                    "UPDATE deliveries SET state = 'completed' WHERE delivery_id = ?",
                    (delivery_id,),
                )
                conn.execute("COMMIT")
                return True, None

            conn.execute(
                "INSERT INTO event_receipts (event_key, delivery_id) VALUES (?, ?)",
                (event_key, delivery_id),
            )
            session = conn.execute(
                "SELECT hermes_session_key FROM sessions "
                "WHERE profile = ? AND workspace = ? AND linear_session_id = ?",
                (self.profile, self.workspace, job.linear_session_id),
            ).fetchone()
            if session is None:
                conn.execute(
                    "INSERT INTO sessions "
                    "(profile, workspace, linear_session_id, hermes_session_key) "
                    "VALUES (?, ?, ?, ?)",
                    (
                        self.profile,
                        self.workspace,
                        job.linear_session_id,
                        job.hermes_session_key,
                    ),
                )
            else:
                job = QueuedLinearJob(
                    delivery_id=job.delivery_id,
                    linear_session_id=job.linear_session_id,
                    hermes_session_key=str(session[0]),
                    prompt=job.prompt,
                    issue_id=job.issue_id,
                )
            conn.execute(
                "UPDATE deliveries SET issue_id = ? WHERE delivery_id = ?",
                (job.issue_id, delivery_id),
            )
            self._insert_outbox(
                conn,
                delivery_id,
                "thought",
                job.linear_session_id,
                "Queued for execution.",
            )
            if job.issue_id:
                issue_is_active = conn.execute(
                    "SELECT 1 FROM deliveries "
                    "WHERE issue_id = ? AND state = 'running' LIMIT 1",
                    (job.issue_id,),
                ).fetchone()
                if issue_is_active is None:
                    self._insert_outbox(
                        conn,
                        delivery_id,
                        "issue_status_waiting",
                        job.issue_id,
                        "waiting",
                    )
            conn.execute(
                "UPDATE deliveries SET state = 'queued' WHERE delivery_id = ?",
                (delivery_id,),
            )
            conn.execute("COMMIT")
            return True, job

    def claim_prepared(self) -> QueuedLinearJob | None:
        """Claim the oldest prepared job for the single serialized executor."""
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT delivery_id, payload FROM deliveries "
                "WHERE state = 'prepared' ORDER BY rowid LIMIT 1"
            ).fetchone()
            if row is None:
                conn.execute("COMMIT")
                return None
            delivery_id, raw = str(row[0]), bytes(row[1])
            try:
                job, _event_key, _is_created = self._standard_job_from_payload(
                    delivery_id,
                    raw,
                )
            except _LinearAuthorizationRejection as rejection:
                self._record_authorization_rejection(conn, delivery_id, rejection)
                conn.execute("COMMIT")
                return None
            session = conn.execute(
                "SELECT hermes_session_key FROM sessions "
                "WHERE profile = ? AND workspace = ? AND linear_session_id = ?",
                (self.profile, self.workspace, job.linear_session_id),
            ).fetchone()
            if session is None:
                conn.execute("ROLLBACK")
                raise RuntimeError("queued Linear job is missing its Hermes session")
            job = QueuedLinearJob(
                delivery_id=job.delivery_id,
                linear_session_id=job.linear_session_id,
                hermes_session_key=str(session[0]),
                prompt=job.prompt,
                issue_id=job.issue_id,
            )
            conn.execute(
                "UPDATE deliveries SET state = 'running' WHERE delivery_id = ?",
                (delivery_id,),
            )
            if job.issue_id:
                self._insert_outbox(
                    conn,
                    delivery_id,
                    "issue_status_active",
                    job.issue_id,
                    "active",
                )
            conn.execute("COMMIT")
            return job

    def release_claim(self, job: QueuedLinearJob) -> None:
        """Return a claimed job to prepared when its active status is unconfirmed."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE deliveries SET state = 'prepared' "
                "WHERE delivery_id = ? AND state = 'running'",
                (job.delivery_id,),
            )

    def execution_ready(self, job: QueuedLinearJob) -> bool:
        required = ["thought"]
        if job.issue_id:
            required.append("issue_status_active")
        placeholders = ",".join("?" for _ in required)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT kind, state FROM outbox WHERE delivery_id = ? "
                f"AND kind IN ({placeholders})",
                (job.delivery_id, *required),
            ).fetchall()
        states = {str(kind): str(state) for kind, state in rows}
        return all(states.get(kind) == "sent" for kind in required)

    def execution_suppressed(self, job: QueuedLinearJob) -> bool:
        if not job.issue_id:
            return False
        with self._connect() as conn:
            row = conn.execute(
                "SELECT state FROM outbox WHERE delivery_id = ? "
                "AND kind = 'issue_status_active'",
                (job.delivery_id,),
            ).fetchone()
        return row is not None and str(row[0]) == "suppressed"

    def cancel_job(self, job: QueuedLinearJob) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE deliveries SET state = 'canceled' "
                "WHERE delivery_id = ? AND state = 'running'",
                (job.delivery_id,),
            )

    def reauthorize_recoverable(self) -> bool:
        """Reject recoverable jobs that no longer satisfy policy."""
        if self.allowed_linear_user_ids is None:
            return False
        rejected = False
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                "SELECT delivery_id, payload FROM deliveries "
                "WHERE state IN ('queued', 'prepared', 'ambiguous') ORDER BY rowid"
            ).fetchall()
            for delivery_id, raw in rows:
                try:
                    self._standard_job_from_payload(str(delivery_id), bytes(raw))
                except _LinearAuthorizationRejection as rejection:
                    self._record_authorization_rejection(
                        conn, str(delivery_id), rejection
                    )
                    rejected = True
            conn.execute("COMMIT")
        return rejected

    def next_unprepared(self) -> QueuedLinearJob | None:
        """Return the oldest admitted job whose Hermes session needs preparing."""
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT delivery_id, payload FROM deliveries "
                "WHERE state = 'queued' ORDER BY rowid LIMIT 1"
            ).fetchone()
            if row is None:
                conn.execute("COMMIT")
                return None
            delivery_id, raw = str(row[0]), bytes(row[1])
            try:
                job, _event_key, _is_created = self._standard_job_from_payload(
                    delivery_id,
                    raw,
                )
            except _LinearAuthorizationRejection as rejection:
                self._record_authorization_rejection(conn, delivery_id, rejection)
                conn.execute("COMMIT")
                return None
            session = conn.execute(
                "SELECT hermes_session_key FROM sessions "
                "WHERE profile = ? AND workspace = ? AND linear_session_id = ?",
                (self.profile, self.workspace, job.linear_session_id),
            ).fetchone()
            if session is None:
                conn.execute("ROLLBACK")
                raise RuntimeError("queued Linear job is missing its session mapping")
            conn.execute("COMMIT")
            return QueuedLinearJob(
                delivery_id=job.delivery_id,
                linear_session_id=job.linear_session_id,
                hermes_session_key=str(session[0]),
                prompt=job.prompt,
                issue_id=job.issue_id,
            )

    def mark_prepared(self, job: QueuedLinearJob) -> None:
        """Record that the real Hermes session exists before execution."""
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            updated = conn.execute(
                "UPDATE deliveries SET state = 'prepared' "
                "WHERE delivery_id = ? AND state = 'queued'",
                (job.delivery_id,),
            ).rowcount
            if updated != 1:
                conn.execute("ROLLBACK")
                raise RuntimeError("Linear job is not awaiting session preparation")
            conn.execute("COMMIT")

    def complete_job(self, job: QueuedLinearJob, response: str) -> None:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._insert_outbox(
                conn,
                job.delivery_id,
                "response",
                job.linear_session_id,
                response,
            )
            if job.issue_id:
                self._insert_outbox(
                    conn,
                    job.delivery_id,
                    "issue_comment",
                    job.issue_id,
                    _summary_comment(response),
                )
                has_follow_up = conn.execute(
                    "SELECT 1 FROM deliveries WHERE issue_id = ? "
                    "AND delivery_id != ? AND state IN ('queued', 'prepared', 'running') "
                    "LIMIT 1",
                    (job.issue_id, job.delivery_id),
                ).fetchone()
                terminal_kind = (
                    "issue_status_terminal_waiting"
                    if has_follow_up is not None
                    else "issue_status_done"
                )
                terminal_state = "waiting" if has_follow_up is not None else "done"
                self._insert_outbox(
                    conn,
                    job.delivery_id,
                    terminal_kind,
                    job.issue_id,
                    terminal_state,
                )
            conn.execute(
                "UPDATE deliveries SET state = 'completed' WHERE delivery_id = ?",
                (job.delivery_id,),
            )
            conn.execute("COMMIT")

    def fail_job(self, job: QueuedLinearJob) -> None:
        response = "Unable to complete this request. Please retry."
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._insert_outbox(
                conn,
                job.delivery_id,
                "response",
                job.linear_session_id,
                response,
            )
            if job.issue_id:
                self._insert_outbox(
                    conn,
                    job.delivery_id,
                    "issue_comment",
                    job.issue_id,
                    _summary_comment(response),
                )
                self._insert_outbox(
                    conn,
                    job.delivery_id,
                    "issue_status_failure",
                    job.issue_id,
                    "failure",
                )
            conn.execute(
                "UPDATE deliveries SET state = 'completed' WHERE delivery_id = ?",
                (job.delivery_id,),
            )
            conn.execute("COMMIT")

    def _claim_one(self) -> tuple[str, bytes] | None:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT delivery_id, payload FROM deliveries WHERE state = 'pending' ORDER BY created_at, delivery_id LIMIT 1"
            ).fetchone()
            if row is None:
                conn.execute("COMMIT")
                return None
            conn.execute("UPDATE deliveries SET state = 'running' WHERE delivery_id = ?", (row[0],))
            conn.execute("COMMIT")
            return str(row[0]), bytes(row[1])

    def _reserve_event(self, event_key: str, delivery_id: str) -> bool:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT delivery_id FROM event_receipts WHERE event_key = ?",
                (event_key,),
            ).fetchone()
            if existing is not None:
                conn.execute("UPDATE deliveries SET state = 'completed' WHERE delivery_id = ?", (delivery_id,))
                conn.execute("COMMIT")
                return False
            conn.execute(
                "INSERT INTO event_receipts (event_key, delivery_id) VALUES (?, ?)",
                (event_key, delivery_id),
            )
            conn.execute("COMMIT")
            return True

    def _session_key(self, linear_session_id: str) -> str:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT hermes_session_key FROM sessions WHERE profile = ? AND workspace = ? AND linear_session_id = ?",
                (self.profile, self.workspace, linear_session_id),
            ).fetchone()
            if row is None:
                key = f"linear:{self.workspace}:{linear_session_id}"
                conn.execute(
                    "INSERT INTO sessions (profile, workspace, linear_session_id, hermes_session_key) VALUES (?, ?, ?, ?)",
                    (self.profile, self.workspace, linear_session_id, key),
                )
            else:
                key = str(row[0])
            conn.execute("COMMIT")
            return key

    def _queue_activity(self, delivery_id: str, kind: str, linear_session_id: str, body: str) -> None:
        with self._connect() as conn:
            self._insert_outbox(
                conn,
                delivery_id,
                kind,
                linear_session_id,
                body,
            )

    def process_once(
        self,
        execute: Callable[[str, str], str],
        *,
        before_execute: Callable[[], None] | None = None,
        on_error: Callable[[], None] | None = None,
    ) -> bool:
        claimed = self._claim_one()
        if claimed is None:
            return False
        delivery_id, raw = claimed
        linear_session_id: str | None = None
        event_key = f"delivery:{delivery_id}"
        try:
            try:
                event = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError):
                with self._connect() as conn:
                    conn.execute("UPDATE deliveries SET state = 'rejected' WHERE delivery_id = ?", (delivery_id,))
                return True
            if not isinstance(event, dict):
                with self._connect() as conn:
                    conn.execute("UPDATE deliveries SET state = 'rejected' WHERE delivery_id = ?", (delivery_id,))
                return True
            if event.get("type") == "AgentSessionEvent":
                session = event.get("agentSession")
                if not isinstance(session, dict) or not session.get("id"):
                    with self._connect() as conn:
                        conn.execute("UPDATE deliveries SET state = 'rejected' WHERE delivery_id = ?", (delivery_id,))
                    return True
                linear_session_id = str(session["id"])
                action = event.get("action")
                if action == "created":
                    event_key = f"created:{linear_session_id}"
                    prompt = str(event.get("promptContext") or "")
                    if not prompt:
                        session = event.get("agentSession") or {}
                        comment = session.get("comment") if isinstance(session, dict) else None
                        if isinstance(comment, dict):
                            prompt = str(comment.get("body") or "")
                elif action == "prompted":
                    activity = event.get("agentActivity") or {}
                    activity_id = str(activity.get("id") or "") if isinstance(activity, dict) else ""
                    if not activity_id:
                        with self._connect() as conn:
                            conn.execute("UPDATE deliveries SET state = 'rejected' WHERE delivery_id = ?", (delivery_id,))
                        return True
                    event_key = f"prompted:{activity_id}"
                    prompt = str(activity.get("body") or "")
                    if not prompt:
                        content = activity.get("content") or {}
                        if isinstance(content, dict):
                            prompt = str(content.get("body") or "")
                        elif isinstance(content, str):
                            prompt = content
                else:
                    raise ValueError("unsupported AgentSessionEvent action")
                try:
                    self._requester_user_id(
                        event=event,
                        session=session,
                        action=action,
                        linear_session_id=linear_session_id,
                        event_key=event_key,
                    )
                except _LinearAuthorizationRejection as rejection:
                    with self._connect() as conn:
                        conn.execute("BEGIN IMMEDIATE")
                        self._record_authorization_rejection(
                            conn,
                            delivery_id,
                            rejection,
                        )
                        conn.execute("COMMIT")
                    return True
            else:
                # Compatibility for pre-standardisation inbox records only.
                data = event.get("data")
                session = data.get("agentSession") if isinstance(data, dict) else None
                legacy_prompt = data.get("prompt") if isinstance(data, dict) else None
                if not isinstance(session, dict) or not session.get("id"):
                    with self._connect() as conn:
                        conn.execute("UPDATE deliveries SET state = 'rejected' WHERE delivery_id = ?", (delivery_id,))
                    return True
                linear_session_id = str(session["id"])
                if self.allowed_linear_user_ids is not None:
                    rejection = _LinearAuthorizationRejection(
                        linear_session_id=linear_session_id,
                        event_key=event_key,
                        requester_user_id=None,
                        reason="linear_user_identity_missing",
                    )
                    with self._connect() as conn:
                        conn.execute("BEGIN IMMEDIATE")
                        self._record_authorization_rejection(
                            conn,
                            delivery_id,
                            rejection,
                        )
                        conn.execute("COMMIT")
                    return True
                if not legacy_prompt:
                    self._queue_activity(
                        delivery_id,
                        "response",
                        linear_session_id,
                        "Unable to process this Linear event. Please retry your request.",
                    )
                    with self._connect() as conn:
                        conn.execute("UPDATE deliveries SET state = 'completed' WHERE delivery_id = ?", (delivery_id,))
                    return True
                prompt = str(legacy_prompt)
            if not linear_session_id or not prompt:
                raise ValueError("AgentSessionEvent is missing session or prompt")
            if not self._reserve_event(event_key, delivery_id):
                return True
            if event.get("type") == "AgentSessionEvent" and event.get("action") == "created":
                self._queue_activity(delivery_id, "thought", linear_session_id, "Working on this now.")
                if before_execute is not None:
                    before_execute()
            response = str(execute(self._session_key(linear_session_id), prompt))
            with self._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                self._insert_outbox(
                    conn,
                    delivery_id,
                    "response",
                    linear_session_id,
                    response,
                )
                conn.execute("UPDATE deliveries SET state = 'completed' WHERE delivery_id = ?", (delivery_id,))
                conn.execute("COMMIT")
        except Exception:
            if linear_session_id:
                self._queue_activity(
                    delivery_id,
                    "response",
                    linear_session_id,
                    "Unable to complete this request. Please retry.",
                )
                with self._connect() as conn:
                    conn.execute("UPDATE deliveries SET state = 'completed' WHERE delivery_id = ?", (delivery_id,))
                if on_error is not None:
                    on_error()
                return True
            with self._connect() as conn:
                conn.execute("UPDATE deliveries SET state = 'pending' WHERE delivery_id = ?", (delivery_id,))
            raise
        return True

    def dispatch_outbox(self, emit: Callable[[str, str, str], object]) -> bool:
        """Emit one activity once; quarantine ambiguity instead of reposting."""
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT delivery_id, kind, linear_session_id, body FROM outbox "
                "WHERE state = 'pending' ORDER BY sequence, rowid LIMIT 1"
            ).fetchone()
            if row is None:
                conn.execute("COMMIT")
                return False
            conn.execute("UPDATE outbox SET state = 'sending' WHERE delivery_id = ? AND kind = ?", (row[0], row[1]))
            conn.execute("COMMIT")
        try:
            kind = str(row[1])
            operation = "issue_status" if kind.startswith("issue_status_") else kind
            outcome = emit(str(row[2]), operation, str(row[3]))
        except Exception:
            retry_state = (
                "pending" if str(row[1]).startswith("issue_status_") else "ambiguous"
            )
            with self._connect() as conn:
                conn.execute(
                    "UPDATE outbox SET state = ? "
                    "WHERE delivery_id = ? AND kind = ?",
                    (retry_state, row[0], row[1]),
                )
            raise
        final_state = "suppressed" if outcome is False else "sent"
        with self._connect() as conn:
            conn.execute(
                "UPDATE outbox SET state = ? WHERE delivery_id = ? AND kind = ?",
                (final_state, row[0], row[1]),
            )
        return True

    def outbox(self) -> list[tuple[str, str, str]]:
        with self._connect() as conn:
            return [(str(kind), str(session), str(body)) for kind, session, body in conn.execute(
                "SELECT kind, linear_session_id, body FROM outbox ORDER BY delivery_id, kind"
            )]

    def outbox_state(self) -> list[str]:
        with self._connect() as conn:
            return [str(row[0]) for row in conn.execute("SELECT state FROM outbox ORDER BY delivery_id, kind")]

    def delivery_rejection(
        self,
        delivery_id: str,
    ) -> tuple[str | None, str | None] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT requester_user_id, rejection_reason FROM deliveries "
                "WHERE delivery_id = ?",
                (delivery_id,),
            ).fetchone()
            if row is None:
                return None
            return (
                str(row[0]) if row[0] is not None else None,
                str(row[1]) if row[1] is not None else None,
            )

    def delivery_state(self, delivery_id: str) -> str | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT state FROM deliveries WHERE delivery_id = ?", (delivery_id,)
            ).fetchone()
            return str(row[0]) if row is not None else None
