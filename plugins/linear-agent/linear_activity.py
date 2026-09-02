"""Minimal Linear Agent Activity GraphQL client."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable

_ENDPOINT = "https://api.linear.app/graphql"
_MUTATION = """mutation AgentActivityCreate($input: AgentActivityCreateInput!) {
  agentActivityCreate(input: $input) { success }
}"""
_READINESS_QUERY = "query LinearAgentReadiness { viewer { id } }"
_ISSUE_WORKFLOW_QUERY = """query LinearIssueWorkflow($id: String!) {
  issue(id: $id) {
    id
    state { type }
    team { states { nodes { id name type position } } }
  }
}"""
_ISSUE_UPDATE_MUTATION = """mutation LinearIssueUpdate($id: String!, $input: IssueUpdateInput!) {
  issueUpdate(id: $id, input: $input) { success }
}"""
_COMMENT_CREATE_MUTATION = """mutation LinearIssueComment($input: CommentCreateInput!) {
  commentCreate(input: $input) { success }
}"""


class LinearActivityClient:
    def __init__(self, access_token: str | Callable[[], str], *, transport: Callable[[str, dict[str, str], bytes], bytes] | None = None) -> None:
        if not access_token:
            raise ValueError("Linear access token is required")
        self._access_token = access_token
        self._transport = transport or self._http_transport

    def _token(self) -> str:
        access_token = self._access_token() if callable(self._access_token) else self._access_token
        if not access_token:
            raise RuntimeError("Linear access token provider returned no token")
        return access_token

    def verify_authenticated(self) -> None:
        encoded = json.dumps({"query": _READINESS_QUERY}, separators=(",", ":")).encode("utf-8")
        raw = self._send_authenticated(encoded)
        result = json.loads(raw)
        if result.get("errors") or not result.get("data", {}).get("viewer", {}).get("id"):
            raise RuntimeError("Linear authentication readiness check failed")

    @staticmethod
    def _http_transport(url: str, headers: dict[str, str], body: bytes) -> bytes:
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(request, timeout=15) as response:  # nosec B310: fixed HTTPS API endpoint
            return response.read()

    def emit(self, agent_session_id: str, activity_type: str, body: str) -> None:
        if activity_type not in {"thought", "response", "elicitation"}:
            raise ValueError("unsupported Agent Activity type")
        if not agent_session_id or not body:
            raise ValueError("agent session and activity body are required")
        payload = {
            "query": _MUTATION,
            "variables": {"input": {"agentSessionId": agent_session_id, "content": {"type": activity_type, "body": body}}},
        }
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        raw = self._send_authenticated(encoded)
        result = json.loads(raw)
        if result.get("errors") or not result.get("data", {}).get("agentActivityCreate", {}).get("success"):
            raise RuntimeError("Linear rejected Agent Activity")

    def dispatch(self, target_id: str, operation: str, body: str) -> bool:
        if not target_id or not body:
            raise ValueError("Linear operation requires target and body")
        if operation in {"thought", "response"}:
            self.emit(target_id, operation, body)
            return True
        if operation == "issue_comment":
            result = self._graphql(
                _COMMENT_CREATE_MUTATION,
                {"input": {"issueId": target_id, "body": body}},
            )
            if not result.get("data", {}).get("commentCreate", {}).get("success"):
                raise RuntimeError("Linear rejected issue comment")
            return True
        if operation != "issue_status" or body not in {"waiting", "active", "done", "failure"}:
            raise ValueError("unsupported Linear issue operation")
        result = self._graphql(_ISSUE_WORKFLOW_QUERY, {"id": target_id})
        issue = result.get("data", {}).get("issue")
        if not isinstance(issue, dict):
            raise RuntimeError("Linear issue workflow lookup failed")  # noqa: TRY004
        current_state = issue.get("state")
        if (
            isinstance(current_state, dict)
            and current_state.get("type") in {"canceled", "duplicate"}
        ):
            return False
        states = issue.get("team", {}).get("states", {}).get("nodes", [])
        preferred_name, fallback_type = {
            "waiting": ("Todo", "unstarted"),
            "failure": ("Todo", "unstarted"),
            "active": ("In Progress", "started"),
            "done": ("Done", "completed"),
        }[body]
        candidates = [state for state in states if isinstance(state, dict)]
        target = next(
            (state for state in candidates if state.get("name") == preferred_name),
            None,
        )
        if target is None:
            matching = [state for state in candidates if state.get("type") == fallback_type]
            target = min(matching, key=lambda state: float(state.get("position", 0))) if matching else None
        if not isinstance(target, dict) or not target.get("id"):
            raise RuntimeError(f"Linear {preferred_name} workflow state is unavailable")
        updated = self._graphql(
            _ISSUE_UPDATE_MUTATION,
            {"id": target_id, "input": {"stateId": str(target["id"])}},
        )
        if not updated.get("data", {}).get("issueUpdate", {}).get("success"):
            raise RuntimeError("Linear rejected issue status update")
        return True

    def _graphql(self, query: str, variables: dict[str, object]) -> dict[str, object]:
        encoded = json.dumps(
            {"query": query, "variables": variables}, separators=(",", ":")
        ).encode("utf-8")
        result = json.loads(self._send_authenticated(encoded))
        if result.get("errors"):
            raise RuntimeError("Linear GraphQL operation failed")
        return result

    def _send_authenticated(self, encoded: bytes) -> bytes:
        def send() -> bytes:
            return self._transport(
                _ENDPOINT,
                {"Authorization": f"Bearer {self._token()}", "Content-Type": "application/json"},
                encoded,
            )
        try:
            raw = send()
        except urllib.error.HTTPError as exc:
            if exc.code != 401 or not callable(self._access_token) or not hasattr(self._access_token, "invalidate"):
                raise
            self._access_token.invalidate()
            raw = send()
        return raw
