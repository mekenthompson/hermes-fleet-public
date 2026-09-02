"""Contract test for Linear Agent Activity GraphQL requests."""
from __future__ import annotations

import json
import sys
import unittest
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugins" / "linear-agent"))
from linear_activity import LinearActivityClient


class LinearActivityClientTests(unittest.TestCase):
    def test_readiness_probe_is_read_only_and_authenticated(self) -> None:
        requests = []
        def transport(_url, headers, body):
            requests.append((headers, json.loads(body)))
            return json.dumps({"data": {"viewer": {"id": "viewer-id"}}}).encode()
        client = LinearActivityClient("test-token", transport=transport)
        client.verify_authenticated()
        self.assertEqual(requests[0][0]["Authorization"], "Bearer test-token")
        self.assertIn("viewer", requests[0][1]["query"])
        self.assertNotIn("mutation", requests[0][1]["query"].lower())

    def test_readiness_401_invalidates_and_retries_once(self) -> None:
        class Tokens:
            def __init__(self): self.invalidations = 0
            def __call__(self): return "fresh" if self.invalidations else "expired"
            def invalidate(self): self.invalidations += 1
        tokens = Tokens()
        seen = []
        def transport(_url, headers, _body):
            seen.append(headers["Authorization"])
            if len(seen) == 1:
                raise urllib.error.HTTPError("https://api.linear.app/graphql", 401, "unauthorized", {}, None)
            return b'{"data":{"viewer":{"id":"viewer-id"}}}'
        LinearActivityClient(tokens, transport=transport).verify_authenticated()
        self.assertEqual(seen, ["Bearer expired", "Bearer fresh"])
        self.assertEqual(tokens.invalidations, 1)

    def test_emits_documented_thought_activity_shape(self) -> None:
        seen: dict[str, object] = {}

        def transport(url: str, headers: dict[str, str], body: bytes) -> bytes:
            seen.update(url=url, headers=headers, body=json.loads(body))
            return b'{"data":{"agentActivityCreate":{"success":true}}}'

        client = LinearActivityClient("test-token", transport=transport)
        client.emit("session-1", "thought", "Starting work")

        self.assertEqual(seen["url"], "https://api.linear.app/graphql")
        self.assertEqual(seen["headers"]["Authorization"], "Bearer test-token")
        variables = seen["body"]["variables"]
        self.assertEqual(variables["input"], {"agentSessionId": "session-1", "content": {"type": "thought", "body": "Starting work"}})


    def test_dispatch_preserves_agent_activity_operations(self) -> None:
        requests = []

        def transport(_url: str, _headers: dict[str, str], body: bytes) -> bytes:
            requests.append(json.loads(body))
            return b'{"data":{"agentActivityCreate":{"success":true}}}'

        LinearActivityClient("test-token", transport=transport).dispatch(
            "session-1", "response", "Finished"
        )

        self.assertEqual(
            requests[0]["variables"],
            {
                "input": {
                    "agentSessionId": "session-1",
                    "content": {"type": "response", "body": "Finished"},
                }
            },
        )

    def test_waiting_operation_moves_issue_to_todo(self) -> None:
        requests = []

        def transport(_url: str, _headers: dict[str, str], body: bytes) -> bytes:
            request = json.loads(body)
            requests.append(request)
            if "LinearIssueWorkflow" in request["query"]:
                return json.dumps({
                    "data": {
                        "issue": {
                            "id": "issue-1",
                            "state": {"type": "backlog"},
                            "team": {
                                "states": {
                                    "nodes": [
                                        {"id": "todo-id", "name": "Todo", "type": "unstarted", "position": 1},
                                        {"id": "active-id", "name": "In Progress", "type": "started", "position": 2},
                                        {"id": "done-id", "name": "Done", "type": "completed", "position": 3},
                                    ]
                                }
                            },
                        }
                    }
                }).encode()
            return b'{"data":{"issueUpdate":{"success":true}}}'

        LinearActivityClient("test-token", transport=transport).dispatch(
            "issue-1", "issue_status", "waiting"
        )

        self.assertEqual(len(requests), 2)
        self.assertEqual(
            requests[1]["variables"]["input"],
            {"stateId": "todo-id"},
        )

    def test_active_and_done_operations_use_matching_workflow_states(self) -> None:
        for operation, expected_state in (
            ("active", "active-id"),
            ("done", "done-id"),
            ("failure", "todo-id"),
        ):
            with self.subTest(operation=operation):
                requests = []

                def transport(
                    _url: str,
                    _headers: dict[str, str],
                    body: bytes,
                    _requests=requests,
                ) -> bytes:
                    request = json.loads(body)
                    _requests.append(request)
                    if "LinearIssueWorkflow" in request["query"]:
                        return json.dumps({
                            "data": {
                                "issue": {
                                    "id": "issue-1",
                                    "state": {"type": "unstarted"},
                                    "team": {
                                        "states": {
                                            "nodes": [
                                                {"id": "todo-id", "name": "Todo", "type": "unstarted", "position": 1},
                                                {"id": "review-id", "name": "In Review", "type": "started", "position": 1002},
                                                {"id": "active-id", "name": "In Progress", "type": "started", "position": 2},
                                                {"id": "done-id", "name": "Done", "type": "completed", "position": 3},
                                            ]
                                        }
                                    },
                                }
                            }
                        }).encode()
                    return b'{"data":{"issueUpdate":{"success":true}}}'

                LinearActivityClient("test-token", transport=transport).dispatch(
                    "issue-1", "issue_status", operation
                )

                self.assertEqual(
                    requests[1]["variables"]["input"],
                    {"stateId": expected_state},
                )

    def test_terminal_issue_is_not_reopened_by_waiting_operation(self) -> None:
        requests = []

        def transport(_url: str, _headers: dict[str, str], body: bytes) -> bytes:
            request = json.loads(body)
            requests.append(request)
            return json.dumps({
                "data": {
                    "issue": {
                        "id": "issue-1",
                        "state": {"type": "canceled"},
                        "team": {
                            "states": {
                                "nodes": [
                                    {"id": "todo-id", "name": "Todo", "type": "unstarted", "position": 1}
                                ]
                            }
                        },
                    }
                }
            }).encode()

        dispatched = LinearActivityClient(
            "test-token", transport=transport
        ).dispatch("issue-1", "issue_status", "waiting")

        self.assertIs(dispatched, False)
        self.assertEqual(len(requests), 1)

    def test_new_turn_reopens_completed_issue_to_todo(self) -> None:
        requests = []

        def transport(_url: str, _headers: dict[str, str], body: bytes) -> bytes:
            request = json.loads(body)
            requests.append(request)
            if "LinearIssueWorkflow" in request["query"]:
                return json.dumps({
                    "data": {
                        "issue": {
                            "id": "issue-1",
                            "state": {"type": "completed"},
                            "team": {
                                "states": {
                                    "nodes": [
                                        {
                                            "id": "todo-id",
                                            "name": "Todo",
                                            "type": "unstarted",
                                            "position": 1,
                                        }
                                    ]
                                }
                            },
                        }
                    }
                }).encode()
            return b'{"data":{"issueUpdate":{"success":true}}}'

        dispatched = LinearActivityClient(
            "test-token", transport=transport
        ).dispatch("issue-1", "issue_status", "waiting")

        self.assertIs(dispatched, True)
        self.assertEqual(
            requests[1]["variables"]["input"],
            {"stateId": "todo-id"},
        )

    def test_comment_operation_adds_a_normal_issue_comment(self) -> None:
        requests = []

        def transport(_url: str, _headers: dict[str, str], body: bytes) -> bytes:
            requests.append(json.loads(body))
            return b'{"data":{"commentCreate":{"success":true}}}'

        LinearActivityClient("test-token", transport=transport).dispatch(
            "issue-1", "issue_comment", "### Agent session summary\n\nFinished the work."
        )

        self.assertEqual(len(requests), 1)
        self.assertEqual(
            requests[0]["variables"]["input"],
            {
                "issueId": "issue-1",
                "body": "### Agent session summary\n\nFinished the work.",
            },
        )

    def test_refreshable_token_provider_is_resolved_for_each_activity(self) -> None:
        tokens = iter(("first-token", "second-token"))
        authorizations = []

        def transport(_url: str, headers: dict[str, str], _body: bytes) -> bytes:
            authorizations.append(headers["Authorization"])
            return b'{"data":{"agentActivityCreate":{"success":true}}}'

        client = LinearActivityClient(lambda: next(tokens), transport=transport)
        client.emit("session-1", "thought", "Starting")
        client.emit("session-1", "response", "Done")

        self.assertEqual(authorizations, ["Bearer first-token", "Bearer second-token"])


    def test_rejects_action_without_action_payload_shape(self) -> None:
        client = LinearActivityClient("test-token", transport=lambda *_: b"{}")
        with self.assertRaises(ValueError):
            client.emit("session-1", "action", "not a valid action payload")

    def test_http_401_invalidates_and_retries_exactly_once(self) -> None:
        class Tokens:
            def __init__(self):
                self.invalidations = 0
            def __call__(self):
                return "fresh" if self.invalidations else "expired"
            def invalidate(self):
                self.invalidations += 1
        tokens = Tokens()
        seen = []
        def transport(_url, headers, _body):
            seen.append(headers["Authorization"])
            if len(seen) == 1:
                raise urllib.error.HTTPError("https://api.linear.app/graphql", 401, "unauthorized", {}, None)
            return b'{"data":{"agentActivityCreate":{"success":true}}}'
        LinearActivityClient(tokens, transport=transport).emit("session-1", "thought", "Starting")
        self.assertEqual(seen, ["Bearer expired", "Bearer fresh"])
        self.assertEqual(tokens.invalidations, 1)

    def test_second_http_401_is_not_retried_a_third_time(self) -> None:
        class Tokens:
            def __init__(self): self.invalidations = 0
            def __call__(self): return "token"
            def invalidate(self): self.invalidations += 1
        tokens = Tokens()
        calls = []
        def transport(*_args):
            calls.append(True)
            raise urllib.error.HTTPError("https://api.linear.app/graphql", 401, "unauthorized", {}, None)
        with self.assertRaises(urllib.error.HTTPError):
            LinearActivityClient(tokens, transport=transport).emit("session-1", "thought", "Starting")
        self.assertEqual(len(calls), 2)
        self.assertEqual(tokens.invalidations, 1)

    def test_non_401_transport_failure_is_never_retried(self) -> None:
        calls = []
        def transport(*_args):
            calls.append(True)
            raise TimeoutError("ambiguous")
        with self.assertRaises(TimeoutError):
            LinearActivityClient(lambda: "token", transport=transport).emit("session-1", "response", "Done")
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
