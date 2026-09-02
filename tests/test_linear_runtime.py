"""Profile-local runtime integration tests, no real gateway or Linear calls."""
from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
agent = types.ModuleType("agent")
secret_scope = types.ModuleType("agent.secret_scope")
secret_scope.get_secret = lambda _name, default="": default
agent.secret_scope = secret_scope
sys.modules.setdefault("agent", agent)
sys.modules.setdefault("agent.secret_scope", secret_scope)
PLUGIN_DIR = ROOT / "plugins" / "linear-agent"
SPEC = importlib.util.spec_from_file_location(
    "hermes_plugins.linear_agent_runtime_test",
    PLUGIN_DIR / "__init__.py",
    submodule_search_locations=[str(PLUGIN_DIR)],
)
assert SPEC is not None and SPEC.loader is not None
PACKAGE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PACKAGE
SPEC.loader.exec_module(PACKAGE)
from hermes_plugins.linear_agent_runtime_test.linear_agent import LinearWorker
from hermes_plugins.linear_agent_runtime_test.linear_runtime import ProfileLinearRuntime

from tests.linear_ingress_fixture import IngressStore, Route


ALLOWED_USER_ID = "11111111-1111-4111-8111-111111111111"
DENIED_USER_ID = "22222222-2222-4222-8222-222222222222"


class LinearRuntimeTests(unittest.TestCase):
    def test_unauthorized_event_never_prepares_or_executes_session(self) -> None:
        async def scenario():
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                inbox = root / "inbox"
                ingress = IngressStore(inbox / "ingress.db")
                route = Route(
                    "sample",
                    "sample",
                    "/webhook/sample/linear",
                    root / "unused.env",
                    inbox,
                )
                ingress.enqueue(route, "delivery-1", json.dumps({
                    "type": "AgentSessionEvent",
                    "action": "created",
                    "agentSession": {
                        "id": "session-1",
                        "creatorId": DENIED_USER_ID,
                    },
                    "promptContext": "must not execute",
                }).encode())
                prepared: list[str] = []
                executed: list[str] = []
                activities: list[tuple[str, str, str]] = []
                worker = LinearWorker(
                    root / "worker.db",
                    profile="sample",
                    workspace="example-workspace",
                    allowed_linear_user_ids=[ALLOWED_USER_ID],
                )

                async def prepare(session_key: str):
                    prepared.append(session_key)

                async def execute(_session_key: str, prompt: str):
                    executed.append(prompt)
                    return "must not execute"

                runtime = ProfileLinearRuntime(
                    worker,
                    inbox / "ingress.db",
                    execute,
                    lambda session_id, activity_type, body: activities.append(
                        (session_id, activity_type, body)
                    ),
                    prepare=prepare,
                )

                self.assertTrue(await runtime.run_once())

                self.assertEqual(prepared, [])
                self.assertEqual(executed, [])
                self.assertEqual(worker.delivery_state("delivery-1"), "rejected")
                self.assertEqual(activities, [(
                    "session-1",
                    "response",
                    "This agent is restricted to approved workspace users.",
                )])

        asyncio.run(scenario())

    def test_policy_migration_rejects_recovery_before_flush(self) -> None:
        async def scenario(state):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                db, ingress = root / "worker.db", root / "ingress.db"
                IngressStore(ingress)
                payload = {
                    "type": "AgentSessionEvent",
                    "action": "created",
                    "agentSession": {
                        "id": "session-1",
                        "creatorId": DENIED_USER_ID,
                        "issue": {"id": "issue-1"},
                    },
                    "promptContext": "work",
                }
                old = LinearWorker(db, profile="sample", workspace="example-workspace")
                old.add_delivery("delivery-1", json.dumps(payload).encode())
                self.assertTrue(old.admit_once()[0])
                if state in ("prepared", "ambiguous"):
                    job = old.next_unprepared()
                    self.assertIsNotNone(job)
                    old.mark_prepared(job)
                if state == "ambiguous":
                    claimed = old.claim_prepared()
                    self.assertIsNotNone(claimed)
                prepared, executed, activities = [], [], []

                async def prepare(key):
                    prepared.append(key)

                async def execute(_key, prompt):
                    executed.append(prompt)
                    return "must not execute"

                restricted = LinearWorker(
                    db,
                    profile="sample",
                    workspace="example-workspace",
                    allowed_linear_user_ids=[ALLOWED_USER_ID],
                )
                runtime = ProfileLinearRuntime(
                    restricted,
                    ingress,
                    execute,
                    lambda *activity: activities.append(activity),
                    prepare=prepare,
                )
                self.assertTrue(await runtime.run_once())
                self.assertEqual((prepared, executed), ([], []))
                self.assertEqual(restricted.delivery_state("delivery-1"), "rejected")
                self.assertEqual(
                    activities,
                    [(
                        "session-1",
                        "response",
                        "This agent is restricted to approved workspace users.",
                    )],
                )
                outbox_states = restricted.outbox_state()
                self.assertEqual(outbox_states.count("sent"), 1)
                self.assertEqual(
                    set(outbox_states),
                    {"sent", "suppressed"},
                )

        for state in ("queued", "prepared", "ambiguous"):
            asyncio.run(scenario(state))

    def test_new_sessions_are_prepared_immediately_but_execute_fifo(self) -> None:
        async def scenario():
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                inbox = root / "inbox"
                ingress = IngressStore(inbox / "ingress.db")
                route = Route("sample", "sample", "/webhook/sample/linear", root / "unused.env", inbox)
                for number in (1, 2):
                    ingress.enqueue(route, f"delivery-{number}", json.dumps({
                        "type": "AgentSessionEvent",
                        "action": "created",
                        "agentSession": {"id": f"session-{number}"},
                        "promptContext": f"work-{number}",
                    }).encode())

                first_started = asyncio.Event()
                release_first = asyncio.Event()
                prepared, executed, activities = [], [], []
                active = 0
                max_active = 0

                async def prepare(session_key):
                    prepared.append(session_key)

                async def execute(session_key, prompt):
                    nonlocal active, max_active
                    active += 1
                    max_active = max(max_active, active)
                    executed.append((session_key, prompt))
                    if prompt == "work-1":
                        first_started.set()
                        await release_first.wait()
                    active -= 1
                    return f"finished-{prompt}"

                runtime = ProfileLinearRuntime(
                    LinearWorker(root / "worker.db", profile="sample", workspace="example-workspace"),
                    inbox / "ingress.db",
                    execute,
                    lambda session_id, activity_type, body: activities.append((session_id, activity_type, body)),
                    prepare=prepare,
                )

                self.assertTrue(await runtime.run_once())
                await asyncio.wait_for(first_started.wait(), timeout=1)
                self.assertTrue(await runtime.run_once())

                self.assertEqual(prepared, [
                    "linear:example-workspace:session-1",
                    "linear:example-workspace:session-2",
                ])
                self.assertEqual(executed, [("linear:example-workspace:session-1", "work-1")])
                self.assertEqual(activities[:2], [
                    ("session-1", "thought", "Queued for execution."),
                    ("session-2", "thought", "Queued for execution."),
                ])

                release_first.set()
                for _ in range(20):
                    await runtime.run_once()
                    if len(executed) == 2 and len(activities) == 4:
                        break
                    await asyncio.sleep(0)

                self.assertEqual(executed, [
                    ("linear:example-workspace:session-1", "work-1"),
                    ("linear:example-workspace:session-2", "work-2"),
                ])
                self.assertEqual(max_active, 1)
                self.assertEqual(activities[-2:], [
                    ("session-1", "response", "finished-work-1"),
                    ("session-2", "response", "finished-work-2"),
                ])

        asyncio.run(scenario())

    def test_restart_executes_older_queued_job_before_new_delivery(self) -> None:
        async def scenario():
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                inbox = root / "inbox"
                worker = LinearWorker(root / "worker.db", profile="sample", workspace="example-workspace")
                worker.add_delivery("older", json.dumps({
                    "type": "AgentSessionEvent",
                    "action": "created",
                    "agentSession": {"id": "session-older"},
                    "promptContext": "older",
                }).encode())
                admitted, old_job = worker.admit_once()
                self.assertTrue(admitted)
                self.assertIsNotNone(old_job)

                ingress = IngressStore(inbox / "ingress.db")
                route = Route("sample", "sample", "/webhook/sample/linear", root / "unused.env", inbox)
                ingress.enqueue(route, "newer", json.dumps({
                    "type": "AgentSessionEvent",
                    "action": "created",
                    "agentSession": {"id": "session-newer"},
                    "promptContext": "newer",
                }).encode())
                prepared, executed = [], []

                async def prepare(session_key):
                    prepared.append(session_key)

                async def execute(_session_key, prompt):
                    executed.append(prompt)
                    return "done"

                runtime = ProfileLinearRuntime(
                    LinearWorker(root / "worker.db", profile="sample", workspace="example-workspace"),
                    inbox / "ingress.db",
                    execute,
                    lambda *_args: None,
                    prepare=prepare,
                )
                self.assertTrue(await runtime.run_once())
                for _ in range(8):
                    await asyncio.sleep(0)
                    await runtime.run_once()
                    if executed:
                        break

                self.assertEqual(prepared[0], "linear:example-workspace:session-older")
                self.assertEqual(executed[0], "older")

        asyncio.run(scenario())

    def test_restart_retries_session_preparation_before_execution(self) -> None:
        async def scenario():
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                inbox = root / "inbox"
                IngressStore(inbox / "ingress.db")
                worker = LinearWorker(
                    root / "worker.db",
                    profile="sample",
                    workspace="example-workspace",
                )
                worker.add_delivery("delivery-1", json.dumps({
                    "type": "AgentSessionEvent",
                    "action": "created",
                    "agentSession": {"id": "session-1"},
                    "promptContext": "work",
                }).encode())
                admitted, job = worker.admit_once()
                self.assertTrue(admitted)
                self.assertIsNotNone(job)
                self.assertEqual(worker.delivery_state("delivery-1"), "queued")

                order = []

                async def prepare(_session_key):
                    order.append("prepare")

                async def execute(_session_key, _prompt):
                    order.append("execute")
                    return "done"

                runtime = ProfileLinearRuntime(
                    LinearWorker(
                        root / "worker.db",
                        profile="sample",
                        workspace="example-workspace",
                    ),
                    inbox / "ingress.db",
                    execute,
                    lambda *_args: None,
                    prepare=prepare,
                )
                for _ in range(10):
                    await runtime.run_once()
                    if order == ["prepare", "execute"]:
                        break
                    await asyncio.sleep(0)

                self.assertEqual(order, ["prepare", "execute"])
                for _ in range(10):
                    await runtime.run_once()
                    if worker.delivery_state("delivery-1") == "completed":
                        break
                    await asyncio.sleep(0)
                self.assertEqual(worker.delivery_state("delivery-1"), "completed")

        asyncio.run(scenario())

    def test_queued_acknowledgement_is_sent_before_session_preparation_finishes(self) -> None:
        async def scenario():
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                inbox = root / "inbox"
                ingress = IngressStore(inbox / "ingress.db")
                route = Route(
                    "sample",
                    "sample",
                    "/webhook/sample/linear",
                    root / "unused.env",
                    inbox,
                )
                ingress.enqueue(route, "delivery-1", json.dumps({
                    "type": "AgentSessionEvent",
                    "action": "created",
                    "agentSession": {
                        "id": "session-1",
                        "issue": {"id": "issue-1"},
                    },
                    "promptContext": "work",
                }).encode())
                activities: list[tuple[str, str, str]] = []
                prepare_started = asyncio.Event()
                release_prepare = asyncio.Event()

                async def prepare(_session_key):
                    prepare_started.set()
                    await release_prepare.wait()

                runtime = ProfileLinearRuntime(
                    LinearWorker(
                        root / "worker.db",
                        profile="sample",
                        workspace="example-workspace",
                    ),
                    inbox / "ingress.db",
                    lambda _key, _prompt: asyncio.sleep(0, result="Finished"),
                    lambda target, operation, body: activities.append(
                        (target, operation, body)
                    ),
                    prepare=prepare,
                )
                running = asyncio.create_task(runtime.run_once())
                await asyncio.wait_for(prepare_started.wait(), timeout=1)
                self.assertEqual(
                    activities[0],
                    ("session-1", "thought", "Queued for execution."),
                )
                release_prepare.set()
                await running
                await runtime.shutdown()

        asyncio.run(scenario())

    def test_execution_does_not_start_when_active_status_is_not_confirmed(self) -> None:
        async def scenario():
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                inbox = root / "inbox"
                ingress = IngressStore(inbox / "ingress.db")
                route = Route(
                    "sample",
                    "sample",
                    "/webhook/sample/linear",
                    root / "unused.env",
                    inbox,
                )
                ingress.enqueue(route, "delivery-1", json.dumps({
                    "type": "AgentSessionEvent",
                    "action": "created",
                    "agentSession": {
                        "id": "session-1",
                        "issue": {"id": "issue-1"},
                    },
                    "promptContext": "work",
                }).encode())
                executions: list[str] = []

                async def execute(_key, _prompt):
                    executions.append("started")
                    return "Finished"

                def emit(_target, operation, body):
                    if operation == "issue_status" and body == "active":
                        raise TimeoutError("uncertain status update")

                runtime = ProfileLinearRuntime(
                    LinearWorker(
                        root / "worker.db",
                        profile="sample",
                        workspace="example-workspace",
                    ),
                    inbox / "ingress.db",
                    execute,
                    emit,
                    prepare=lambda _key: asyncio.sleep(0),
                )
                self.assertTrue(await runtime.run_once())
                await asyncio.sleep(0)
                self.assertEqual(executions, [])
                await runtime.shutdown()

        asyncio.run(scenario())

    def test_terminal_issue_status_suppression_cancels_queued_execution(self) -> None:
        async def scenario():
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                inbox = root / "inbox"
                ingress = IngressStore(inbox / "ingress.db")
                route = Route(
                    "sample",
                    "sample",
                    "/webhook/sample/linear",
                    root / "unused.env",
                    inbox,
                )
                ingress.enqueue(route, "delivery-1", json.dumps({
                    "type": "AgentSessionEvent",
                    "action": "created",
                    "agentSession": {
                        "id": "session-1",
                        "issue": {"id": "issue-1"},
                    },
                    "promptContext": "work",
                }).encode())
                executions: list[str] = []

                async def execute(_key, _prompt):
                    executions.append("started")
                    return "Finished"

                def emit(_target, operation, _body):
                    return operation != "issue_status"

                worker = LinearWorker(
                    root / "worker.db",
                    profile="sample",
                    workspace="example-workspace",
                )
                runtime = ProfileLinearRuntime(
                    worker,
                    inbox / "ingress.db",
                    execute,
                    emit,
                    prepare=lambda _key: asyncio.sleep(0),
                )
                self.assertTrue(await runtime.run_once())
                await asyncio.sleep(0)
                self.assertEqual(executions, [])
                self.assertEqual(worker.delivery_state("delivery-1"), "canceled")
                await runtime.shutdown()

        asyncio.run(scenario())

    def test_graceful_shutdown_marks_active_issue_failed_and_comments(self) -> None:
        async def scenario():
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                inbox = root / "inbox"
                ingress = IngressStore(inbox / "ingress.db")
                route = Route(
                    "sample",
                    "sample",
                    "/webhook/sample/linear",
                    root / "unused.env",
                    inbox,
                )
                ingress.enqueue(route, "delivery-1", json.dumps({
                    "type": "AgentSessionEvent",
                    "action": "created",
                    "agentSession": {
                        "id": "session-1",
                        "issue": {"id": "issue-1"},
                    },
                    "promptContext": "work",
                }).encode())
                execution_started = asyncio.Event()
                activities: list[tuple[str, str, str]] = []

                async def execute(_key, _prompt):
                    execution_started.set()
                    await asyncio.Event().wait()
                    return "unreachable"

                worker = LinearWorker(
                    root / "worker.db",
                    profile="sample",
                    workspace="example-workspace",
                )
                runtime = ProfileLinearRuntime(
                    worker,
                    inbox / "ingress.db",
                    execute,
                    lambda target, operation, body: activities.append(
                        (target, operation, body)
                    ),
                    prepare=lambda _key: asyncio.sleep(0),
                )
                await runtime.run_once()
                await asyncio.wait_for(execution_started.wait(), timeout=1)
                await runtime.shutdown()

                self.assertEqual(worker.delivery_state("delivery-1"), "completed")
                self.assertIn(
                    ("issue-1", "issue_status", "failure"),
                    activities,
                )
                self.assertEqual(
                    sum(operation == "issue_comment" for _, operation, _ in activities),
                    1,
                )

        asyncio.run(scenario())

    def test_created_delivery_emits_thought_runs_profile_session_and_emits_response(self) -> None:
        async def scenario():
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                inbox = root / "inbox"
                ingress = IngressStore(inbox / "ingress.db")
                route = Route("sample", "sample", "/webhook/sample/linear", root / "unused.env", inbox)
                ingress.enqueue(route, "delivery-1", json.dumps({
                    "type": "AgentSessionEvent",
                    "action": "created",
                    "agentSession": {
                        "id": "session-1",
                        "issue": {"id": "issue-1", "teamId": "team-1"},
                    },
                    "promptContext": "untrusted context",
                }).encode())
                calls, activities = [], []

                async def execute(session_key, prompt):
                    calls.append((session_key, prompt))
                    return "Finished"

                def emit(session_id, activity_type, body):
                    activities.append((session_id, activity_type, body))

                runtime = ProfileLinearRuntime(
                    LinearWorker(root / "worker.db", profile="sample", workspace="example-workspace"),
                    inbox / "ingress.db", execute, emit,
                )
                self.assertTrue(await runtime.run_once())
                for _ in range(10):
                    if len(activities) >= 6:
                        break
                    await runtime.run_once()
                    await asyncio.sleep(0)
                self.assertEqual(calls, [("linear:example-workspace:session-1", "untrusted context")])
                self.assertEqual(activities, [
                    ("session-1", "thought", "Queued for execution."),
                    ("issue-1", "issue_status", "waiting"),
                    ("issue-1", "issue_status", "active"),
                    ("session-1", "response", "Finished"),
                    (
                        "issue-1",
                        "issue_comment",
                        "### Agent session summary\n\nFinished",
                    ),
                    ("issue-1", "issue_status", "done"),
                ])
                while await runtime.run_once():
                    await asyncio.sleep(0)

        asyncio.run(scenario())

    def test_unrelated_comment_webhook_does_not_block_agent_session(self) -> None:
        async def scenario():
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                inbox = root / "inbox"
                ingress = IngressStore(inbox / "ingress.db")
                route = Route("sample", "sample", "/webhook/sample/linear", root / "unused.env", inbox)
                ingress.enqueue(route, "comment-delivery", json.dumps({
                    "type": "Comment",
                    "action": "create",
                    "data": {"id": "comment-1", "body": "@sample hello"},
                }).encode())
                ingress.enqueue(route, "session-delivery", json.dumps({
                    "type": "AgentSessionEvent",
                    "action": "created",
                    "agentSession": {"id": "session-1"},
                    "promptContext": "hello",
                }).encode())
                calls, activities = [], []

                async def execute(session_key, prompt):
                    calls.append((session_key, prompt))
                    return "Hi"

                runtime = ProfileLinearRuntime(
                    LinearWorker(root / "worker.db", profile="sample", workspace="example-workspace"),
                    inbox / "ingress.db", execute,
                    lambda session_id, activity_type, body: activities.append((session_id, activity_type, body)),
                )

                self.assertTrue(await runtime.run_once())
                self.assertEqual(calls, [])
                self.assertEqual(activities, [])
                self.assertTrue(await runtime.run_once())
                self.assertTrue(await runtime.run_once())
                self.assertEqual(calls, [("linear:example-workspace:session-1", "hello")])
                self.assertEqual(activities, [
                    ("session-1", "thought", "Queued for execution."),
                    ("session-1", "response", "Hi"),
                ])
                while await runtime.run_once():
                    await asyncio.sleep(0)

        asyncio.run(scenario())

    def test_prompted_delivery_emits_thought_before_execution(self) -> None:
        async def scenario():
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                inbox = root / "inbox"
                ingress = IngressStore(inbox / "ingress.db")
                route = Route("sample", "sample", "/webhook/sample/linear", root / "unused.env", inbox)
                ingress.enqueue(route, "delivery-1", json.dumps({
                    "type": "AgentSessionEvent",
                    "action": "prompted",
                    "agentSession": {
                        "id": "session-1",
                        "issue": {"id": "issue-1"},
                    },
                    "agentActivity": {
                        "id": "activity-1",
                        "body": "follow up",
                    },
                }).encode())
                activities, execution_snapshots = [], []

                async def execute(_session_key, _prompt):
                    execution_snapshots.append(list(activities))
                    return "Finished"

                worker = LinearWorker(
                    root / "worker.db",
                    profile="sample",
                    workspace="example-workspace",
                )
                runtime = ProfileLinearRuntime(
                    worker,
                    inbox / "ingress.db",
                    execute,
                    lambda session_id, activity_type, body: activities.append((session_id, activity_type, body)),
                    prepare=lambda _key: asyncio.sleep(0),
                )
                for _ in range(12):
                    await runtime.run_once()
                    await asyncio.sleep(0)
                    if any(operation == "issue_comment" for _, operation, _ in activities):
                        break

                self.assertEqual(execution_snapshots, [[
                    ("session-1", "thought", "Queued for execution."),
                    ("issue-1", "issue_status", "waiting"),
                    ("issue-1", "issue_status", "active"),
                ]])
                self.assertEqual(
                    [
                        body for _, operation, body in activities
                        if operation == "issue_comment"
                    ],
                    ["### Agent session summary\n\nFinished"],
                )

        asyncio.run(scenario())

    def test_session_preparation_failure_emits_ordered_redacted_error_without_execution(self) -> None:
        async def scenario():
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                inbox = root / "inbox"
                ingress = IngressStore(inbox / "ingress.db")
                route = Route("sample", "sample", "/webhook/sample/linear", root / "unused.env", inbox)
                ingress.enqueue(route, "delivery-1", json.dumps({
                    "type": "AgentSessionEvent",
                    "action": "created",
                    "agentSession": {
                        "id": "session-1",
                        "issue": {"id": "issue-1"},
                    },
                    "promptContext": "work",
                }).encode())
                activities, executions = [], []

                async def prepare(_session_key):
                    raise RuntimeError("sensitive preparation failure")

                async def execute(*_args):
                    executions.append(True)
                    return "must not run"

                runtime = ProfileLinearRuntime(
                    LinearWorker(root / "worker.db", profile="sample", workspace="example-workspace"),
                    inbox / "ingress.db",
                    execute,
                    lambda session_id, activity_type, body: activities.append((session_id, activity_type, body)),
                    prepare=prepare,
                )
                self.assertTrue(await runtime.run_once())

                self.assertEqual(executions, [])
                self.assertEqual(activities, [
                    ("session-1", "thought", "Queued for execution."),
                    ("issue-1", "issue_status", "waiting"),
                    (
                        "session-1",
                        "response",
                        "Unable to complete this request. Please retry.",
                    ),
                    (
                        "issue-1",
                        "issue_comment",
                        (
                            "### Agent session summary\n\n"
                            "Unable to complete this request. Please retry."
                        ),
                    ),
                    ("issue-1", "issue_status", "failure"),
                ])

        asyncio.run(scenario())

    def test_execution_failure_emits_redacted_error_and_does_not_crash_runtime(self) -> None:
        async def scenario():
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                inbox = root / "inbox"
                ingress = IngressStore(inbox / "ingress.db")
                route = Route("sample", "sample", "/webhook/sample/linear", root / "unused.env", inbox)
                ingress.enqueue(route, "delivery-1", json.dumps({
                    "type": "AgentSessionEvent",
                    "action": "created",
                    "agentSession": {
                        "id": "session-1",
                        "issue": {"id": "issue-1"},
                    },
                    "promptContext": "context",
                }).encode())
                activities = []

                async def execute(_key, _prompt):
                    raise RuntimeError("sensitive failure")

                runtime = ProfileLinearRuntime(
                    LinearWorker(root / "worker.db", profile="sample", workspace="example-workspace"),
                    inbox / "ingress.db", execute,
                    lambda session_id, activity_type, body: activities.append((session_id, activity_type, body)),
                )
                self.assertTrue(await runtime.run_once())
                self.assertTrue(await runtime.run_once())
                self.assertEqual(activities, [
                    ("session-1", "thought", "Queued for execution."),
                    ("issue-1", "issue_status", "waiting"),
                    ("issue-1", "issue_status", "active"),
                    (
                        "session-1",
                        "response",
                        "Unable to complete this request. Please retry.",
                    ),
                    (
                        "issue-1",
                        "issue_comment",
                        (
                            "### Agent session summary\n\n"
                            "Unable to complete this request. Please retry."
                        ),
                    ),
                    ("issue-1", "issue_status", "failure"),
                ])

        asyncio.run(scenario())


    def test_outbound_activity_failure_is_quarantined_without_crashing_runtime(self) -> None:
        async def scenario():
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                inbox = root / "inbox"
                ingress = IngressStore(inbox / "ingress.db")
                route = Route("sample", "sample", "/webhook/sample/linear", root / "unused.env", inbox)
                ingress.enqueue(route, "delivery-1", json.dumps({"type": "AgentSessionEvent", "action": "created", "agentSession": {"id": "session-1"}, "promptContext": "work"}).encode())
                runtime = ProfileLinearRuntime(
                    LinearWorker(root / "worker.db", profile="sample", workspace="example-workspace"),
                    inbox / "ingress.db", lambda _key, _prompt: asyncio.sleep(0, result="Finished"),
                    lambda *_: (_ for _ in ()).throw(RuntimeError("network unavailable")),
                )
                self.assertTrue(await runtime.run_once())
                self.assertFalse(await runtime.run_once())

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
