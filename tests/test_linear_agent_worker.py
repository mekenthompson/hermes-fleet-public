"""Durable worker tests for the profile-local Linear adapter."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "plugins" / "linear-agent"))
from linear_agent import LinearWorker


ALLOWED_USER_ID = "11111111-1111-4111-8111-111111111111"
DENIED_USER_ID = "22222222-2222-4222-8222-222222222222"
UPPERCASE_USER_ID = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"


class LinearAgentWorkerTests(unittest.TestCase):
    def test_one_delivery_creates_one_profile_namespaced_session_and_outbox(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            worker = LinearWorker(Path(temp) / "worker.db", profile="sample", workspace="example-workspace")
            worker.add_delivery("delivery-1", json.dumps({"data": {"agentSession": {"id": "linear-session-1"}, "prompt": "Inspect this issue"}}).encode())
            calls: list[tuple[str, str]] = []
            self.assertTrue(worker.process_once(lambda key, prompt: calls.append((key, prompt)) or "Done"))
            self.assertFalse(worker.process_once(lambda *_: "ignored"))
            self.assertEqual(calls, [("linear:example-workspace:linear-session-1", "Inspect this issue")])
            self.assertEqual(worker.outbox(), [("response", "linear-session-1", "Done")])

    def test_duplicate_created_event_with_new_delivery_id_executes_once(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            worker = LinearWorker(Path(temp) / "worker.db", profile="sample", workspace="example-workspace")
            payload = json.dumps({
                "type": "AgentSessionEvent",
                "action": "created",
                "agentSession": {"id": "linear-session-1"},
                "promptContext": "Inspect this issue",
            }).encode()
            worker.add_delivery("delivery-1", payload)
            worker.add_delivery("delivery-2", payload)
            calls: list[tuple[str, str]] = []

            while worker.process_once(lambda key, prompt: calls.append((key, prompt)) or "Done"):
                pass

            self.assertEqual(calls, [("linear:example-workspace:linear-session-1", "Inspect this issue")])
            self.assertEqual(worker.outbox(), [
                ("response", "linear-session-1", "Done"),
                ("thought", "linear-session-1", "Working on this now."),
            ])

    def test_top_level_linear_created_payload_uses_prompt_context(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            worker = LinearWorker(Path(temp) / "worker.db", profile="sample", workspace="example-workspace")
            worker.add_delivery("delivery-1", json.dumps({"type": "AgentSessionEvent", "action": "created", "agentSession": {"id": "linear-session-1"}, "promptContext": "untrusted Linear context"}).encode())
            calls: list[tuple[str, str]] = []
            self.assertTrue(worker.process_once(lambda key, prompt: calls.append((key, prompt)) or "Done"))
            self.assertEqual(calls, [("linear:example-workspace:linear-session-1", "untrusted Linear context")])

    def test_allowlisted_creator_executes_created_event(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            worker = LinearWorker(
                Path(temp) / "worker.db",
                profile="sample",
                workspace="example-workspace",
                allowed_linear_user_ids=[ALLOWED_USER_ID],
            )
            worker.add_delivery("delivery-1", json.dumps({
                "type": "AgentSessionEvent",
                "action": "created",
                "agentSession": {
                    "id": "linear-session-1",
                    "creatorId": ALLOWED_USER_ID,
                    "creator": {"id": ALLOWED_USER_ID},
                },
                "promptContext": "untrusted Linear context",
            }).encode())
            calls: list[tuple[str, str]] = []

            self.assertTrue(worker.process_once(
                lambda key, prompt: calls.append((key, prompt)) or "Done"
            ))

            self.assertEqual(
                calls,
                [("linear:example-workspace:linear-session-1", "untrusted Linear context")],
            )
            self.assertEqual(worker.delivery_state("delivery-1"), "completed")

    def test_unauthorized_creator_is_rejected_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            worker = LinearWorker(
                Path(temp) / "worker.db",
                profile="sample",
                workspace="example-workspace",
                allowed_linear_user_ids=[ALLOWED_USER_ID],
            )
            worker.add_delivery("delivery-1", json.dumps({
                "type": "AgentSessionEvent",
                "action": "created",
                "agentSession": {
                    "id": "linear-session-1",
                    "creatorId": DENIED_USER_ID,
                    "creator": {"id": DENIED_USER_ID},
                },
                "promptContext": "must not execute",
            }).encode())
            calls: list[tuple[str, str]] = []

            self.assertTrue(worker.process_once(
                lambda key, prompt: calls.append((key, prompt)) or "must not execute"
            ))

            self.assertEqual(calls, [])
            self.assertEqual(worker.delivery_state("delivery-1"), "rejected")
            self.assertEqual(
                worker.delivery_rejection("delivery-1"),
                (DENIED_USER_ID, "linear_user_not_allowed"),
            )
            self.assertEqual(worker.outbox(), [
                (
                    "response",
                    "linear-session-1",
                    "This agent is restricted to approved workspace users.",
                ),
            ])

    def test_unauthorized_prompted_follow_up_is_rejected_independently(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            worker = LinearWorker(
                Path(temp) / "worker.db",
                profile="sample",
                workspace="example-workspace",
                allowed_linear_user_ids=[ALLOWED_USER_ID],
            )
            worker.add_delivery("delivery-created", json.dumps({
                "type": "AgentSessionEvent",
                "action": "created",
                "agentSession": {
                    "id": "linear-session-1",
                    "creatorId": ALLOWED_USER_ID,
                },
                "promptContext": "allowed creation",
            }).encode())
            calls: list[str] = []
            self.assertTrue(worker.process_once(lambda _key, prompt: calls.append(prompt) or "Done"))
            worker.add_delivery("delivery-prompted", json.dumps({
                "type": "AgentSessionEvent",
                "action": "prompted",
                "agentSession": {"id": "linear-session-1"},
                "agentActivity": {
                    "id": "activity-1",
                    "userId": DENIED_USER_ID,
                    "user": {"id": DENIED_USER_ID},
                    "body": "must not execute",
                },
            }).encode())

            self.assertTrue(worker.process_once(lambda _key, prompt: calls.append(prompt) or "Done"))

            self.assertEqual(calls, ["allowed creation"])
            self.assertEqual(worker.delivery_state("delivery-prompted"), "rejected")
            self.assertEqual(
                worker.delivery_rejection("delivery-prompted"),
                (DENIED_USER_ID, "linear_user_not_allowed"),
            )

    def test_allowlist_rejects_missing_and_conflicting_creator_identity(self) -> None:
        cases = {
            "missing": ({}, (None, "linear_user_identity_missing")),
            "nested_only": (
                {"creator": {"id": ALLOWED_USER_ID}},
                (None, "linear_user_identity_missing"),
            ),
            "conflicting": (
                {
                    "creatorId": ALLOWED_USER_ID,
                    "creator": {"id": DENIED_USER_ID},
                },
                (ALLOWED_USER_ID, "linear_user_identity_conflict"),
            ),
        }
        for name, (identity, expected) in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                worker = LinearWorker(
                    Path(temp) / "worker.db",
                    profile="sample",
                    workspace="example-workspace",
                    allowed_linear_user_ids=[ALLOWED_USER_ID],
                )
                worker.add_delivery("delivery-1", json.dumps({
                    "type": "AgentSessionEvent",
                    "action": "created",
                    "agentSession": {"id": "linear-session-1", **identity},
                    "promptContext": "must not execute",
                }).encode())
                calls: list[str] = []

                self.assertTrue(worker.process_once(
                    lambda _key, prompt: calls.append(prompt) or "must not execute"
                ))

                self.assertEqual(calls, [])
                self.assertEqual(worker.delivery_rejection("delivery-1"), expected)

    def test_allowlist_rejects_prompted_event_without_primary_user_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            worker = LinearWorker(
                Path(temp) / "worker.db",
                profile="sample",
                workspace="example-workspace",
                allowed_linear_user_ids=[ALLOWED_USER_ID],
            )
            worker.add_delivery("delivery-1", json.dumps({
                "type": "AgentSessionEvent",
                "action": "prompted",
                "agentSession": {"id": "linear-session-1"},
                "agentActivity": {
                    "id": "activity-1",
                    "user": {"id": ALLOWED_USER_ID},
                    "body": "must not execute",
                },
            }).encode())
            calls: list[str] = []

            self.assertTrue(worker.process_once(
                lambda _key, prompt: calls.append(prompt) or "must not execute"
            ))

            self.assertEqual(calls, [])
            self.assertEqual(
                worker.delivery_rejection("delivery-1"),
                (None, "linear_user_identity_missing"),
            )

    def test_duplicate_denied_event_emits_one_response(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            worker = LinearWorker(
                Path(temp) / "worker.db",
                profile="sample",
                workspace="example-workspace",
                allowed_linear_user_ids=[ALLOWED_USER_ID],
            )
            payload = json.dumps({
                "type": "AgentSessionEvent",
                "action": "prompted",
                "agentSession": {"id": "linear-session-1"},
                "agentActivity": {
                    "id": "activity-1",
                    "userId": DENIED_USER_ID,
                    "body": "must not execute",
                },
            }).encode()
            worker.add_delivery("delivery-1", payload)
            worker.add_delivery("delivery-2", payload)

            self.assertTrue(worker.process_once(lambda *_args: "must not execute"))
            self.assertTrue(worker.process_once(lambda *_args: "must not execute"))

            denial_responses = [item for item in worker.outbox() if item[2] == (
                "This agent is restricted to approved workspace users."
            )]
            self.assertEqual(len(denial_responses), 1)
            self.assertEqual(worker.delivery_state("delivery-2"), "rejected")

    def test_allowlist_configuration_must_be_non_empty_unique_uuids(self) -> None:
        invalid_policies = (
            [],
            ["not-a-linear-user-id"],
            [UPPERCASE_USER_ID],
            [ALLOWED_USER_ID, ALLOWED_USER_ID],
        )
        for policy in invalid_policies:
            with self.subTest(policy=policy), tempfile.TemporaryDirectory() as temp:
                with self.assertRaisesRegex(ValueError, "allowed_linear_user_ids"):
                    LinearWorker(
                        Path(temp) / "worker.db",
                        profile="sample",
                        workspace="example-workspace",
                        allowed_linear_user_ids=policy,
                    )

    def test_allowlist_rejects_legacy_event_without_requester_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            worker = LinearWorker(
                Path(temp) / "worker.db",
                profile="sample",
                workspace="example-workspace",
                allowed_linear_user_ids=[ALLOWED_USER_ID],
            )
            worker.add_delivery("delivery-1", json.dumps({
                "data": {
                    "agentSession": {"id": "linear-session-1"},
                    "prompt": "must not execute",
                },
            }).encode())
            calls: list[str] = []

            self.assertTrue(worker.process_once(
                lambda _key, prompt: calls.append(prompt) or "must not execute"
            ))

            self.assertEqual(calls, [])
            self.assertEqual(worker.delivery_state("delivery-1"), "rejected")
            self.assertEqual(
                worker.delivery_rejection("delivery-1"),
                (None, "linear_user_identity_missing"),
            )

    def test_duplicate_prompted_activity_with_new_delivery_id_executes_once(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            worker = LinearWorker(Path(temp) / "worker.db", profile="sample", workspace="example-workspace")
            payload = json.dumps({
                "type": "AgentSessionEvent",
                "action": "prompted",
                "agentSession": {"id": "linear-session-1"},
                "agentActivity": {
                    "id": "activity-1",
                    "content": {"type": "prompt", "body": "@sample please look"},
                },
            }).encode()
            worker.add_delivery("delivery-1", payload)
            worker.add_delivery("delivery-2", payload)
            calls: list[tuple[str, str]] = []

            while worker.process_once(lambda key, prompt: calls.append((key, prompt)) or "Done"):
                pass

            self.assertEqual(calls, [("linear:example-workspace:linear-session-1", "@sample please look")])
            self.assertEqual(worker.outbox(), [("response", "linear-session-1", "Done")])

    def test_distinct_prompted_activities_in_one_session_both_execute(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            worker = LinearWorker(Path(temp) / "worker.db", profile="sample", workspace="example-workspace")
            for delivery_id, activity_id, prompt in (
                ("delivery-1", "activity-1", "first follow-up"),
                ("delivery-2", "activity-2", "second follow-up"),
            ):
                worker.add_delivery(delivery_id, json.dumps({
                    "type": "AgentSessionEvent",
                    "action": "prompted",
                    "agentSession": {"id": "linear-session-1"},
                    "agentActivity": {
                        "id": activity_id,
                        "content": {"type": "prompt", "body": prompt},
                    },
                }).encode())
            calls: list[tuple[str, str]] = []

            while worker.process_once(lambda key, prompt: calls.append((key, prompt)) or "Done"):
                pass

            self.assertEqual(calls, [
                ("linear:example-workspace:linear-session-1", "first follow-up"),
                ("linear:example-workspace:linear-session-1", "second follow-up"),
            ])

    def test_prompted_event_without_activity_id_is_quarantined_without_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            worker = LinearWorker(Path(temp) / "worker.db", profile="sample", workspace="example-workspace")
            worker.add_delivery("delivery-1", json.dumps({
                "type": "AgentSessionEvent",
                "action": "prompted",
                "agentSession": {"id": "linear-session-1"},
                "agentActivity": {"content": {"type": "prompt", "body": "@sample please look"}},
            }).encode())
            calls: list[tuple[str, str]] = []
            self.assertTrue(worker.process_once(lambda key, prompt: calls.append((key, prompt)) or "Done"))
            self.assertEqual(calls, [])
            self.assertEqual(worker.delivery_state("delivery-1"), "rejected")
            self.assertEqual(worker.outbox(), [])

    def test_created_event_falls_back_to_session_comment_body(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            worker = LinearWorker(Path(temp) / "worker.db", profile="sample", workspace="example-workspace")
            worker.add_delivery("delivery-1", json.dumps({
                "type": "AgentSessionEvent",
                "action": "created",
                "agentSession": {"id": "linear-session-1", "comment": {"body": "@sample you working?"}},
            }).encode())
            calls: list[tuple[str, str]] = []
            self.assertTrue(worker.process_once(lambda key, prompt: calls.append((key, prompt)) or "Yes"))
            self.assertEqual(calls, [("linear:example-workspace:linear-session-1", "@sample you working?")])

    def test_same_linear_session_reuses_hermes_session_key_for_follow_up(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            worker = LinearWorker(Path(temp) / "worker.db", profile="sample", workspace="example-workspace")
            for delivery, prompt in (("delivery-1", "first"), ("delivery-2", "follow up")):
                worker.add_delivery(delivery, json.dumps({"data": {"agentSession": {"id": "linear-session-1"}, "prompt": prompt}}).encode())
            calls: list[str] = []
            while worker.process_once(lambda key, prompt: calls.append(key) or prompt):
                pass
            self.assertEqual(calls, ["linear:example-workspace:linear-session-1", "linear:example-workspace:linear-session-1"])

    def test_outbox_marks_uncertain_network_activity_ambiguous_without_repost(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            worker = LinearWorker(Path(temp) / "worker.db", profile="sample", workspace="example-workspace")
            worker.add_delivery("delivery-1", json.dumps({"data": {"agentSession": {"id": "linear-session-1"}, "prompt": "work"}}).encode())
            worker.process_once(lambda *_: "Done")
            attempts: list[str] = []
            with self.assertRaises(RuntimeError):
                worker.dispatch_outbox(lambda *_: attempts.append("send") or (_ for _ in ()).throw(RuntimeError("timeout")))
            self.assertEqual(attempts, ["send"])
            self.assertFalse(worker.dispatch_outbox(lambda *_: attempts.append("duplicate")))
            self.assertEqual(worker.outbox_state(), ["ambiguous"])


    def test_allowlist_rejects_queued_and_prepared_jobs_during_recovery(self) -> None:
        for initial_state in ("queued", "prepared"):
            with self.subTest(initial_state=initial_state), tempfile.TemporaryDirectory() as temp:
                database = Path(temp) / "worker.db"
                unrestricted = LinearWorker(
                    database,
                    profile="sample",
                    workspace="example-workspace",
                )
                unrestricted.add_delivery("delivery-1", json.dumps({
                    "type": "AgentSessionEvent",
                    "action": "created",
                    "agentSession": {
                        "id": "linear-session-1",
                        "creatorId": DENIED_USER_ID,
                    },
                    "promptContext": "must not execute",
                }).encode())
                admitted, _job = unrestricted.admit_once()
                self.assertTrue(admitted)
                if initial_state == "prepared":
                    queued = unrestricted.next_unprepared()
                    assert queued is not None
                    unrestricted.mark_prepared(queued)

                restricted = LinearWorker(
                    database,
                    profile="sample",
                    workspace="example-workspace",
                    allowed_linear_user_ids=[ALLOWED_USER_ID],
                )
                recovered = (
                    restricted.next_unprepared()
                    if initial_state == "queued"
                    else restricted.claim_prepared()
                )

                self.assertIsNone(recovered)
                self.assertEqual(restricted.delivery_state("delivery-1"), "rejected")
                self.assertEqual(
                    restricted.delivery_rejection("delivery-1"),
                    (DENIED_USER_ID, "linear_user_not_allowed"),
                )
                denials = [
                    item for item in restricted.outbox()
                    if item[2] == "This agent is restricted to approved workspace users."
                ]
                self.assertEqual(len(denials), 1)

    def test_restart_retries_status_update_left_sending(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "worker.db"
            worker = LinearWorker(
                database,
                profile="sample",
                workspace="example-workspace",
            )
            worker.add_delivery("delivery-1", json.dumps({
                "type": "AgentSessionEvent",
                "action": "created",
                "agentSession": {
                    "id": "linear-session-1",
                    "issue": {"id": "issue-1"},
                },
                "promptContext": "work",
            }).encode())
            worker.admit_once()
            job = worker.next_unprepared()
            assert job is not None
            worker.mark_prepared(job)
            running = worker.claim_prepared()
            assert running is not None
            worker.complete_job(running, "Finished")
            with worker._connect() as conn:
                conn.execute("UPDATE outbox SET state = 'sent'")
                conn.execute(
                    "UPDATE outbox SET state = 'sending' "
                    "WHERE kind = 'issue_status_done'"
                )

            recovered = LinearWorker(
                database,
                profile="sample",
                workspace="example-workspace",
            )
            emitted: list[tuple[str, str, str]] = []
            self.assertTrue(recovered.dispatch_outbox(
                lambda target, operation, body: emitted.append(
                    (target, operation, body)
                )
            ))
            self.assertEqual(
                emitted,
                [("issue-1", "issue_status", "done")],
            )

    def test_created_event_queues_thought_before_response(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            worker = LinearWorker(Path(temp) / "worker.db", profile="sample", workspace="example-workspace")
            worker.add_delivery("delivery-1", json.dumps({"type": "AgentSessionEvent", "action": "created", "agentSession": {"id": "linear-session-1"}, "promptContext": "work"}).encode())
            sent = []

            def before_execute():
                while worker.dispatch_outbox(lambda session, kind, body: sent.append((kind, session, body))):
                    pass

            worker.process_once(lambda *_: "Done", before_execute=before_execute)
            while worker.dispatch_outbox(lambda session, kind, body: sent.append((kind, session, body))):
                pass

            self.assertEqual([item[0] for item in sent], ["thought", "response"])
            self.assertEqual(sent[0][2], "Working on this now.")
            self.assertEqual(sent[1][2], "Done")


    def test_imports_only_its_profile_delivery_from_ingress(self) -> None:
        from tests.linear_ingress_fixture import IngressStore, Route
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            inbox = root / "inbox"
            ingress = IngressStore(inbox / "ingress.db")
            route = Route("sample", "sample", "/webhook/sample/linear", root / "unused.env", inbox)
            payload = json.dumps({"type": "AgentSessionEvent", "action": "created", "agentSession": {"id": "linear-session-1"}, "promptContext": "work"}).encode()
            ingress.enqueue(route, "delivery-1", payload)
            worker = LinearWorker(root / "worker.db", profile="sample", workspace="example-workspace")

            self.assertTrue(worker.import_from_ingress_once(inbox / "ingress.db"))
            seen = []
            self.assertTrue(worker.process_once(lambda key, prompt: seen.append((key, prompt)) or "Done"))
            self.assertEqual(seen, [("linear:example-workspace:linear-session-1", "work")])
            self.assertFalse(worker.import_from_ingress_once(inbox / "ingress.db"))


    def test_execution_failure_queues_a_redacted_error_activity(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            worker = LinearWorker(Path(temp) / "worker.db", profile="sample", workspace="example-workspace")
            worker.add_delivery("delivery-1", json.dumps({"type": "AgentSessionEvent", "action": "created", "agentSession": {"id": "linear-session-1"}, "promptContext": "work"}).encode())
            emitted = []

            def flush():
                while worker.dispatch_outbox(lambda session, kind, body: emitted.append((kind, body))):
                    pass

            self.assertTrue(worker.process_once(
                lambda *_: (_ for _ in ()).throw(RuntimeError("token=do-not-leak")),
                before_execute=flush,
                on_error=flush,
            ))
            self.assertEqual(emitted, [("thought", "Working on this now."), ("response", "Unable to complete this request. Please retry.")])
            self.assertFalse(worker.process_once(lambda *_: "duplicate"))


    def test_restart_preserves_admitted_job_for_fifo_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "worker.db"
            payload = json.dumps({
                "type": "AgentSessionEvent",
                "action": "created",
                "agentSession": {"id": "linear-session-1"},
                "promptContext": "work",
            }).encode()
            worker = LinearWorker(database, profile="sample", workspace="example-workspace")
            worker.add_delivery("delivery-1", payload)

            admitted, job = worker.admit_once()
            self.assertTrue(admitted)
            self.assertIsNotNone(job)
            self.assertEqual(worker.delivery_state("delivery-1"), "queued")

            recovered = LinearWorker(database, profile="sample", workspace="example-workspace")
            queued = recovered.next_unprepared()
            self.assertIsNotNone(queued)
            self.assertEqual(queued.prompt, "work")
            recovered.mark_prepared(queued)
            queued = recovered.claim_prepared()
            self.assertIsNotNone(queued)
            recovered.complete_job(queued, "Done")
            self.assertEqual(recovered.delivery_state("delivery-1"), "completed")

    def test_restart_quarantines_activity_left_sending(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "worker.db"
            worker = LinearWorker(database, profile="sample", workspace="example-workspace")
            worker.add_delivery("delivery-1", json.dumps({"data": {"agentSession": {"id": "linear-session-1"}, "prompt": "work"}}).encode())
            worker.process_once(lambda *_: "Done")
            with worker._connect() as conn:
                conn.execute("UPDATE outbox SET state = 'sending'")
            recovered = LinearWorker(database, profile="sample", workspace="example-workspace")
            self.assertEqual(recovered.outbox_state(), ["ambiguous"])


    def test_import_marks_selected_logical_agent_when_name_differs_from_profile(self) -> None:
        from tests.linear_ingress_fixture import IngressStore, Route
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            inbox = root / "inbox"
            ingress = IngressStore(inbox / "ingress.db")
            route = Route("alternate-agent", "sample", "/webhook/sample/linear", root / "unused.env", inbox)
            ingress.enqueue(route, "delivery-1", json.dumps({"data": {"agentSession": {"id": "linear-session-1"}, "prompt": "work"}}).encode())
            worker = LinearWorker(root / "worker.db", profile="sample", workspace="example-workspace")
            self.assertTrue(worker.import_from_ingress_once(inbox / "ingress.db"))
            self.assertFalse(worker.import_from_ingress_once(inbox / "ingress.db"))


    def test_restart_quarantines_running_delivery_and_queues_terminal_response(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "worker.db"
            worker = LinearWorker(database, profile="sample", workspace="example-workspace")
            worker.add_delivery("delivery-1", json.dumps({"type": "AgentSessionEvent", "action": "created", "agentSession": {"id": "linear-session-1"}, "promptContext": "work"}).encode())
            self.assertIsNotNone(worker._claim_one())
            recovered = LinearWorker(database, profile="sample", workspace="example-workspace")
            self.assertEqual(recovered.outbox(), [("response", "linear-session-1", "The agent was interrupted before its status could be confirmed. Please retry this request.")])
            self.assertFalse(recovered.process_once(lambda *_: "must not rerun"))

    def test_malformed_json_is_quarantined_without_infinite_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            worker = LinearWorker(Path(temp) / "worker.db", profile="sample", workspace="example-workspace")
            worker.add_delivery("delivery-bad", b"{not-json")

            self.assertTrue(worker.process_once(lambda *_: "must not execute"))
            self.assertFalse(worker.process_once(lambda *_: "must not retry"))
            self.assertEqual(worker.delivery_state("delivery-bad"), "rejected")

    def test_malformed_agent_session_event_without_session_is_quarantined(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            worker = LinearWorker(Path(temp) / "worker.db", profile="sample", workspace="example-workspace")
            worker.add_delivery("delivery-bad", json.dumps({
                "type": "AgentSessionEvent",
                "action": "created",
                "promptContext": "work",
            }).encode())

            self.assertTrue(worker.process_once(lambda *_: "must not execute"))
            self.assertFalse(worker.process_once(lambda *_: "must not retry"))
            self.assertEqual(worker.delivery_state("delivery-bad"), "rejected")

    def test_legacy_event_with_session_but_no_prompt_gets_terminal_response(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            worker = LinearWorker(Path(temp) / "worker.db", profile="sample", workspace="example-workspace")
            worker.add_delivery("delivery-bad", json.dumps({
                "data": {"agentSession": {"id": "linear-session-1"}}
            }).encode())
            calls = []

            self.assertTrue(worker.process_once(lambda *_: calls.append("execute") or "must not execute"))
            self.assertEqual(calls, [])
            self.assertEqual(worker.outbox(), [
                ("response", "linear-session-1", "Unable to process this Linear event. Please retry your request."),
            ])
            self.assertFalse(worker.process_once(lambda *_: "must not retry"))
    def test_queued_follow_up_does_not_move_an_actively_running_issue_back_to_todo(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            worker = LinearWorker(
                Path(temp) / "worker.db",
                profile="sample",
                workspace="example-workspace",
            )
            first = json.dumps({
                "type": "AgentSessionEvent",
                "action": "created",
                "agentSession": {
                    "id": "linear-session-1",
                    "issue": {"id": "issue-1"},
                },
                "promptContext": "first turn",
            }).encode()
            follow_up = json.dumps({
                "type": "AgentSessionEvent",
                "action": "prompted",
                "agentSession": {
                    "id": "linear-session-1",
                    "issue": {"id": "issue-1"},
                },
                "agentActivity": {
                    "id": "activity-2",
                    "body": "second turn",
                },
            }).encode()

            worker.add_delivery("delivery-1", first)
            self.assertTrue(worker.admit_once()[0])
            first_job = worker.next_unprepared()
            assert first_job is not None
            worker.mark_prepared(first_job)
            self.assertIsNotNone(worker.claim_prepared())

            worker.add_delivery("delivery-2", follow_up)
            self.assertTrue(worker.admit_once()[0])
            emitted: list[tuple[str, str, str]] = []
            while worker.dispatch_outbox(
                lambda target, operation, body: emitted.append(
                    (target, operation, body)
                )
            ):
                pass

            self.assertEqual(
                [body for _, operation, body in emitted if operation == "issue_status"],
                ["waiting", "active"],
            )
    def test_finishing_a_turn_leaves_issue_in_todo_when_a_follow_up_is_queued(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            worker = LinearWorker(
                Path(temp) / "worker.db",
                profile="sample",
                workspace="example-workspace",
            )
            first = json.dumps({
                "type": "AgentSessionEvent",
                "action": "created",
                "agentSession": {
                    "id": "linear-session-1",
                    "issue": {"id": "issue-1"},
                },
                "promptContext": "first turn",
            }).encode()
            follow_up = json.dumps({
                "type": "AgentSessionEvent",
                "action": "prompted",
                "agentSession": {
                    "id": "linear-session-1",
                    "issue": {"id": "issue-1"},
                },
                "agentActivity": {
                    "id": "activity-2",
                    "body": "second turn",
                },
            }).encode()

            worker.add_delivery("delivery-1", first)
            self.assertTrue(worker.admit_once()[0])
            first_job = worker.next_unprepared()
            assert first_job is not None
            worker.mark_prepared(first_job)
            running = worker.claim_prepared()
            assert running is not None
            worker.add_delivery("delivery-2", follow_up)
            self.assertTrue(worker.admit_once()[0])

            worker.complete_job(running, "first complete")
            emitted: list[tuple[str, str, str]] = []
            while worker.dispatch_outbox(
                lambda target, operation, body: emitted.append(
                    (target, operation, body)
                )
            ):
                pass

            self.assertEqual(
                [body for _, operation, body in emitted if operation == "issue_status"],
                ["waiting", "active", "waiting"],
            )
    def test_restart_marks_interrupted_turn_failed_and_adds_summary_comment(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "worker.db"
            worker = LinearWorker(
                database,
                profile="sample",
                workspace="example-workspace",
            )
            worker.add_delivery("delivery-1", json.dumps({
                "type": "AgentSessionEvent",
                "action": "created",
                "agentSession": {
                    "id": "linear-session-1",
                    "issue": {"id": "issue-1"},
                },
                "promptContext": "work",
            }).encode())
            worker.admit_once()
            job = worker.next_unprepared()
            assert job is not None
            worker.mark_prepared(job)
            self.assertIsNotNone(worker.claim_prepared())

            recovered = LinearWorker(
                database,
                profile="sample",
                workspace="example-workspace",
            )
            self.assertEqual(recovered.delivery_state("delivery-1"), "ambiguous")
            emitted: list[tuple[str, str, str]] = []
            while recovered.dispatch_outbox(
                lambda target, operation, body: emitted.append(
                    (target, operation, body)
                )
            ):
                pass

            self.assertIn(
                (
                    "issue-1",
                    "issue_comment",
                    (
                        "### Agent session summary\n\n"
                        "The agent was interrupted before its status could be "
                        "confirmed. Please retry this request."
                    ),
                ),
                emitted,
            )
            self.assertEqual(
                [body for _, operation, body in emitted if operation == "issue_status"],
                ["waiting", "active", "failure"],
            )
    def test_summary_comment_is_redacted_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            worker = LinearWorker(
                Path(temp) / "worker.db",
                profile="sample",
                workspace="example-workspace",
            )
            job = worker._standard_job_from_payload(
                "delivery-1",
                json.dumps({
                    "type": "AgentSessionEvent",
                    "action": "created",
                    "agentSession": {
                        "id": "linear-session-1",
                        "issue": {"id": "issue-1"},
                    },
                    "promptContext": "work",
                }).encode(),
            )[0]
            worker.add_delivery("delivery-1", json.dumps({
                "type": "AgentSessionEvent",
                "action": "created",
                "agentSession": {
                    "id": "linear-session-1",
                    "issue": {"id": "issue-1"},
                },
                "promptContext": "work",
            }).encode())
            private_key_marker = "PRIVATE " + "KEY"
            fake_private_key = "\n".join((
                f"-----BEGIN {private_key_marker}-----",
                "private-material",
                f"-----END {private_key_marker}-----",
            ))
            sensitive_lines = (
                "access_token=super-secret",
                "Authorization: Basic abc123",
                "https://user:pass@example.test/x?api_key=url-secret",
                "Cookie: sessionid=cookie-secret",
                '{"apiKey": "json secret with spaces"}',
                "apiKey:",
                "  - super-secret-list-value",
                "clientSecret: yaml-secret",
                fake_private_key,
            )
            sensitive = "\n".join(sensitive_lines)
            worker.complete_job(
                job,
                sensitive + " " + ("x" * 9000),
            )
            emitted: list[tuple[str, str, str]] = []
            while worker.dispatch_outbox(
                lambda target, operation, body: emitted.append(
                    (target, operation, body)
                )
            ):
                pass

            comment = next(
                body for _, operation, body in emitted
                if operation == "issue_comment"
            )
            for secret in (
                "super-secret",
                "abc123",
                "user:pass",
                "url-secret",
                "cookie-secret",
                "json secret with spaces",
                "super-secret-list-value",
                "yaml-secret",
                "private-material",
            ):
                self.assertNotIn(secret, comment)
            self.assertIn("[REDACTED]", comment)
            self.assertLessEqual(len(comment), 8000)
            self.assertTrue(comment.endswith("…"))
    def test_duplicate_replay_does_not_repeat_issue_statuses_or_summary_comment(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            worker = LinearWorker(
                Path(temp) / "worker.db",
                profile="sample",
                workspace="example-workspace",
            )
            payload = json.dumps({
                "type": "AgentSessionEvent",
                "action": "created",
                "agentSession": {
                    "id": "linear-session-1",
                    "issue": {"id": "issue-1"},
                },
                "promptContext": "work",
            }).encode()
            worker.add_delivery("delivery-1", payload)
            worker.admit_once()
            job = worker.next_unprepared()
            assert job is not None
            worker.mark_prepared(job)
            running = worker.claim_prepared()
            assert running is not None
            worker.complete_job(running, "Finished")

            worker.add_delivery("delivery-2", payload)
            worker.admit_once()
            emitted: list[tuple[str, str, str]] = []
            while worker.dispatch_outbox(
                lambda target, operation, body: emitted.append(
                    (target, operation, body)
                )
            ):
                pass

            self.assertEqual(
                sum(operation == "issue_comment" for _, operation, _ in emitted),
                1,
            )
            self.assertEqual(
                [body for _, operation, body in emitted if operation == "issue_status"],
                ["waiting", "active", "done"],
            )
    def test_existing_worker_database_is_migrated_for_issue_lifecycle(self) -> None:
        import sqlite3

        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "worker.db"
            with closing(sqlite3.connect(database)) as conn:
                with conn:
                    conn.executescript("""
                    CREATE TABLE deliveries (
                        delivery_id TEXT PRIMARY KEY,
                        payload BLOB NOT NULL,
                        payload_sha256 TEXT NOT NULL,
                        state TEXT NOT NULL DEFAULT 'pending',
                        created_at INTEGER NOT NULL
                    );
                    CREATE TABLE outbox (
                        delivery_id TEXT NOT NULL,
                        kind TEXT NOT NULL,
                        linear_session_id TEXT NOT NULL,
                        body TEXT NOT NULL,
                        state TEXT NOT NULL DEFAULT 'pending',
                        PRIMARY KEY (delivery_id, kind)
                    );
                """)

            worker = LinearWorker(
                database,
                profile="sample",
                workspace="example-workspace",
            )
            with worker._connect() as conn:
                delivery_columns = {
                    str(row[1]) for row in conn.execute(
                        "PRAGMA table_info(deliveries)"
                    )
                }
                outbox_columns = {
                    str(row[1]) for row in conn.execute("PRAGMA table_info(outbox)")
                }
                tables = {
                    str(row[0]) for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
            self.assertIn("issue_id", delivery_columns)
            self.assertIn("requester_user_id", delivery_columns)
            self.assertIn("rejection_reason", delivery_columns)
            self.assertIn("sequence", outbox_columns)
            self.assertIn("outbox_sequence", tables)
    def test_status_update_with_uncertain_result_is_retried_safely(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            worker = LinearWorker(
                Path(temp) / "worker.db",
                profile="sample",
                workspace="example-workspace",
            )
            worker.add_delivery("delivery-1", json.dumps({
                "type": "AgentSessionEvent",
                "action": "created",
                "agentSession": {
                    "id": "linear-session-1",
                    "issue": {"id": "issue-1"},
                },
                "promptContext": "work",
            }).encode())
            worker.admit_once()
            job = worker.next_unprepared()
            assert job is not None
            worker.mark_prepared(job)
            self.assertIsNotNone(worker.claim_prepared())
            active_attempts = 0

            def emit(_target, operation, body):
                nonlocal active_attempts
                if operation == "issue_status" and body == "active":
                    active_attempts += 1
                    if active_attempts == 1:
                        raise TimeoutError("uncertain status update")

            with self.assertRaises(TimeoutError):
                while worker.dispatch_outbox(emit):
                    pass
            self.assertTrue(worker.dispatch_outbox(emit))
            self.assertEqual(active_attempts, 2)


if __name__ == "__main__":
    unittest.main()
