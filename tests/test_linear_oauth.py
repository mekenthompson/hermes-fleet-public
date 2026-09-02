"""Profile-local Linear OAuth refresh tests."""
from __future__ import annotations

import hashlib
import json
import stat
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "plugins" / "linear-agent"))

from linear_oauth import LinearOAuthToken, initialize_oauth_state, read_oauth_state


class LinearOAuthTokenTests(unittest.TestCase):
    def test_read_rejects_existing_state_under_symlinked_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            outside = root / "outside"
            outside.mkdir(mode=0o700)
            state = outside / "oauth.json"
            state.write_text("{}")
            state.chmod(0o600)
            (root / "secrets").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "symlink"):
                read_oauth_state(root / "secrets" / "oauth.json")

    def test_read_rejects_existing_state_under_exposed_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            secrets = Path(temp) / "secrets"
            secrets.mkdir(mode=0o755)
            state = secrets / "oauth.json"
            state.write_text("{}")
            state.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError, "ownership or permissions"):
                read_oauth_state(state)

    def test_state_rejects_exposed_profile_home_above_private_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            home.mkdir(mode=0o755)
            secrets = home / "secrets"
            secrets.mkdir(mode=0o700)
            state = secrets / "oauth.json"
            state.write_text("{}")
            state.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError, "ownership or permissions"):
                read_oauth_state(state)
            state.unlink()
            with self.assertRaisesRegex(RuntimeError, "ownership or permissions"):
                initialize_oauth_state(state, {"client_id": "client", "client_secret": "secret", "refresh_token": "refresh"})

    def test_concurrent_expiry_causes_one_refresh(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "linear-oauth.json"
            path.write_text(json.dumps({"access_token": "expired", "expires_at": 1, "refresh_token": "refresh", "client_id": "client", "client_secret": "secret"}), encoding="utf-8")
            path.chmod(0o600)
            calls = []
            def transport(_url, _headers, _body):
                calls.append(1); time.sleep(0.02)
                return json.dumps({"access_token": "fresh", "refresh_token": "rotated", "expires_in": 3600}).encode()
            source = LinearOAuthToken(path, now=lambda: 100, transport=transport)
            results = []
            threads = [threading.Thread(target=lambda: results.append(source())) for _ in range(5)]
            [thread.start() for thread in threads]
            [thread.join() for thread in threads]
            self.assertEqual(results, ["fresh"] * 5)
            self.assertEqual(len(calls), 1)

    def test_two_provider_instances_serialize_one_refresh(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "linear-oauth.json"
            path.write_text(json.dumps({"access_token": "expired", "expires_at": 1, "refresh_token": "refresh", "client_id": "client", "client_secret": "secret"}), encoding="utf-8")
            path.chmod(0o600)
            calls = []

            def transport(_url, _headers, _body):
                calls.append(1)
                time.sleep(0.02)
                return json.dumps({"access_token": "fresh", "refresh_token": "rotated", "expires_in": 3600}).encode()

            sources = [LinearOAuthToken(path, now=lambda: 100, transport=transport) for _ in range(2)]
            results = []
            threads = [threading.Thread(target=lambda source=source: results.append(source())) for source in sources]
            [thread.start() for thread in threads]
            [thread.join() for thread in threads]
            self.assertEqual(sorted(results), ["fresh", "fresh"])
            self.assertEqual(len(calls), 1)

    def test_lost_refresh_response_replays_same_rotation_inside_window(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "linear-oauth.json"
            path.write_text(json.dumps({"access_token": "", "expires_at": 0, "refresh_token": "refresh-old", "client_id": "client", "client_secret": "secret"}))
            path.chmod(0o600)
            calls = []
            response = json.dumps({"access_token": "access-new", "refresh_token": "refresh-new", "expires_in": 3600}).encode()
            def transport(*_args):
                calls.append(True)
                if len(calls) == 1:
                    raise TimeoutError("response lost after provider rotation")
                return response
            persisted = []
            token = LinearOAuthToken(path, now=lambda: 1000, transport=transport, refresh_sink=persisted.append)
            with self.assertRaises(TimeoutError):
                token()
            self.assertIn("refresh_intent_at", json.loads(path.read_text()))
            self.assertEqual(token(), "access-new")
            self.assertEqual(persisted, ["refresh-new"])
            committed = json.loads(path.read_text())
            self.assertEqual(committed["refresh_token"], "refresh-new")
            self.assertNotIn("refresh_intent_at", committed)

    def test_refresh_intent_is_durable_before_provider_rotation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "linear-oauth.json"
            path.write_text(json.dumps({"access_token": "expired", "expires_at": 1, "refresh_token": "refresh", "client_id": "client", "client_secret": "secret"}), encoding="utf-8")
            path.chmod(0o600)

            def transport(_url, _headers, _body):
                staged = json.loads(path.read_text())
                self.assertEqual(staged["refresh_intent_at"], 100)
                self.assertIn("refresh_intent_digest", staged)
                return json.dumps({"access_token": "fresh", "refresh_token": "rotated", "expires_in": 3600}).encode()

            self.assertEqual(LinearOAuthToken(path, now=lambda: 100, transport=transport)(), "fresh")
            self.assertNotIn("refresh_intent_at", json.loads(path.read_text()))

    def test_stale_refresh_intent_requires_reauthorization(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "linear-oauth.json"
            path.write_text(json.dumps({"access_token": "expired", "expires_at": 1, "refresh_token": "refresh", "client_id": "client", "client_secret": "secret", "refresh_intent_at": 100, "refresh_intent_digest": hashlib.sha256(b"refresh").hexdigest()}), encoding="utf-8")
            path.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError, "reauthorization"):
                LinearOAuthToken(path, now=lambda: 1901, transport=lambda *_: self.fail("must not call provider"))()

    def test_initializes_private_state_from_broker_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "secrets" / "linear-oauth.json"
            initialize_oauth_state(path, {"client_id": "client", "client_secret": "secret", "refresh_token": "refresh"})
            state = json.loads(path.read_text())
            self.assertEqual(state, {"client_id": "client", "client_secret": "secret", "refresh_token": "refresh", "access_token": "", "expires_at": 0})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_initialization_rejects_symlinked_profile_home_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            real_home = root / "real-home"
            real_home.mkdir(mode=0o700)
            linked_home = root / "linked-home"
            linked_home.symlink_to(real_home, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "symlink"):
                initialize_oauth_state(linked_home / "secrets" / "oauth.json", {"client_id": "client", "client_secret": "secret", "refresh_token": "refresh"})
            self.assertFalse((real_home / "secrets").exists())

    def test_initialization_rejects_symlinked_secret_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            outside = Path(temp) / "outside"
            home.mkdir(mode=0o700)
            outside.mkdir(mode=0o700)
            (home / "secrets").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "symlink"):
                initialize_oauth_state(home / "secrets" / "linear-oauth.json", {"client_id": "client", "client_secret": "secret", "refresh_token": "refresh"})
            self.assertFalse((outside / "linear-oauth.json").exists())
    def test_unexpired_access_token_is_reused_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "linear-oauth.json"
            path.write_text(json.dumps({"access_token": "current", "expires_at": 2000}), encoding="utf-8")
            path.chmod(0o600)
            token = LinearOAuthToken(path, now=lambda: 1000, transport=lambda *_: self.fail("must not refresh"))

            self.assertEqual(token(), "current")

    def test_expired_token_is_refreshed_and_rotated_state_is_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "linear-oauth.json"
            path.write_text(json.dumps({
                "access_token": "expired",
                "expires_at": 900,
                "refresh_token": "refresh-old",
                "client_id": "client",
                "client_secret": "secret",
            }), encoding="utf-8")
            path.chmod(0o600)
            requests = []

            def transport(url, headers, body):
                requests.append((url, headers, body))
                return json.dumps({
                    "access_token": "fresh",
                    "refresh_token": "refresh-new",
                    "expires_in": 3600,
                }).encode()

            token = LinearOAuthToken(path, now=lambda: 1000, transport=transport)

            self.assertEqual(token(), "fresh")
            saved = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(saved["access_token"], "fresh")
            self.assertEqual(saved["refresh_token"], "refresh-new")
            self.assertEqual(saved["expires_at"], 4540)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(len(requests), 1)
            self.assertNotIn(b"expired", requests[0][2])

    def test_oauth_file_with_broad_permissions_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "linear-oauth.json"
            path.write_text(json.dumps({"access_token": "current", "expires_at": 2000}), encoding="utf-8")
            path.chmod(0o644)

            with self.assertRaisesRegex(ValueError, "permissions"):
                LinearOAuthToken(path, now=lambda: 1000)()

    def test_rotation_is_not_usable_until_remote_sink_confirms_it(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "linear-oauth.json"
            path.write_text(json.dumps({
                "access_token": "expired", "expires_at": 900,
                "refresh_token": "refresh-old", "client_id": "client", "client_secret": "secret",
            }), encoding="utf-8")
            path.chmod(0o600)
            refresh_calls = []
            sink_calls = []

            def transport(*_args):
                refresh_calls.append(True)
                return json.dumps({"access_token": "fresh", "refresh_token": "refresh-new", "expires_in": 3600}).encode()

            def failing_sink(token: str) -> None:
                sink_calls.append(token)
                raise RuntimeError("remote unavailable")

            with self.assertRaisesRegex(RuntimeError, "durable store"):
                LinearOAuthToken(path, now=lambda: 1000, transport=transport, refresh_sink=failing_sink)()
            staged = json.loads(path.read_text())
            self.assertEqual(staged["pending_refresh_token"], "refresh-new")
            self.assertEqual(staged["refresh_token"], "refresh-old")

            token = LinearOAuthToken(path, now=lambda: 1000, transport=transport, refresh_sink=sink_calls.append)
            self.assertEqual(token(), "fresh")
            committed = json.loads(path.read_text())
            self.assertNotIn("pending_refresh_token", committed)
            self.assertEqual(committed["refresh_token"], "refresh-new")
            self.assertEqual(len(refresh_calls), 1)

    def test_partial_pending_rotation_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "oauth.json"
            path.write_text(json.dumps({"access_token": "", "expires_at": 0, "refresh_token": "refresh", "client_id": "client", "client_secret": "secret", "pending_refresh_token": "rotated"}))
            path.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError, "pending"):
                LinearOAuthToken(path, now=lambda: 1000, transport=lambda *_: b"{}")()

    def test_invalid_pending_rotation_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "oauth.json"
            path.write_text(json.dumps({"access_token": "", "expires_at": 0, "refresh_token": "refresh", "client_id": "client", "client_secret": "secret", "pending_refresh_token": "rotated", "pending_access_token": "access", "pending_expires_at": "invalid"}))
            path.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError, "pending"):
                LinearOAuthToken(path, now=lambda: 1000, transport=lambda *_: b"{}")()

    def test_expired_pending_access_reconciles_refresh_then_refreshes_again(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "linear-oauth.json"
            path.write_text(json.dumps({"access_token": "expired", "expires_at": 1, "refresh_token": "refresh-old", "client_id": "client", "client_secret": "secret", "pending_access_token": "stale-pending", "pending_refresh_token": "refresh-pending", "pending_expires_at": 50}), encoding="utf-8")
            path.chmod(0o600)
            persisted = []
            bodies = []

            def transport(_url, _headers, body):
                bodies.append(body)
                return json.dumps({"access_token": "fresh", "refresh_token": "refresh-final", "expires_in": 3600}).encode()

            source = LinearOAuthToken(path, now=lambda: 100, transport=transport, refresh_sink=persisted.append)
            self.assertEqual(source(), "fresh")
            self.assertEqual(persisted, ["refresh-pending", "refresh-final"])
            self.assertIn(b"refresh_token=refresh-pending", bodies[0])

    def test_invalidate_forces_refresh_on_next_use(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "linear-oauth.json"
            path.write_text(json.dumps({
                "access_token": "current", "expires_at": 2000,
                "refresh_token": "refresh-old", "client_id": "client", "client_secret": "secret",
            }), encoding="utf-8")
            path.chmod(0o600)
            token = LinearOAuthToken(path, now=lambda: 1000, transport=lambda *_: json.dumps({
                "access_token": "fresh", "refresh_token": "refresh-new", "expires_in": 3600,
            }).encode(), refresh_sink=lambda _token: None)
            token.invalidate()
            self.assertEqual(token(), "fresh")


if __name__ == "__main__":
    unittest.main()
