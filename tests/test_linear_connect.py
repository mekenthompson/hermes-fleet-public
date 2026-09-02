"""Profile-scoped 1Password Connect persistence for Linear OAuth."""
from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "plugins" / "linear-agent"))

from linear_connect import OnePasswordLinearRefreshSink, load_connect_environment

CONNECT_HOST = "http://connect.example.internal:8080"
APPROVED_CONNECT_HOSTS = frozenset({CONNECT_HOST})


class OnePasswordLinearRefreshSinkTests(unittest.TestCase):
    def test_connect_environment_requires_private_regular_file(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / ".op.env"
            path.write_text(
                "OP_CONNECT_HOST=http://connect.example.internal:8080\n"
                "OP_CONNECT_TOKEN=secret-token\n"
                "OP_CONNECT_ALLOWED_HOSTS=http://connect.example.internal:8080\n",
                encoding="utf-8",
            )
            path.chmod(0o600)
            self.assertEqual(
                load_connect_environment(path),
                (
                    "http://connect.example.internal:8080",
                    "secret-token",
                    frozenset({"http://connect.example.internal:8080"}),
                ),
            )
            path.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, "permissions"):
                load_connect_environment(path)

    def test_connect_environment_handles_short_regular_file_reads(self) -> None:
        import tempfile
        real_read = os.read
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / ".op.env"
            path.write_text(
                f"OP_CONNECT_HOST={CONNECT_HOST}\n"
                "OP_CONNECT_TOKEN=secret-token\n"
                f"OP_CONNECT_ALLOWED_HOSTS={CONNECT_HOST}\n",
                encoding="utf-8",
            )
            path.chmod(0o600)
            with patch("linear_connect.os.read", side_effect=lambda fd, size: real_read(fd, min(size, 7))):
                host, token, approved = load_connect_environment(path)
            self.assertEqual((host, token, approved), (CONNECT_HOST, "secret-token", APPROVED_CONNECT_HOSTS))

    def test_connect_environment_requires_explicit_host_allowlist(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / ".op.env"
            path.write_text(
                f"OP_CONNECT_HOST={CONNECT_HOST}\nOP_CONNECT_TOKEN=secret-token\n",
                encoding="utf-8",
            )
            path.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError, "allowlist"):
                load_connect_environment(path)

    def test_patch_waits_for_exact_profile_item_readback(self) -> None:
        calls = []
        reads = iter(("old-refresh", "new-refresh"))

        def transport(method, url, headers, body=None):
            calls.append((method, url, body))
            if url.endswith("/v1/vaults"):
                return [{"id": "vault-sample"}]
            if method == "PATCH":
                patch = json.loads(body)
                self.assertEqual(patch, [{"op": "replace", "path": "/fields/field-refresh/value", "value": "new-refresh"}])
                return {"version": 2}
            return {
                "id": "item-linear", "vault": {"id": "vault-sample"}, "title": "Linear Client",
                "fields": [{"id": "field-refresh", "label": "refresh_token", "value": next(reads)}],
            }

        sink = OnePasswordLinearRefreshSink(
            connect_host=CONNECT_HOST, connect_token="connect-secret",
            approved_connect_hosts=APPROVED_CONNECT_HOSTS,
            profile="sample", vault_id="vault-sample", item_id="item-linear",
            transport=transport, sleep=lambda _seconds: None,
        )
        sink("new-refresh")
        self.assertEqual(sum(1 for method, *_ in calls if method == "PATCH"), 1)

    def test_reads_complete_profile_bound_oauth_credentials(self) -> None:
        def transport(_method, url, _headers, body=None):
            if url.endswith("/v1/vaults"):
                return [{"id": "vault-sample"}]
            return {"id": "item-linear", "vault": {"id": "vault-sample"}, "title": "Linear Client", "fields": [
                {"id": "field-client", "label": "client_id", "value": "client"},
                {"id": "field-secret", "label": "client_secret", "value": "secret"},
                {"id": "field-refresh", "label": "refresh_token", "value": "refresh"},
            ]}
        sink = OnePasswordLinearRefreshSink(connect_host=CONNECT_HOST, connect_token="token", approved_connect_hosts=APPROVED_CONNECT_HOSTS, profile="sample", vault_id="vault-sample", item_id="item-linear", transport=transport)
        self.assertEqual(sink.read_credentials(), {"client_id": "client", "client_secret": "secret", "refresh_token": "refresh"})

    def test_reads_standard_1password_username_and_credential_aliases(self) -> None:
        def transport(_method, url, _headers, body=None):
            if url.endswith("/v1/vaults"):
                return [{"id": "vault-sample"}]
            return {"id": "item-linear", "vault": {"id": "vault-sample"}, "title": "Linear Client", "fields": [
                {"id": "username", "label": "username", "value": "client"},
                {"id": "credential", "label": "credential", "value": "secret"},
                {"id": "field-refresh", "label": "refresh_token", "value": "refresh"},
            ]}
        sink = OnePasswordLinearRefreshSink(connect_host=CONNECT_HOST, connect_token="token", approved_connect_hosts=APPROVED_CONNECT_HOSTS, profile="sample", vault_id="vault-sample", item_id="item-linear", transport=transport)
        self.assertEqual(sink.read_credentials()["client_secret"], "secret")

    def test_cross_profile_vault_scope_is_rejected_before_write(self) -> None:
        writes = []
        def transport(method, url, _headers, body=None):
            if method != "GET":
                writes.append((method, body))
            if url.endswith("/v1/vaults"):
                return [{"id": "vault-operator"}]
            return {}
        sink = OnePasswordLinearRefreshSink(
            connect_host=CONNECT_HOST, connect_token="connect-secret",
            approved_connect_hosts=APPROVED_CONNECT_HOSTS,
            profile="sample", vault_id="vault-sample", item_id="item-linear", transport=transport,
        )
        with self.assertRaisesRegex(RuntimeError, "vault scope"):
            sink("new-refresh")
        self.assertEqual(writes, [])

    def test_unapproved_connect_host_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "Connect host"):
            OnePasswordLinearRefreshSink(
                connect_host="https://attacker.example", connect_token="secret",
                approved_connect_hosts=APPROVED_CONNECT_HOSTS, profile="sample",
                vault_id="vault-sample", item_id="item-linear",
            )


if __name__ == "__main__":
    unittest.main()
