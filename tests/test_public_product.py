from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PublicProductTests(unittest.TestCase):
    def test_required_public_product_files_exist(self) -> None:
        for relative in (
            "Dockerfile",
            "compose.example.yaml",
            "README.md",
            "SECURITY.md",
            "LICENSE",
            ".github/workflows/ci.yml",
            "contracts/image.json",
            "contracts/config.json",
            "contracts/plugins.json",
            "scripts/verify-public-tree.py",
            "scripts/image_ref.py",
            "scripts/verify-agent-image-ref.py",
            "scripts/build-fleet-image.py",
            "scripts/compose.py",
        ):
            with self.subTest(relative=relative):
                self.assertTrue((ROOT / relative).is_file())

    def test_repository_has_no_remote_and_clean_history_contract(self) -> None:
        roots = subprocess.check_output(
            ["git", "rev-list", "--max-parents=0", "HEAD"],
            cwd=ROOT,
            text=True,
        ).split()
        self.assertEqual(roots, ["4dbbe890715aec58a04fd376559a97fa300e9486"])
        config = (ROOT / ".git" / "config").read_text(encoding="utf-8")
        # GitHub checkouts have origin. Local publication candidates must not.
        if os.environ.get("GITHUB_ACTIONS"):
            return
        self.assertNotIn('[remote "', config)

    def test_dockerfile_is_a_minimal_digest_parameterized_child(self) -> None:
        text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertEqual(re.findall(r"(?m)^FROM\s+(.+)$", text), ["${AGENT_IMAGE}"])
        self.assertIn("ARG AGENT_IMAGE", text)
        self.assertIn("scripts/image_ref.py /opt/hermes-fleet/bin/image_ref.py", text)
        self.assertIn("scripts/verify-agent-image-ref.py /opt/hermes-fleet/bin/verify-agent-image-ref", text)
        self.assertNotRegex(text, r"(?m)^\s*(?:ENTRYPOINT|CMD|USER)\b")
        self.assertNotIn("core_runtime_paths", text)

    def test_compose_uses_synthetic_profiles_and_dedicated_networks(self) -> None:
        text = (ROOT / "compose.example.yaml").read_text(encoding="utf-8")
        self.assertIn("operator:", text)
        self.assertIn("worker:", text)
        self.assertIn("operator-network:", text)
        self.assertIn("worker-network:", text)
        self.assertNotIn("network_mode: host", text)
        self.assertNotIn("docker.sock", text)
        self.assertNotIn("privileged: true", text)
        self.assertNotRegex(text, r"(?m)^\s*user:\s*")
        self.assertGreaterEqual(text.count("/opt/data"), 4)

    def test_contracts_are_public_product_contracts(self) -> None:
        image = json.loads((ROOT / "contracts/image.json").read_text())
        config = json.loads((ROOT / "contracts/config.json").read_text())
        plugins = json.loads((ROOT / "contracts/plugins.json").read_text())
        self.assertEqual(image["status"], "public_product_skeleton")
        self.assertEqual(image["images"]["fleet"]["base"], "agent_digest")
        self.assertTrue(image["images"]["agent"]["provenance_required"])
        self.assertEqual(image["runtime"]["network"]["default"], "dedicated_per_profile_bridge")
        self.assertEqual(config["desired_state"]["unknown_key_policy"], "fail_closed")
        self.assertEqual(config["desired_state"]["secret_value_policy"], "reject")
        self.assertEqual(plugins["public_base"]["default_enabled_plugins"], [])
        self.assertTrue(all(not item["default_enabled"] for item in plugins["components"]))
        contract_text = "\n".join(
            (ROOT / relative).read_text(encoding="utf-8").lower()
            for relative in ("contracts/image.json", "contracts/config.json", "contracts/plugins.json")
        )
        for prohibited in (
            "private_house",
            "runtime_secret_broker",
            "honcho",
            "secret-broker",
            "house-policy",
        ):
            with self.subTest(prohibited=prohibited):
                self.assertNotIn(prohibited, contract_text)
        self.assertEqual(image["publication"]["implementation_state"], "future_release_gate")

    def test_immutable_reference_wrappers_reject_mutable_images(self) -> None:
        digest = "0123456789abcdef" * 4
        good = f"ghcr.io/example/hermes-agent@sha256:{digest}"
        valid = subprocess.run(
            [
                "python3",
                "scripts/build-fleet-image.py",
                "--agent-image",
                good,
                "--tag",
                "hermes-fleet:test",
                "--dry-run",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(valid.returncode, 0, valid.stderr)
        self.assertIn(f"AGENT_IMAGE={good}", valid.stdout)
        invalid = subprocess.run(
            [
                "python3",
                "scripts/build-fleet-image.py",
                "--agent-image",
                "ghcr.io/example/hermes-agent:latest",
                "--tag",
                "hermes-fleet:test",
                "--dry-run",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(invalid.returncode, 0)
        deploy = subprocess.run(
            ["python3", "scripts/compose.py", "config"],
            cwd=ROOT,
            env={"HERMES_FLEET_IMAGE": "ghcr.io/example/hermes-fleet:latest"},
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(deploy.returncode, 0)

        immutable = "ghcr.io/example/hermes-fleet@sha256:" + "0" * 64
        override = subprocess.run(
            ["python3", "scripts/compose.py", "--", "-f", "/tmp/override.yaml", "config"],
            cwd=ROOT,
            env={"HERMES_FLEET_IMAGE": immutable},
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(override.returncode, 0)
        self.assertIn("unsupported Compose command", override.stderr)

    def test_wrappers_anchor_docker_to_repository_root(self) -> None:
        immutable = "ghcr.io/example/hermes-agent@sha256:" + "0" * 64
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            capture = temp / "capture"
            docker = temp / "docker"
            docker.write_text("#!/bin/sh\nprintf '%s\\n' \"$PWD\" \"$@\" > \"$CAPTURE\"\n", encoding="utf-8")
            docker.chmod(0o755)
            env = {**os.environ, "PATH": f"{temp}:{os.environ['PATH']}", "CAPTURE": str(capture)}

            build = subprocess.run(
                [
                    "python3",
                    str(ROOT / "scripts/build-fleet-image.py"),
                    "--agent-image",
                    immutable,
                    "--tag",
                    "hermes-fleet:test",
                ],
                cwd=temp,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(build.returncode, 0, build.stderr)
            build_args = capture.read_text(encoding="utf-8").splitlines()
            self.assertEqual(build_args[0], str(ROOT))
            self.assertEqual(build_args[-1], ".")

            env["HERMES_FLEET_IMAGE"] = immutable.replace("hermes-agent", "hermes-fleet")
            compose = subprocess.run(
                ["python3", str(ROOT / "scripts/compose.py"), "config"],
                cwd=temp,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(compose.returncode, 0, compose.stderr)
            compose_args = capture.read_text(encoding="utf-8").splitlines()
            self.assertEqual(compose_args[0], str(ROOT))
            self.assertIn(str(ROOT / "compose.example.yaml"), compose_args)

    def test_public_tree_policy_includes_untracked_files(self) -> None:
        forbidden = ROOT / "auth.json"
        forbidden.write_text("{}\n", encoding="utf-8")
        try:
            result = subprocess.run(
                ["python3", "scripts/verify-public-tree.py"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("forbidden path: auth.json", result.stdout)
        finally:
            forbidden.unlink(missing_ok=True)

    def test_public_tree_policy_rejects_ignored_env_variants(self) -> None:
        forbidden = ROOT / ".env.production"
        forbidden.write_text("EXAMPLE=value\n", encoding="utf-8")
        try:
            result = subprocess.run(
                ["python3", "scripts/verify-public-tree.py"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("forbidden path: .env.production", result.stdout)
        finally:
            forbidden.unlink(missing_ok=True)

    def test_public_tree_policy_scans_its_own_source(self) -> None:
        verifier = ROOT / "scripts/verify-public-tree.py"
        original = verifier.read_text(encoding="utf-8")
        marker = "BEGIN " + "PRIVATE KEY"
        verifier.write_text(original + f"\n# {marker}\n", encoding="utf-8")
        try:
            result = subprocess.run(
                ["python3", "scripts/verify-public-tree.py"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("private key: scripts/verify-public-tree.py", result.stdout)
        finally:
            verifier.write_text(original, encoding="utf-8")

    def test_public_tree_policy_rejects_unexpected_binary(self) -> None:
        binary = ROOT / "artifact.bin"
        binary.write_bytes(b"\xff\xfe\x00\x01")
        try:
            result = subprocess.run(
                ["python3", "scripts/verify-public-tree.py"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("binary file requires dedicated scanning: artifact.bin", result.stdout)
        finally:
            binary.unlink(missing_ok=True)

    def test_ci_is_source_only_and_pinned(self) -> None:
        text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("permissions:\n  contents: read", text)
        self.assertIn("fetch-depth: 0", text)
        self.assertIn("python3 -m unittest discover", text)
        self.assertIn("scripts/verify-public-tree.py", text)
        self.assertIn("python3 scripts/compose.py config -q", text)
        self.assertNotIn("packages: write", text)
        self.assertNotIn("docker/build-push-action", text)
        for uses in re.findall(r"(?m)^\s*-?\s*uses:\s*([^\s#]+)", text):
            self.assertRegex(uses, r"^[^@]+@[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
