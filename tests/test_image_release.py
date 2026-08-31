from __future__ import annotations

import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/fleet-image.yml"
AGENT_MANIFEST = ROOT / "release/agent-image-manifest.json"
READ_MANIFEST = ROOT / "scripts/read-agent-image-manifest.py"
EMIT_MANIFEST = ROOT / "scripts/emit-fleet-image-manifest.py"
COMPACT_SBOM = ROOT / "scripts/compact-spdx-sbom.py"
AGENT_REPOSITORY = "ghcr.io/mekenthompson/hermes-agent"
AGENT_REVISION = "5aa54ca6b47db1271b9101f4a08076e17bc9b759"
AGENT_DIGEST = "sha256:9c6473d0eb3ccf0c7b82d8599d0d42af622e8e7a7f22525bb3743b4a83f17dc5"
AGENT_REF = f"{AGENT_REPOSITORY}@{AGENT_DIGEST}"


class FleetImageReleaseTests(unittest.TestCase):
    def test_release_files_exist(self) -> None:
        for path in (WORKFLOW, AGENT_MANIFEST, READ_MANIFEST, EMIT_MANIFEST, COMPACT_SBOM, ROOT / "docs/image-release.md"):
            with self.subTest(path=path):
                self.assertTrue(path.is_file())

    def test_agent_handoff_is_exact_and_validator_is_fail_closed(self) -> None:
        manifest = json.loads(AGENT_MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(
            manifest,
            {
                "schema_version": 1,
                "repository": AGENT_REPOSITORY,
                "revision": AGENT_REVISION,
                "digest": AGENT_DIGEST,
                "immutable_ref": AGENT_REF,
            },
        )
        result = subprocess.run(
            ["python3", str(READ_MANIFEST), "--manifest", str(AGENT_MANIFEST)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["AGENT_IMAGE"], AGENT_REF)

        bad_values = (
            {**manifest, "immutable_ref": f"{AGENT_REPOSITORY}:latest"},
            {**manifest, "digest": "sha256:1234"},
            {**manifest, "revision": "main"},
            {**manifest, "extra": "not-allowed"},
        )
        for bad in bad_values:
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "manifest.json"
                path.write_text(json.dumps(bad), encoding="utf-8")
                rejected = subprocess.run(
                    ["python3", str(READ_MANIFEST), "--manifest", str(path)],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertNotEqual(rejected.returncode, 0)

    def test_dockerfile_bakes_public_provenance_without_changing_runtime_contract(self) -> None:
        text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertEqual(re.findall(r"(?m)^FROM\s+(.+)$", text), ["${AGENT_IMAGE}"])
        for token in (
            "ARG FLEET_GIT_SHA",
            "ARG FLEET_IMAGE_IDENTITY",
            "HERMES_FLEET_GIT_SHA=${FLEET_GIT_SHA}",
            "HERMES_FLEET_IMAGE_IDENTITY=${FLEET_IMAGE_IDENTITY}",
            "HERMES_FLEET_AGENT_IMAGE=${AGENT_IMAGE}",
            "org.opencontainers.image.revision=\"${FLEET_GIT_SHA}\"",
            "/etc/hermes-fleet/image-provenance.json",
        ):
            self.assertIn(token, text)
        self.assertNotRegex(text, r"(?m)^\s*(?:ENTRYPOINT|CMD|USER)\b")

    def test_release_workflow_is_manual_publish_and_least_privilege(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("pull_request:", text)
        self.assertIn("workflow_dispatch:", text)
        self.assertNotRegex(text, r"(?m)^\s*push:\s*$")
        self.assertIn("github.repository == 'mekenthompson/hermes-fleet-public'", text)
        self.assertIn("github.ref == 'refs/heads/main'", text)
        self.assertIn("environment: fleet-image-publish", text)
        self.assertIn("platforms: linux/amd64", text)
        self.assertIn("packages: read", text.split("\n  publish:\n", 1)[0])
        self.assertNotIn("packages: write", text.split("\n  publish:\n", 1)[0])
        self.assertRegex(
            text,
            r"(?s)permissions:\n  contents: read.*?publish:.*?permissions:\n      contents: read\n      packages: write\n      id-token: write\n      attestations: write",
        )
        self.assertNotIn("secrets.", text)
        for uses in re.findall(r"(?m)^\s*-?\s*uses:\s*([^\s#]+)", text):
            self.assertRegex(uses, r"^[^@]+@[0-9a-f]{40}$")

    def test_preflight_consumes_handoff_and_verifies_runtime_isolation(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        for token in (
            "scripts/read-agent-image-manifest.py",
            "release/agent-image-manifest.json",
            "AGENT_IMAGE=${{ steps.agent.outputs.AGENT_IMAGE }}",
            "FLEET_GIT_SHA=${{ github.sha }}",
            "FLEET_IMAGE_IDENTITY=${{ env.IMAGE_REPOSITORY }}",
            "EXPECTED_AGENT_REVISION",
            "/etc/hermes/image-provenance.json",
            "/etc/hermes-fleet/image-provenance.json",
            "metadata.version(\"hermes-agent\")",
            "HERMES_FLEET_GIT_SHA",
            "HERMES_FLEET_IMAGE_IDENTITY",
            "HERMES_FLEET_AGENT_IMAGE",
            "docker.sock",
            "scripts/verify-inherited-runtime-config.py",
            "os.getuid() != 0",
            "docker/login-action@",
        ):
            self.assertIn(token, text)
        runtime = (ROOT / "scripts/verify-inherited-runtime-config.py").read_text(encoding="utf-8")
        self.assertIn("Config.User", runtime)
        self.assertIn("Config.Entrypoint", runtime)
        self.assertIn("Config.Cmd", runtime)

    def test_exact_candidate_scan_and_publication_contract(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(text.count("docker/build-push-action@"), 1)
        self.assertIn('docker save "$TEST_IMAGE" | gzip -1 > fleet-image.tar.gz', text)
        self.assertIn("set -euo pipefail", text)
        self.assertIn("gzip -dc fleet-image.tar.gz | docker load", text)
        self.assertIn('docker push "$TEST_IMAGE"', text)
        publish = text.split("\n  publish:\n", 1)[1]
        self.assertNotIn("docker/build-push-action@", publish)
        self.assertIn("Load and verify exact scanned candidate", publish)

    def test_release_preserves_full_evidence_and_attests_bounded_sbom(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        for token in (
            "fleet-image.spdx.json",
            "fleet-image.attestation.spdx.json",
            "scripts/compact-spdx-sbom.py",
            "--max-bytes 16777216",
            "trivy-image.json",
            "severity: CRITICAL",
            "actions/attest-build-provenance@",
            "actions/attest-sbom@",
            "sbom-path: fleet-image.attestation.spdx.json",
            "fleet-image-handoff-${{ github.sha }}",
        ):
            self.assertIn(token, text)

    def test_fleet_handoff_generator_binds_agent_and_fleet_identities(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "handoff.json"
            digest = "sha256:" + "a" * 64
            result = subprocess.run(
                [
                    "python3",
                    str(EMIT_MANIFEST),
                    "--repository",
                    "ghcr.io/mekenthompson/hermes-fleet-public",
                    "--revision",
                    "b" * 40,
                    "--digest",
                    digest,
                    "--agent-manifest",
                    str(AGENT_MANIFEST),
                    "--output",
                    str(output),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(data["schema_version"], 1)
            self.assertEqual(data["fleet"]["immutable_ref"], f"ghcr.io/mekenthompson/hermes-fleet-public@{digest}")
            self.assertEqual(data["fleet"]["source_repository"], "https://github.com/mekenthompson/hermes-fleet-public")
            self.assertEqual(data["agent"]["immutable_ref"], AGENT_REF)
            self.assertEqual(output.read_text(encoding="utf-8"), json.dumps(data, indent=2, sort_keys=True) + "\n")

    def test_compact_sbom_removes_file_surfaces_and_is_deterministic(self) -> None:
        document = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "documentDescribes": ["SPDXRef-Package-a", "SPDXRef-File-a"],
            "packages": [{
                "name": "a",
                "SPDXID": "SPDXRef-Package-a",
                "filesAnalyzed": True,
                "hasFiles": ["SPDXRef-File-a"],
                "licenseInfoFromFiles": ["MIT"],
                "packageVerificationCode": {"packageVerificationCodeValue": "abc"},
            }],
            "files": [{"SPDXID": "SPDXRef-File-a", "fileName": "/a"}],
            "snippets": [{"SPDXID": "SPDXRef-Snippet-a"}],
            "relationships": [
                {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Package-a"},
                {"spdxElementId": "SPDXRef-Package-a", "relationshipType": "CONTAINS", "relatedSpdxElement": "SPDXRef-File-a"},
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "full.json"
            first = Path(directory) / "first.json"
            second = Path(directory) / "second.json"
            source.write_text(json.dumps(document), encoding="utf-8")
            for output in (first, second):
                result = subprocess.run(
                    ["python3", str(COMPACT_SBOM), "--input", str(source), "--output", str(output)],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            compact = json.loads(first.read_text(encoding="utf-8"))
            self.assertEqual(compact["files"], [])
            self.assertEqual(compact["snippets"], [])
            self.assertEqual(compact["documentDescribes"], ["SPDXRef-Package-a"])
            self.assertEqual(len(compact["relationships"]), 1)
            package = compact["packages"][0]
            self.assertFalse(package["filesAnalyzed"])
            for field in ("hasFiles", "licenseInfoFromFiles", "packageVerificationCode"):
                self.assertNotIn(field, package)

    def test_compact_sbom_rejects_malformed_ids_and_relationships(self) -> None:
        cases = (
            {"SPDXID": "bad", "packages": [{"SPDXID": "SPDXRef-Package-a"}], "files": [], "relationships": []},
            {"SPDXID": "SPDXRef-DOCUMENT", "packages": [{"SPDXID": 123}], "files": [], "relationships": []},
            {"SPDXID": "SPDXRef-DOCUMENT", "packages": [{"SPDXID": "SPDXRef-Package-a"}], "files": [], "relationships": ["bad"]},
        )
        for document in cases:
            with self.subTest(document=document), tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / "full.json"
                output = Path(directory) / "compact.json"
                source.write_text(json.dumps(document), encoding="utf-8")
                result = subprocess.run(
                    ["python3", str(COMPACT_SBOM), "--input", str(source), "--output", str(output)],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(output.exists())
                self.assertNotIn("Traceback", result.stderr)

    def test_release_documentation_states_boundaries(self) -> None:
        text = (ROOT / "docs/image-release.md").read_text(encoding="utf-8").lower()
        for token in (
            "exact agent digest",
            "without rebuilding",
            "full spdx",
            "package-level",
            "no production deployment",
            "fleet-image-publish",
            "rollback",
        ):
            self.assertIn(token, text)


if __name__ == "__main__":
    unittest.main()
