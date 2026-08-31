# Fleet image release

The public Fleet image is a minimal child of the **exact Agent digest** recorded in `release/agent-image-manifest.json`. Mutable tags are rejected before Docker runs.

## Transaction

Pull requests and manual validation runs build one `linux/amd64` candidate from the exact Fleet source revision. Preflight verifies the pinned Agent handoff, inherited Agent provenance marker and installed Hermes version, Fleet revision and image identity, inherited runtime user/entrypoint/command, non-root `hermes` uid, absence of a Docker socket, full SPDX evidence, bounded package-level SPDX, and the critical-vulnerability gate.

A `publish=true` dispatch from `main` exports that candidate. The protected `fleet-image-publish` job downloads, loads, and re-verifies the same candidate, then pushes it **without rebuilding**. Publication attaches SLSA build provenance and the bounded package-level SPDX document to the resulting digest. The full SPDX and scanner report remain pre-publication evidence.

The final authenticated artifact is a House handoff manifest containing only public Agent and Fleet source/image identities. It is not deployment configuration and contains no topology, profile identity, host path, policy, or secret reference.

## Boundaries

This workflow performs **no production deployment**. It does not modify profile state, Docker Compose inputs, networks, secrets, or running containers. The public image inherits the Agent image's user, entrypoint, and command and adds only public contracts, verification tools, labels, and provenance environment values.

## Approval

Only `main` may enter `fleet-image-publish`. Review the exact preflight source SHA, Agent digest, runtime checks, full SPDX, compact SPDX, and Trivy result before approving.

## Rollback

Rollback is digest selection, not an image rebuild. A private deployment may retain a previously verified Fleet digest and select it after its own cold/warm compatibility and rollback tests. Publishing a digest does not authorize rollout.
