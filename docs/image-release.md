# Fleet image release

The public Fleet image is a minimal child of the **exact Agent digest** recorded in `release/agent-image-manifest.json`. Mutable tags are rejected before Docker runs.

## Transaction

Pull requests and manual validation runs build one `linux/amd64` candidate from the exact Fleet source revision. Preflight verifies the pinned Agent handoff, inherited Agent provenance marker and installed Hermes version, Fleet revision and image identity, inherited runtime user/entrypoint/command, non-root `hermes` workload execution, 1Password CLI 2.39.0 from its exact official image digest, Claude Code 2.1.251 from the exact-version npm package and committed integrity lock, absence of a Docker socket, full SPDX evidence, bounded package-level SPDX, official SPDX 2.3 schema validity through a fully hashed validator lock, and the critical-vulnerability gate.

A `publish=true` dispatch from `main` exports that candidate. The protected `fleet-image-publish` job downloads, loads, and re-verifies the same candidate, then pushes it **without rebuilding**. Publication attaches SLSA build provenance and the bounded package-level SPDX document to the resulting digest. The full SPDX and scanner report remain pre-publication evidence.

The final authenticated artifact is a House handoff manifest containing only public Agent and Fleet source/image identities. It is not deployment configuration and contains no topology, profile identity, host path, policy, or secret reference.

## Boundaries

This workflow performs **no production deployment**. It does not modify profile state, Docker Compose inputs, networks, secrets, or running containers. The public image inherits the Agent image's user, entrypoint, and command. The Agent image records `User=root` and drops to the non-root `hermes` account through its entrypoint. Fleet also copies the `op` executable from the immutable official image `docker.io/1password/op@sha256:d7d12b409ec699c9fa139d3bdfc80671f744380d39db8c539d9dc6e7e553d3c1`, verifies version `2.39.0` during build and release, and records that source in the image provenance marker. Claude Code is installed from the committed lockfile at exact version `2.1.251`; `npm ci` disables lifecycle scripts, then the Dockerfile explicitly invokes only Anthropic's locked `install.cjs` to select the native optional package. The lock records npm integrity `sha512-eG+ZPPpW2Dbmnntf1Fz9/T9ewS8I8SKfc1tcU2PqSwmftfjRPP7BXPaCyLuZ8kvgTdiPnJi/2/JnTvTRieneEQ==`, and auto-update is disabled so runtime bytes cannot drift from the scanned image. The image contains no credentials, Claude OAuth state, account data, vault references, or 1Password configuration; those remain external runtime inputs.

## Approval

Only `main` may enter `fleet-image-publish`. Review the exact preflight source SHA, Agent digest, runtime checks, full SPDX, compact SPDX, and Trivy result before approving.

## Rollback

Rollback is digest selection, not an image rebuild. A private deployment may retain a previously verified Fleet digest and select it after its own cold/warm compatibility and rollback tests. Publishing a digest does not authorize rollout.
