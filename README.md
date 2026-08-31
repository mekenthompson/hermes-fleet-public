# Hermes Fleet

An opinionated, public Docker isolation pattern for running multiple [Hermes Agent](https://github.com/NousResearch/hermes-agent) profiles as separate containers.

This repository is a product skeleton. It does not yet publish images or claim production readiness.

## Design

- Build a complete Agent image from an exact pushed public fork commit.
- Build the Fleet image as a digest-pinned child of that Agent image.
- Run one container, writable state volume, workspace volume, and Docker network per profile.
- Keep Docker socket, host networking, host bridges, privileged mode, credentials, identities, sessions, memories, and deployment topology out of the public image.
- Keep optional integrations as standalone plugins, disabled by default.

## Supported local commands

The supported build wrapper validates the Agent base reference before Docker sees it:

```bash
python3 scripts/build-fleet-image.py \
  --agent-image ghcr.io/example/hermes-agent@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --tag hermes-fleet:local
```

The supported Compose wrapper validates `HERMES_FLEET_IMAGE` before invoking Docker Compose:

```bash
export HERMES_FLEET_IMAGE=ghcr.io/example/hermes-fleet@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
python3 scripts/compose.py config
```

Direct `docker build` and `docker compose` calls bypass the immutable-reference guard and are not supported.

## Local validation

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
python3 scripts/verify-public-tree.py
python3 scripts/verify-agent-image-ref.py   ghcr.io/example/hermes-agent@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

## Example deployment

Set `HERMES_FLEET_IMAGE` to an immutable digest reference, then use `python3 scripts/compose.py`. The example profiles are synthetic. Replace them in a deployment repository, not in this public product tree.

The Phase 2 Compose file demonstrates volume and network separation only. Runtime hardening, egress controls, cold/warm state compatibility, UID/GID behavior, shutdown, persistence, and rollback remain Phase 3 acceptance gates. The example is not a production baseline until those daemon-backed tests pass.

The managed files under `examples/` demonstrate a small administrator overlay. They are not a security boundary and contain no secrets. Mutable Hermes configuration remains in each profile's `/opt/data/config.yaml`.

See `contracts/` for the machine-readable architecture boundaries.
