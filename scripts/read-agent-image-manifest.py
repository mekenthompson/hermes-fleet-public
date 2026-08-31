#!/usr/bin/env python3
"""Validate the pinned Agent handoff and emit release build inputs."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

REPOSITORY_RE = re.compile(r"^ghcr\.io/[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
EXPECTED_KEYS = {"schema_version", "repository", "revision", "digest", "immutable_ref"}


def load_manifest(path: Path) -> dict[str, object]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or set(data) != EXPECTED_KEYS:
        raise SystemExit("Agent manifest has unexpected fields")
    if data.get("schema_version") != 1:
        raise SystemExit("unsupported Agent manifest schema")
    repository = data.get("repository")
    revision = data.get("revision")
    digest = data.get("digest")
    immutable_ref = data.get("immutable_ref")
    if not isinstance(repository, str) or REPOSITORY_RE.fullmatch(repository) is None:
        raise SystemExit("invalid Agent repository")
    if not isinstance(revision, str) or REVISION_RE.fullmatch(revision) is None:
        raise SystemExit("invalid Agent revision")
    if not isinstance(digest, str) or DIGEST_RE.fullmatch(digest) is None:
        raise SystemExit("invalid Agent digest")
    if immutable_ref != f"{repository}@{digest}":
        raise SystemExit("Agent immutable_ref does not match repository and digest")
    return data


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--github-env", type=Path)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    data = load_manifest(args.manifest)
    values = {
        "AGENT_IMAGE": data["immutable_ref"],
        "AGENT_REPOSITORY": data["repository"],
        "AGENT_REVISION": data["revision"],
        "AGENT_DIGEST": data["digest"],
    }
    for destination in (args.github_env, args.github_output):
        if destination:
            with destination.open("a", encoding="utf-8") as handle:
                for key, value in values.items():
                    handle.write(f"{key}={value}\n")
    print(json.dumps(values, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
