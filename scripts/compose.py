#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path

from image_ref import require_digest_reference

ROOT = Path(__file__).resolve().parents[1]

ALLOWED_COMMANDS = {
    "config",
    "down",
    "images",
    "logs",
    "ps",
    "pull",
    "restart",
    "start",
    "stop",
    "up",
}
FORBIDDEN_OPTIONS = {
    "-f",
    "--file",
    "--env-file",
    "-p",
    "--project-name",
    "--project-directory",
}


def validated_args(raw: list[str]) -> list[str]:
    args = list(raw)
    if args[:1] == ["--"]:
        args.pop(0)
    if not args:
        return ["config"]
    if args[0] not in ALLOWED_COMMANDS:
        raise ValueError(f"unsupported Compose command: {args[0]}")
    for item in args:
        option = item.split("=", 1)[0]
        if option in FORBIDDEN_OPTIONS:
            raise ValueError(f"Compose override is not allowed: {option}")
    return args


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the fixed synthetic Compose example with a digest-pinned Fleet image")
    parser.add_argument("compose_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    image = require_digest_reference(os.environ.get("HERMES_FLEET_IMAGE", ""))
    command = ["docker", "compose", "-f", str(ROOT / "compose.example.yaml"), *validated_args(args.compose_args)]
    return subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        env={**os.environ, "HERMES_FLEET_IMAGE": image},
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
