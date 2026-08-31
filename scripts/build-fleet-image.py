#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

from image_ref import require_digest_reference

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the Fleet child from an immutable Agent image")
    parser.add_argument("--agent-image", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    agent_image = require_digest_reference(args.agent_image)
    command = [
        "docker", "build",
        "--build-arg", f"AGENT_IMAGE={agent_image}",
        "--tag", args.tag,
        ".",
    ]
    if args.dry_run:
        print(" ".join(command))
        return 0
    return subprocess.run(command, cwd=ROOT, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
