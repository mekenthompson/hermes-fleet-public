#!/usr/bin/env python3
from __future__ import annotations

import sys

from image_ref import require_digest_reference


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: verify-agent-image-ref.py IMAGE@sha256:DIGEST", file=sys.stderr)
        return 2
    try:
        print(require_digest_reference(argv[1]))
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
