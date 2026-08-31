from __future__ import annotations

import re

PATTERN = re.compile(r"^[a-z0-9][a-z0-9._/-]*(?::[a-zA-Z0-9._-]+)?@sha256:[0-9a-f]{64}$")


def require_digest_reference(value: str) -> str:
    if not PATTERN.fullmatch(value):
        raise ValueError("expected an immutable image reference ending in @sha256:<64 lowercase hex>")
    return value
