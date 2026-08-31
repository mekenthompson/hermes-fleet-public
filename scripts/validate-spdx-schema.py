#!/usr/bin/env python3
"""Validate one or more SPDX JSON documents against a pinned schema."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from jsonschema import Draft7Validator


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--schema", required=True, type=Path)
    parser.add_argument("documents", nargs="+", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    schema = json.loads(args.schema.read_text(encoding="utf-8"))
    Draft7Validator.check_schema(schema)
    validator = Draft7Validator(schema)
    failed = False
    for path in args.documents:
        document = json.loads(path.read_text(encoding="utf-8"))
        errors = sorted(validator.iter_errors(document), key=lambda error: tuple(str(item) for item in error.absolute_path))
        if errors:
            failed = True
            for error in errors:
                location = ".".join(str(item) for item in error.absolute_path) or "$"
                print(f"{path}:{location}: {error.message}")
        else:
            print(f"{path}: valid SPDX 2.3 JSON")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
