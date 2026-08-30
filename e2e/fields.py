#!/usr/bin/env python3
"""Assert the JSON on stdin carries the fields a client destructures.

Usage: fields.py [--item] FIELD...

  --item        check the first element of a JSON list instead of the value
  FIELD         a dotted path that must be present (branding.accent)
  FIELD:ts      the value must additionally parse as an RFC3339 timestamp
                (semantic parseability, never byte equality — the Rust and Go
                servers format sub-seconds differently)

Exits non-zero naming every missing field, so a contract break reads as a
sentence in the e2e transcript.
"""

import json
import re
import sys
from datetime import datetime


def parseable_timestamp(value: str) -> None:
    """RFC3339 with any sub-second precision — the servers emit nanoseconds,
    which JavaScript's Date accepts but an older fromisoformat does not."""
    trimmed = re.sub(r"(\.\d{1,6})\d*", r"\1", str(value).replace("Z", "+00:00"))
    datetime.fromisoformat(trimmed)


def main() -> int:
    args = sys.argv[1:]
    data = json.load(sys.stdin)
    if args and args[0] == "--item":
        args = args[1:]
        if not isinstance(data, list) or not data:
            print("FAIL: expected a non-empty JSON list", file=sys.stderr)
            return 1
        data = data[0]

    failures = []
    for spec in args:
        path, _, kind = spec.partition(":")
        node = data
        found = True
        for part in path.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                found = False
                break
        if not found:
            failures.append(f"missing field `{path}`")
            continue
        if kind == "ts" and node is not None:
            try:
                parseable_timestamp(node)
            except ValueError:
                failures.append(f"`{path}` is not a parseable timestamp: {node!r}")

    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
