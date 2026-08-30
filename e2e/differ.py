#!/usr/bin/env python3
"""Diff the Rust and Go servers' answers over identically seeded databases.

Usage: differ.py GO_BASE RUST_BASE

Runs the same write flow against each server (each on its own database), then
compares the parsed JSON of every read endpoint the dashboard uses. Volatile
values — timestamps, generated uuids, audit row numbers — are asserted
parseable and then masked, never byte-compared: the two servers format
sub-seconds differently and that is allowed by the gate.
"""

import json
import re
import sys
import urllib.request
from datetime import datetime

MASKED_TS = {"at", "granted_at", "expires_at", "created_at", "last_used", "since"}
MASKED_ID = {"granted-id"}  # grant ids are random uuids; secret ids are derived and must MATCH


def call(base, method, path, body=None):
    request = urllib.request.Request(base + path, method=method)
    data = None
    if body is not None:
        request.add_header("content-type", "application/json")
        data = json.dumps(body).encode()
    try:
        with urllib.request.urlopen(request, data) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw.strip() else None
    except urllib.error.HTTPError as error:
        raw = error.read()
        return error.code, json.loads(raw) if raw.strip() else None


def reveal(base, path):
    with urllib.request.urlopen(base + path) as response:
        return response.read().decode()


def seed(base):
    """The same writes the e2e script performs, replayed for this server."""
    status, created = call(base, "POST", "/api/secrets", {
        "store": "local", "name": "diff-creds",
        "value": '{"db_password":"hunter2","api_key":"abc"}', "note": "differential",
    })
    assert status == 200, (base, status, created)
    secret_id = created["id"]
    status, _ = call(base, "POST", f"/api/secrets/{secret_id}/versions",
                     {"value": '{"db_password":"hunter3","api_key":"abc"}', "note": "rotate"})
    assert status == 200
    status, _ = call(base, "POST", f"/api/secrets/{secret_id}/grants", {
        "subject_kind": "group", "subject": "SRE Team", "level": "read",
        "keys": ["db_password"], "days": 7, "note": "on call",
    })
    assert status == 200
    assert reveal(base, f"/api/secrets/{secret_id}/value?key=db_password") == "hunter3"
    return secret_id


def normalise(node, key=None):
    if isinstance(node, dict):
        out = {}
        for name, value in node.items():
            if name in MASKED_TS and value is not None:
                # Parseable, then masked: sub-second formatting differs
                # between the servers and byte equality is not the contract.
                trimmed = re.sub(r"(\.\d{1,6})\d*", r"\1", str(value).replace("Z", "+00:00"))
                datetime.fromisoformat(trimmed)
                out[name] = "<ts>"
            elif name == "id" and key == "grants":
                out[name] = "<uuid>"
            elif name == "id" and key == "audit":
                out[name] = "<n>"
            else:
                out[name] = normalise(value, key)
        return out
    if isinstance(node, list):
        return [normalise(item, key) for item in node]
    return node


def main() -> int:
    go_base, rust_base = sys.argv[1], sys.argv[2]
    go_id = seed(go_base)
    rust_id = seed(rust_base)
    if go_id != rust_id:
        print(f"DIFF: derived secret ids disagree: go={go_id} rust={rust_id}")
        return 1

    # The Go database carried the whole e2e's earlier traffic; the Rust one is
    # fresh. Unscoped lists are filtered down to what this probe seeded, so
    # the comparison is over identical rows.
    ours = lambda entry: entry.get("name") == "diff-creds" or entry.get("secret") == "diff-creds"
    reads = [
        ("me", "/api/me", None, None),
        ("stores", "/api/stores", None, None),
        ("secrets", "/api/secrets", None, ours),
        ("secret", f"/api/secrets/{go_id}", None, None),
        ("versions", f"/api/secrets/{go_id}/versions", None, None),
        ("grants", f"/api/secrets/{go_id}/grants", "grants", None),
        ("history", f"/api/secrets/{go_id}/history", "audit", None),
        ("audit", "/api/audit?limit=200", "audit", ours),
    ]
    broken = 0
    for name, path, mask, keep in reads:
        go_status, go_body = call(go_base, "GET", path)
        rust_status, rust_body = call(rust_base, "GET", path)
        if keep is not None:
            go_body = [entry for entry in go_body if keep(entry)]
            rust_body = [entry for entry in rust_body if keep(entry)]
        if go_status != rust_status:
            print(f"DIFF {name}: status go={go_status} rust={rust_status}")
            broken += 1
            continue
        go_norm = normalise(go_body, mask)
        rust_norm = normalise(rust_body, mask)
        if go_norm != rust_norm:
            print(f"DIFF {name}:")
            print("  go:   " + json.dumps(go_norm, sort_keys=True))
            print("  rust: " + json.dumps(rust_norm, sort_keys=True))
            broken += 1
        else:
            print(f"same {name}")

    # The raw reveal bodies, byte-equal (no timestamps in them).
    for path in (f"/api/secrets/{go_id}/value", f"/api/secrets/{go_id}/value?key=db_password"):
        go_text, rust_text = reveal(go_base, path), reveal(rust_base, path)
        if go_text != rust_text:
            print(f"DIFF reveal {path}: go={go_text!r} rust={rust_text!r}")
            broken += 1
        else:
            print(f"same reveal {path}")

    if broken:
        print(f"{broken} differential case(s) broke")
        return 1
    print("differential probe: no differences")
    return 0


if __name__ == "__main__":
    sys.exit(main())
