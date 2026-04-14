#!/usr/bin/env python3
"""Parse raw OPA decision logs into a compact summary line format."""

import json
import sys


for raw in sys.stdin:
    raw = raw.strip()
    if not raw:
        continue

    try:
        data = json.loads(raw)
    except Exception:
        continue

    req = data.get("input", {}).get("attributes", {}).get("request", {}).get("http", {})
    headers = req.get("headers", {})

    method = req.get("method", "-")
    path = req.get("path", "-")
    role = headers.get("role", "-")
    firewall = headers.get("x-device-firewall", "-")
    decision = "ALLOW" if data.get("result") else "DENY"

    # Detect identity source: JWT (Bearer token) vs role header vs none
    auth = headers.get("authorization", "")
    if auth.startswith("Bearer "):
        identity_src = "JWT"
    elif role != "-":
        identity_src = "header"
    else:
        identity_src = "none"

    print(f"{decision:5} | {method:4} {path:24} | role={role:8} fw={firewall:8} | id={identity_src}")
