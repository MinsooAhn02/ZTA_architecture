import os
import json
import requests
from flask import Flask, request

app = Flask(__name__)

ROLE = os.getenv('ROLE', 'backend')
BACKEND_URL = os.getenv('BACKEND_URL', 'http://backend')

# ──────────────────────────────────────────────────
# Frontend: proxies all requests to Backend
# Backend: responds with resource data
# OPA ext-authz intercepts BEFORE reaching these handlers
# ──────────────────────────────────────────────────

@app.route('/')
def home():
    if ROLE == 'frontend':
        try:
            resp = requests.get(BACKEND_URL, timeout=5)
            return f"<h1>Frontend</h1><p>Backend replied: {resp.text}</p>"
        except Exception as e:
            return f"<h1>Frontend Error</h1><p>Could not reach backend: {e}</p>"
    else:
        return "Hello from Backend! (I am the secret data)"


# ──────────────────────────────────────────────────
# Scenario C & D: Context-Based / JWT Role Endpoints
# ──────────────────────────────────────────────────

@app.route('/api/data')
def api_data():
    """
    General read endpoint.
    ZTA Policy: accessible to role:user (GET) and role:admin.
    Blocked for: unauthenticated, POST without admin.
    """
    if ROLE == 'frontend':
        try:
            resp = requests.get(f"{BACKEND_URL}/api/data", timeout=5)
            return (
                f"<h2>[GET /api/data] General Data Access</h2>"
                f"<p><b>ZTA Decision:</b> Allowed (user/admin role, GET method)</p>"
                f"<p><b>Data:</b> {resp.text}</p>"
            )
        except Exception as e:
            return f"<h2>Frontend Error</h2><p>{e}</p>"
    else:
        return '{"resource": "sensor-data", "content": "temp=22C, humidity=45%", "classification": "internal"}'


@app.route('/api/admin')
def api_admin():
    """
    Admin-only endpoint.
    ZTA Policy: accessible ONLY to role:admin (header or JWT claim).
    Blocked for: role:user, unauthenticated.
    Demonstrates: path-based context-aware access control.
    """
    if ROLE == 'frontend':
        try:
            resp = requests.get(f"{BACKEND_URL}/api/admin", timeout=5)
            return (
                f"<h2>[GET /api/admin] Admin-Only Data</h2>"
                f"<p><b>ZTA Decision:</b> Allowed (admin role verified)</p>"
                f"<p><b>Data:</b> {resp.text}</p>"
            )
        except Exception as e:
            return f"<h2>Frontend Error</h2><p>{e}</p>"
    else:
        return '{"resource": "admin-config", "classification": "CONFIDENTIAL", "content": "system_key=zta-demo-key, policy_version=3"}'


@app.route('/api/write', methods=['POST'])
def api_write():
    """
    Write (state-change) endpoint.
    ZTA Policy: POST requires role:admin - write ops are privileged.
    Blocked for: role:user (GET-only), unauthenticated.
    Demonstrates: method-based context control (read vs write privilege separation).
    """
    if ROLE == 'frontend':
        try:
            payload = request.get_json(silent=True) or {}
            resp = requests.post(f"{BACKEND_URL}/api/write", json=payload, timeout=5)
            return (
                f"<h2>[POST /api/write] Write Operation</h2>"
                f"<p><b>ZTA Decision:</b> Allowed (admin role, write privilege confirmed)</p>"
                f"<p><b>Result:</b> {resp.text}</p>"
            )
        except Exception as e:
            return f"<h2>Frontend Error</h2><p>{e}</p>"
    else:
        body = request.get_json(silent=True) or {}
        return json.dumps({"result": "write-accepted", "committed": True, "payload": body})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
