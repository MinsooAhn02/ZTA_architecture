import os
import json
import logging
import requests
from flask import Flask, request

app = Flask(__name__)
log = logging.getLogger(__name__)

ROLE = os.getenv('ROLE', 'backend')
BACKEND_URL = os.getenv('BACKEND_URL', 'http://backend')

# OPA ext-authz intercepts BEFORE reaching these handlers.
# Frontend proxies to Backend; Backend serves resource data.

BACKEND_RESPONSES = {
    '/': "Hello from Backend! (I am the secret data)",
    '/api/data': '{"resource":"sensor-data","content":"temp=22C, humidity=45%","classification":"internal"}',
    '/api/admin': '{"resource":"admin-config","classification":"CONFIDENTIAL","content":"system_key=zta-demo-key, policy_version=3"}',
}

FRONTEND_VIEWS = {
    '/':           ("<h1>Frontend</h1><p>Backend replied: {body}</p>", "GET"),
    '/api/data':   ("<h2>[GET /api/data]</h2><p>ZTA Decision: Allowed (user/admin, GET)</p><p>Data: {body}</p>", "GET"),
    '/api/admin':  ("<h2>[GET /api/admin]</h2><p>ZTA Decision: Allowed (admin verified)</p><p>Data: {body}</p>", "GET"),
}


def _proxy(path, method, json_body=None):
    """Frontend proxies to backend; return safe error message on failure (full detail in server log)."""
    url = f"{BACKEND_URL}{path}"
    try:
        if method == "POST":
            r = requests.post(url, json=json_body, timeout=5)
        else:
            r = requests.get(url, timeout=5)
        return r.text
    except Exception as e:
        log.warning("backend proxy %s %s failed: %s", method, path, e)
        return "<unavailable>"


@app.route('/')
def home():
    if ROLE != 'frontend':
        return BACKEND_RESPONSES['/']
    body = _proxy('/', 'GET')
    return FRONTEND_VIEWS['/'][0].format(body=body)


@app.route('/api/data')
def api_data():
    if ROLE != 'frontend':
        return BACKEND_RESPONSES['/api/data']
    body = _proxy('/api/data', 'GET')
    return FRONTEND_VIEWS['/api/data'][0].format(body=body)


@app.route('/api/admin')
def api_admin():
    if ROLE != 'frontend':
        return BACKEND_RESPONSES['/api/admin']
    body = _proxy('/api/admin', 'GET')
    return FRONTEND_VIEWS['/api/admin'][0].format(body=body)


@app.route('/api/write', methods=['POST'])
def api_write():
    payload = request.get_json(silent=True) or {}
    if ROLE != 'frontend':
        return json.dumps({"result": "write-accepted", "committed": True, "payload": payload})
    body = _proxy('/api/write', 'POST', json_body=payload)
    return f"<h2>[POST /api/write]</h2><p>ZTA Decision: Allowed (admin write)</p><p>Result: {body}</p>"


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    app.run(host='0.0.0.0', port=8080)
