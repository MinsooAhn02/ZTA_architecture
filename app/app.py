import os
import re
import uuid

import requests
from flask import Flask, Response, abort, g, jsonify, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024

ROLE = os.getenv("ROLE", "backend")
BACKEND_URL = os.getenv("BACKEND_URL", "http://backend")
TIMEOUT = (2, 5)
_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

BACKEND_RESPONSES = {
    "/": {"service": "backend", "status": "ready"},
    "/api/data": {"resource": "sensor-data", "content": "temp=22C, humidity=45%", "classification": "internal"},
    "/api/admin": {"resource": "admin-config", "classification": "CONFIDENTIAL", "content": "demo-only", "simulation": True},
}


def _request_id():
    if not hasattr(g, "request_id"):
        value = request.headers.get("X-Request-ID", "")
        g.request_id = value if _REQUEST_ID.fullmatch(value) else str(uuid.uuid4())
    return g.request_id


@app.after_request
def add_request_id(response):
    response.headers.setdefault("X-Request-ID", _request_id())
    return response


def _proxy(path, method="GET", payload=None):
    headers = {"X-Request-ID": _request_id()}
    for name in ("Authorization", "X-ZTA-Posture"):
        if value := request.headers.get(name):
            headers[name] = value
    url = f"{BACKEND_URL.rstrip('/')}{path}"
    try:
        if method == "POST":
            upstream = requests.post(url, json=payload, headers=headers, timeout=TIMEOUT, allow_redirects=False)
        else:
            upstream = requests.get(url, headers=headers, timeout=TIMEOUT, allow_redirects=False)
    except requests.Timeout:
        return jsonify(error="backend timeout", request_id=headers["X-Request-ID"]), 504
    except requests.RequestException:
        return jsonify(error="backend unavailable", request_id=headers["X-Request-ID"]), 502

    response = Response(upstream.content, status=upstream.status_code)
    response.headers["Content-Type"] = upstream.headers.get("Content-Type", "application/json")
    response.headers["X-Request-ID"] = headers["X-Request-ID"]
    return response


@app.get("/healthz")
def healthz():
    return jsonify(status="ok")


@app.get("/")
def home():
    if ROLE == "frontend":
        return _proxy("/")
    return jsonify(BACKEND_RESPONSES["/"])


@app.get("/api/data")
def api_data():
    if ROLE == "frontend":
        return _proxy("/api/data")
    return jsonify(BACKEND_RESPONSES["/api/data"])


@app.get("/api/admin")
def api_admin():
    if ROLE == "frontend":
        return _proxy("/api/admin")
    return jsonify(BACKEND_RESPONSES["/api/admin"])


@app.post("/api/write")
def api_write():
    if request.mimetype != "application/json":
        abort(415)
    payload = request.get_json(silent=False)
    if not isinstance(payload, dict):
        return jsonify(error="JSON object required"), 400
    if ROLE == "frontend":
        return _proxy("/api/write", "POST", payload)
    return jsonify(result="write-accepted", committed=False, payload=payload)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
