"""Security scenario runner. All outcomes fail closed; unsupported setup is ERROR."""
from __future__ import annotations

import base64
import contextlib
import http.client
import importlib.util
import io
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError

import identity
from datetime import datetime, timezone

SCHEMA_VERSION = 1
REMOTE = (Path(__file__).with_name("remote_request.sh")).read_text()
DATA_BODY = "sensor-data"
MODE_FOR = {"sidecar": "sidecar", "mtls": "mtls", "jwt": "jwt", "opa-role": "opa-role", "strict": "strict"}


def _b64(value: str) -> str:
    return base64.b64encode(value.encode()).decode()


def request(runtime, url="http://frontend", path=None, method="GET", headers=None, body=None,
            client="curl-client", timeout=10):
    """Issue a request from a pod; only the base64 wire payload carries secrets."""
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
        raise ValueError("Unsupported HTTP method")
    if not url.startswith(("http://", "https://")) or any(c in url for c in "\r\n\0"):
        raise ValueError("Invalid request URL")
    header_items = list((headers or {}).items()) if hasattr(headers or {}, "items") else list(headers or ())
    if any(not isinstance(name, str) or not isinstance(value, str)
           or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
           or any(c in value for c in "\r\n\0") for name, value in header_items):
        raise ValueError("Invalid request header")
    request_id = secrets.token_hex(16)
    lines = [method, url if path is None else url.rstrip("/") + path,
             request_id, str(timeout), str(len(header_items))]
    lines.extend(_b64(f"{key}: {value}") for key, value in header_items)
    lines.append(_b64(body or ""))
    container = "fortio" if client == "fortio-client" else "curl"
    result = runtime.kubectl_process(
        "exec", "-i", f"deploy/{client}", "-c", container, "--", "sh", "-c", REMOTE,
        input="\n".join(lines) + "\n", check=False, timeout=timeout + 5,
    )
    output = result.stdout or ""
    match = re.search(r"__ZTA_RESULT__\t(\d{3})\t(\d+)\t([A-Za-z0-9+/=]*)", output)
    obs = {"kind": "error", "http_code": None, "curl_exit": None,
           "kubectl_exit": result.returncode, "body_ok": None,
           "body": "", "request_id": request_id}
    if result.returncode != 0:
        obs["kind"] = "error"
        return obs
    if not match:
        obs["kind"] = "error"
        return obs
    code, curl_exit, body64 = match.groups()
    obs["http_code"] = int(code)
    obs["curl_exit"] = int(curl_exit)
    try:
        obs["body"] = base64.b64decode(body64, validate=True).decode("utf-8", "replace")
    except (ValueError, UnicodeError):
        obs["kind"] = "error"
        return obs
    if curl_exit == "0" and code != "000":
        obs["kind"] = "http"
    elif curl_exit == "28":
        obs["kind"] = "timeout"
    else:
        obs["kind"] = "transport_denied" if code == "000" else "error"
    return obs


def _row(run_id, case_id, level, expected, observed, passed, evidence=()):
    mode = level if level in MODE_FOR else None
    category = "integration" if mode or level == "dashboard" else "unit" if level == "local-runner" else level
    observed = dict(observed)
    if mode:
        observed.setdefault("mode", mode)
    return {"schema_version": SCHEMA_VERSION, "run_id": run_id,
            "case_id": case_id, "level": category,
            "request_id": observed.get("request_id"),
            "status": "PASS" if passed else ("ERROR" if observed.get("kind") in {"error", "timeout", "transport_denied"} else "FAIL"),
            "expected": expected,
            "observed": {key: value for key, value in observed.items() if key != "body"},
            "evidence": list(evidence)}


def _unsupported(run_id, case_id, level, reason):
    return _row(run_id, case_id, level, {"fixture": "required"},
                {"kind": "error", "http_code": None, "curl_exit": None,
                 "kubectl_exit": None, "body_ok": None, "layer": level}, False,
                [f"not executed: {reason}"])


def _combine(run_id, case_id, level, parts, expected):
    statuses = [part["status"] for part in parts]
    failed = any(status != "PASS" for status in statuses)
    kinds = {part["observed"].get("kind") for part in parts}
    kind = ("error" if kinds & {"error", "timeout"} else
            "transport_denied" if "transport_denied" in kinds else "http")
    steps = [{"request_id": part["request_id"], "status": part["status"], 'level': part['level'],
              **part["observed"]} for part in parts]
    observed = {"kind": kind, "http_code": steps[0].get("http_code") if len(steps) == 1 else None,
                "curl_exit": steps[0].get("curl_exit") if len(steps) == 1 else None,
                "kubectl_exit": steps[0].get("kubectl_exit") if len(steps) == 1 else None,
                "body_ok": all(step['body_ok'] is True for step in steps if step.get('body_ok') is not None),
                "layer": level, "steps": steps}
    mode = level if level in MODE_FOR else None
    if mode:
        observed["mode"] = mode
    return {"schema_version": SCHEMA_VERSION, "run_id": run_id, "case_id": case_id,
            "level": "integration" if mode else level,
            "request_id": steps[0].get("request_id") if steps else None,
            "status": "ERROR" if "ERROR" in statuses else "FAIL" if failed else "PASS",
            "expected": expected, "observed": observed,
            "evidence": [item for part in parts for item in part["evidence"]]}


def _token_headers(token, extra=None):
    pairs = [("Authorization", f"Bearer {token}")] if token else []
    pairs.extend(list((extra or {}).items()) if hasattr(extra or {}, "items") else list(extra or ()))
    return pairs


def _activate_mode(runtime, mode):
    if getattr(runtime, 'config_ready', True) is False:
        runtime.wait_ready()
    if runtime.opa_query("data.jwt_trust.mode") != mode or runtime.mode != mode:
        runtime.apply_mode(mode)


def _check(runtime, run_id, case_id, level, path, code, token=None, method="GET",
           body=None, body_text=None, headers=None, client="curl-client", url="http://frontend"):
    try:
        _activate_mode(runtime, MODE_FOR[level])
        obs = request(runtime, url, path, method, _token_headers(token, headers), body, client)
    except Exception as exc:
        return _row(run_id, case_id, level, {"http_code": code},
                    {"kind": "error", "http_code": None, "curl_exit": None,
                     "kubectl_exit": None, "body_ok": None, "layer": level}, False,
                    [f"runner exception: {type(exc).__name__}"])
    body_ok = body_text is None or body_text in obs.get("body", "")
    obs["body_ok"] = body_ok
    obs["layer"] = level
    passed = obs["kind"] == "http" and obs["http_code"] in (code if isinstance(code, list) else [code]) and body_ok
    if obs['kind'] == 'http' and obs['http_code'] >= 400:
        event = _envoy_line(runtime, 'backend' if url.startswith('http://backend') else 'frontend', obs['request_id'])
        if event:
            obs['deny_reason'] = event.get('response_code_details')
            reason = str(obs['deny_reason'])
            if 'ext_authz_error' in reason:
                obs['kind'] = 'error'
                passed = False
            obs['observed_layer'] = 'jwt' if 'jwt' in reason.lower() else 'opa' if 'ext_authz_denied' in reason else 'workload-authorization' if 'rbac' in reason else 'application'
        else:
            obs['kind'] = 'error'
            passed = False
    return _row(run_id, case_id, level, {"http_code": code, "body_contains": body_text,
                                        "layer": level}, obs, passed)


def _alter_payload(token, mutate):
    try:
        header, payload, signature = token.split(".")
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        data = mutate(data)
        changed = base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).decode().rstrip("=")
        return f"{header}.{changed}.{signature}"
    except (ValueError, TypeError, json.JSONDecodeError):
        return "invalid.token.structure"


def _ttl_revocation(runtime, run_id):
    try:
        issued = identity.issue_tokens(runtime, username="admin-user")
        if not issued.get("refresh_access"):
            raise RuntimeError("identity provider did not issue refresh token")
        body = urlencode({"client_id": "zta-app", "client_secret": identity.CLIENTS["zta-app"]["secret"],
                         "refresh_token": issued["refresh_access"]}).encode()
        req = Request(runtime.issuer + "/protocol/openid-connect/logout", data=body,
                      headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
        with urlopen(req, timeout=10) as response:
            if response.status not in (200, 204):
                raise RuntimeError("unexpected logout response")
        refresh = Request(runtime.issuer + '/protocol/openid-connect/token',
                          data=urlencode({'grant_type': 'refresh_token', 'client_id': 'zta-app',
                          'client_secret': identity.CLIENTS['zta-app']['secret'],
                          'refresh_token': issued['refresh_access']}).encode())
        try:
            with urlopen(refresh, timeout=10):
                raise RuntimeError('Refresh was accepted after logout')
        except HTTPError as error:
            if error.code != 400 or json.loads(error.read()).get('error') != 'invalid_grant':
                raise RuntimeError('Logout refresh rejection was not invalid_grant')
        row = _check(runtime, run_id, "S10", "strict", "/api/data", 200,
                     issued["access"], body_text=DATA_BODY, headers={'X-ZTA-Posture': issued['posture']})
        row["expected"] = {"logout_revokes_refresh_session": True,
                           "access_token_before_expiry": "remains valid under TTL-only revocation"}
        row["evidence"].append("refresh session logout completed; access-token reuse tested before expiry")
        return row
    except Exception as exc:
        return _row(run_id, "S10", "strict",
                    {"access_token_before_expiry": "remains valid under TTL-only revocation"},
                    {"kind": "error", "http_code": None, "curl_exit": None,
                     "kubectl_exit": None, "body_ok": None, "layer": "strict"}, False,
                    [f"logout/reuse check failed: {type(exc).__name__}"])


def _key_rotation(runtime, run_id):
    try:
        old = identity.test_tokens(runtime, "rotation_old", "admin-user")
        _activate_mode(runtime, "opa-role")
        with identity.rotate_keys(runtime, overlap_seconds=360) as rotation:
            runtime.sync_jwks()
            overlap_keys = {key.get("kid") for key in runtime.jwks.get("keys", [])}
            old_kid = json.loads(base64.urlsafe_b64decode(
                old["access"].split(".")[0] + "=" * (-len(old["access"].split(".")[0]) % 4))).get("kid")
            old_during = request(runtime, path="/api/admin", headers=_token_headers(old["access"]))
            new = identity.issue_tokens(runtime, username="admin-user")
            new_before = request(runtime, path="/api/admin", headers=_token_headers(new["access"]))
            rotation.retire()
            runtime.sync_jwks()
            retired_keys = {key.get("kid") for key in runtime.jwks.get("keys", [])}
            old_after = request(runtime, path="/api/admin", headers=_token_headers(old["access"]))
            new_after_tokens = identity.issue_tokens(runtime, username="admin-user")
            new_after_kid = json.loads(base64.urlsafe_b64decode(
                new_after_tokens["access"].split(".")[0] + "=" * (-len(new_after_tokens["access"].split(".")[0]) % 4))).get("kid")
            new_after = request(runtime, path="/api/admin", headers=_token_headers(new_after_tokens["access"]))
            old_retired = (bool(rotation.old_key_ids)
                           and set(rotation.old_key_ids) <= set(rotation.retired_key_ids)
                           and not (set(rotation.old_key_ids) & retired_keys))
            old_rejected = old_after["kind"] == "http" and old_after["http_code"] in (401, 403)
            expiry = json.loads(base64.urlsafe_b64decode(old['access'].split('.')[1] + '=' * (-len(old['access'].split('.')[1]) % 4)))['exp']
            old_remaining = expiry - time.time()
            passed = (old_kid in overlap_keys and old_during["kind"] == "http" and old_during["http_code"] == 200
                      and new_before["kind"] == "http" and new_before["http_code"] == 200
                      and old_rejected and new_after_kid in set(rotation.new_key_ids)
                      and new_after["kind"] == "http"
                      and new_after["http_code"] == 200
                      and old_retired and bool(rotation.new_key_ids) and old_remaining > 0 and rotation.retired_after_seconds >= 360)
            obs = {"kind": "http" if old_after["kind"] == "http" else old_after["kind"],
                   "http_code": old_after.get("http_code"), "curl_exit": old_after.get("curl_exit"),
                   "kubectl_exit": old_after.get("kubectl_exit"), "body_ok": None, "layer": "key-rotation",
                   "old_key_retired": old_retired, "old_key_present_during_overlap": bool(set(rotation.old_key_ids) & overlap_keys),
                   "old_token_kid": old_kid, "new_token_kid": new_after_kid,
                   'old_token_remaining_seconds_at_retirement': old_remaining,
                   'overlap_seconds_measured': rotation.retired_after_seconds,
                   "steps": [
                       {"request_id": old_during["request_id"], "http_code": old_during.get("http_code")},
                       {"request_id": new_before["request_id"], "http_code": new_before["http_code"]},
                       {"request_id": old_after["request_id"], "http_code": old_after.get("http_code")},
                       {"request_id": new_after["request_id"], "http_code": new_after.get("http_code")} ]}
            row = _row(run_id, "S09", "opa-role", {"overlap_seconds": 360,
                        "old_key_during_overlap": 200, "new_key": 200,
                        "old_kid_removed_after_overlap": True}, obs, passed,
                        ["old signer was accepted during overlap and its KID disappeared after retirement"])
        runtime.apply_mode("strict")
        runtime.wait_ready()
        return row
    except Exception as exc:
        try:
            runtime.apply_mode("strict")
            runtime.wait_ready()
        except Exception:
            pass
        return _row(run_id, "S09", "strict", {"new_key": 200, "retired_old_key": 401},
                    {"kind": "error", "http_code": None, "curl_exit": None, "kubectl_exit": None,
                     "body_ok": None, "layer": "strict"}, False,
                    [f"key rotation/recovery failed: {type(exc).__name__}"])


def _secret_log_check(runtime, run_id):
    try:
        issued = identity.issue_tokens(runtime, username="admin-user")
        _activate_mode(runtime, "strict")
        result = request(runtime, path="/api/data", headers=_token_headers(
            issued["access"], {"X-ZTA-Posture": issued["posture"]}))
        logs = "\n".join((
            runtime.kubectl("logs", "deploy/opa", "-c", "opa", "--since=120s", "--tail=300", check=False),
            runtime.kubectl("logs", "deploy/frontend", "-c", "istio-proxy", "--since=120s", "--tail=300", check=False),
        ))
        leaked = any(token and token in logs for token in (issued["access"], issued["posture"]))
        body_ok = DATA_BODY in result.get("body", "")
        result.update({"body_ok": body_ok, "layer": "strict"})
        passed = result["kind"] == "http" and result["http_code"] == 200 and body_ok and not leaked
        return _row(run_id, "S30", "strict", {"http_code": 200, "logs_exclude_tokens": True},
                    result, passed, ["OPA/Envoy log scan performed in memory; raw logs and credentials were not saved",
                    "no issued access/posture token found" if not leaked else "issued token detected in runtime logs"])
    except Exception as exc:
        return _row(run_id, "S30", "strict", {"logs_exclude_tokens": True},
                    {"kind": "error", "http_code": None, "curl_exit": None,
                     "kubectl_exit": None, "body_ok": None, "layer": "strict"}, False,
                    [f"secret-log check failed: {type(exc).__name__}"])


def _opa_management_boundary(runtime, run_id):
    probe = 'suite_probe_' + run_id.replace('-', '')
    _activate_mode(runtime, 'strict')
    issued = identity.issue_tokens(runtime, username='admin-user')
    headers = _token_headers(issued['access'], {'X-ZTA-Posture': issued['posture']})
    before = request(runtime, path='/api/data', headers=headers)
    steps = []
    for method in ('GET', 'PUT'):
        snapshot = runtime.network_drop_snapshot('opa')
        started = time.time()
        blocked = request(runtime, 'http://' + snapshot['pod_ip'] + ':8181', '/v1/data/' + probe,
                          method=method, headers={'Content-Type': 'application/json'},
                          body=json.dumps({'test': run_id}) if method == 'PUT' else None, timeout=18)
        ended = time.time()
        after = runtime.network_drop_snapshot('opa')
        blocked.update(body_ok=None, method=method, drop_before=snapshot, drop_after=after,
                       window_utc=[datetime.fromtimestamp(t, timezone.utc).isoformat() for t in (started, ended)])
        proof = (blocked['kind'] == 'transport_denied' and blocked['kubectl_exit'] == 0
                 and snapshot['pod_ip'] == after['pod_ip'] and snapshot['rule_sha256'] == after['rule_sha256']
                 and after['drop_packets'] > snapshot['drop_packets'])
        if not proof:
            blocked['kind'] = 'error'
        steps.append(_row(run_id, 'S16-' + method, 'strict', {'management_api': 'network denied'},
                          blocked, proof, ['Calico OPA ingress DROP counter increased in the isolated request window',
                                           'TCP denial has no HTTP request ID at destination; source-side request ID and time window retained']))
    fresh = identity.issue_tokens(runtime, username='admin-user')
    recovered = request(runtime, path='/api/data', headers=_token_headers(fresh['access'], {'X-ZTA-Posture': fresh['posture']}))
    unchanged = runtime.opa_query('data.' + probe) is None
    controls = before['http_code'] == recovered['http_code'] == 200 and DATA_BODY in recovered['body'] and unchanged
    steps.append(_row(run_id, 'S16-controls', 'strict', {'opa_healthy': True, 'probe_data_absent': True},
                      {'kind': 'http', 'http_code': recovered['http_code'], 'body_ok': controls,
                       'request_id': recovered['request_id'], 'probe_data_absent': unchanged}, controls))
    return _combine(run_id, 'S16', 'strict', steps, {'unauthorized_read_write': 'Calico denied; OPA remains healthy'})


def _request_row(run_id, case_id, level, result, expected, passed, evidence=()):
    body = result.get("body", "")
    observed = {key: value for key, value in result.items() if key != "body"}
    observed["layer"] = level
    observed["body_ok"] = bool(expected.get("body_contains") in body) if expected.get("body_contains") else None
    return _row(run_id, case_id, level, expected, observed, passed, evidence)


def _envoy_line(runtime, deployment, request_id):
    for attempt in range(5):
        raw = runtime.kubectl("logs", f"deploy/{deployment}", "-c", "istio-proxy",
                              "--since=120s", "--tail=500", check=False)
        for line in str(raw).splitlines():
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if item.get("request_id") == request_id:
                return item
        if attempt < 4:
            time.sleep(0.5)
    return None


def _opa_outage(runtime, run_id):
    issued = identity.issue_tokens(runtime, username="admin-user")
    headers = _token_headers(issued["access"], {"X-ZTA-Posture": issued["posture"]})
    try:
        _activate_mode(runtime, "strict")
        before = request(runtime, path="/api/data", headers=headers)
        with runtime.fault("opa") as injected_fault:
            denied = request(runtime, path="/api/data", headers=headers)
            envoy = _envoy_line(runtime, "frontend", denied["request_id"])
            error_detail = " ".join(str(envoy.get(key, "")) for key in
                                    ("response_code_details", "upstream_transport_failure", "response_flags")) if envoy else ""
            failed_closed = (denied["kind"] == "http" and denied["http_code"] in (403, 503)
                             and "sensor-data" not in denied.get("body", "")
                             and bool(envoy) and "ext_authz_error" in error_detail)
        after = request(runtime, path="/api/data", headers=headers)
        passed = (before["kind"] == "http" and before["http_code"] == 200
                  and failed_closed and after["kind"] == "http" and after["http_code"] == 200
                  and DATA_BODY in after.get("body", ""))
        obs = {"kind": "http" if denied["kind"] == "http" else denied["kind"],
               "http_code": denied.get("http_code"), "curl_exit": denied.get("curl_exit"),
               "kubectl_exit": denied.get("kubectl_exit"), "body_ok": "sensor-data" not in denied.get("body", ""),
               "layer": "strict", 'fault': injected_fault, "steps": [
                   {"request_id": before["request_id"], "http_code": before["http_code"], "body_ok": DATA_BODY in before.get("body", "")},
                   {"request_id": denied["request_id"], "http_code": denied.get("http_code"), "ext_authz_error": bool(envoy), "body_ok": "sensor-data" not in denied.get("body", "")},
                   {"request_id": after["request_id"], "http_code": after["http_code"], "body_ok": DATA_BODY in after.get("body", "")},
               ]}
        return _row(run_id, "S17", "strict", {"opa_unavailable": "deny without backend data; recover after restart"},
                    obs, passed, ["matched frontend Envoy request_id and ext_authz_error" if failed_closed
                                  else "OPA outage denial lacks correlated fail-closed evidence"])
    except Exception as exc:
        return _row(run_id, "S17", "strict", {"opa_unavailable": "deny without backend data"},
                    {"kind": "error", "http_code": None, "curl_exit": None, "kubectl_exit": None,
                     "body_ok": None, "layer": "strict"}, False,
                    [f"OPA outage/recovery failed: {type(exc).__name__}"])


def _backend_failure(runtime, run_id):
    viewer = identity.issue_tokens(runtime, username="viewer-user")
    admin = identity.issue_tokens(runtime, username="admin-user")
    try:
        _activate_mode(runtime, "strict")
        denied = request(runtime, path="/api/admin", headers=_token_headers(
            viewer["access"], {"X-ZTA-Posture": viewer["posture"]}))
        before = request(runtime, path="/api/data", headers=_token_headers(
            admin["access"], {"X-ZTA-Posture": admin["posture"]}))
        with runtime.fault("backend") as injected_fault:
            failed = request(runtime, path="/api/data", headers=_token_headers(
                admin["access"], {"X-ZTA-Posture": admin["posture"]}))
            envoy = _envoy_line(runtime, "frontend", failed["request_id"])
        after_tokens = identity.issue_tokens(runtime, username="admin-user")
        after = request(runtime, path="/api/data", headers=_token_headers(
            after_tokens["access"], {"X-ZTA-Posture": after_tokens["posture"]}))
        failure_code = failed.get("http_code")
        upstream_error = (failed["kind"] == "http" and failure_code in (502, 503)
                          and "sensor-data" not in failed.get("body", "") and bool(envoy))
        passed = (denied["kind"] == "http" and denied["http_code"] == 403
                  and before["http_code"] == 200 and upstream_error
                  and after["kind"] == "http" and after["http_code"] == 200
                  and DATA_BODY in after.get("body", ""))
        return _row(run_id, "S22", "strict", {"viewer_admin": 403, "backend_unavailable": [502, 503],
                    "recovery": 200}, {"kind": "http" if failed["kind"] == "http" else failed["kind"],
                    "http_code": failure_code, "curl_exit": failed.get("curl_exit"),
                    "kubectl_exit": failed.get("kubectl_exit"), "body_ok": "sensor-data" not in failed.get("body", ""),
                    "layer": "strict", 'fault': injected_fault, 'unit_evidence': getattr(runtime, 'app_unit_evidence', None), "steps": [
                        {"request_id": denied["request_id"], "http_code": denied["http_code"]},
                        {"request_id": before["request_id"], "http_code": before["http_code"]},
                        {"request_id": failed["request_id"], "http_code": failure_code,
                         "envoy_logged": bool(envoy)},
                        {"request_id": after["request_id"], "http_code": after["http_code"]},
                    ]}, passed, ["backend down surfaced as non-200 and recovered after restoration"])
    except Exception as exc:
        return _row(run_id, "S22", "strict", {"backend_failure_is_not_200": True},
                    {"kind": "error", "http_code": None, "curl_exit": None, "kubectl_exit": None,
                     "body_ok": None, "layer": "strict"}, False,
                    [f"backend failure/recovery check failed: {type(exc).__name__}"])


def _idp_outage(runtime, run_id):
    issued = identity.issue_tokens(runtime, username="admin-user")
    headers = _token_headers(issued["access"], {"X-ZTA-Posture": issued["posture"]})
    try:
        _activate_mode(runtime, "strict")
        before = request(runtime, path="/api/data", headers=headers)
        with runtime.fault("keycloak") as injected_fault:
            cached = request(runtime, path="/api/data", headers=headers)
            try:
                identity.issue_tokens(runtime, username="admin-user")
                new_issue_failed = False
            except Exception:
                new_issue_failed = True
        runtime.sync_jwks()
        fresh = identity.issue_tokens(runtime, username="admin-user")
        after = request(runtime, path="/api/data", headers=_token_headers(
            fresh["access"], {"X-ZTA-Posture": fresh["posture"]}))
        passed = all(step["kind"] == "http" and step["http_code"] == 200
                     and DATA_BODY in step.get("body", "") for step in (before, cached, after)) and new_issue_failed
        obs = {"kind": "http" if cached["kind"] == "http" else cached["kind"],
               "http_code": cached.get("http_code"), "curl_exit": cached.get("curl_exit"),
               "kubectl_exit": cached.get("kubectl_exit"), "body_ok": DATA_BODY in cached.get("body", ""),
               "layer": "strict", 'fault': injected_fault, "new_token_issue_failed": new_issue_failed,
               "steps": [{"request_id": step["request_id"], "http_code": step.get("http_code"),
                          "body_ok": DATA_BODY in step.get("body", "")} for step in (before, cached, after)]}
        return _row(run_id, "S24", "strict", {"cached_jwks_token": 200,
                    "new_issuance_during_idp_outage": "fails", "recovered_issuance": 200}, obs, passed,
                    ["cached-token validation continued while IdP was down; JWKS synced after recovery"])
    except Exception as exc:
        return _row(run_id, "S24", "strict", {"cached_jwks_token": 200, "recovered_issuance": 200},
                    {"kind": "error", "http_code": None, "curl_exit": None, "kubectl_exit": None,
                     "body_ok": None, "layer": "strict"}, False,
                    [f"IdP outage/recovery check failed: {type(exc).__name__}"])


def _policy_transition(runtime, run_id):
    issued = identity.issue_tokens(runtime, username="viewer-user")
    headers = _token_headers(issued["access"])
    row = None
    try:
        _activate_mode(runtime, "strict")
        before = request(runtime, path="/api/data", headers=headers)
        started = time.monotonic()
        runtime.apply_mode("opa-role")
        open_ms = round((time.monotonic() - started) * 1000, 1)
        allowed = request(runtime, path="/api/data", headers=headers)
        started = time.monotonic()
        runtime.apply_mode("strict")
        deny_ms = round((time.monotonic() - started) * 1000, 1)
        denied = request(runtime, path="/api/data", headers=headers)
        passed = (before["kind"] == "http" and before["http_code"] == 403
                  and allowed["kind"] == "http" and allowed["http_code"] == 200
                  and DATA_BODY in allowed.get("body", "")
                  and denied["kind"] == "http" and denied["http_code"] == 403)
        obs = {"kind": "http" if denied["kind"] == "http" else denied["kind"],
               "http_code": denied.get("http_code"), "curl_exit": denied.get("curl_exit"),
               "kubectl_exit": denied.get("kubectl_exit"), "body_ok": True, "layer": "strict",
               "mode_change_ms": {"opa_role": open_ms, "strict": deny_ms},
               "steps": [{"request_id": result["request_id"], "http_code": result.get("http_code"),
                          "body_ok": DATA_BODY in result.get("body", "")} for result in (before, allowed, denied)]}
        row = _row(run_id, "S18", "strict", {"strict_without_posture": 403,
                    "opa_role_without_posture": 200, "strict_restored": 403}, obs, passed,
                    ["each mode change waited for expected Envoy proxy configuration ACKs"])
    except Exception as exc:
        row = _row(run_id, "S18", "strict", {"transition": "deny after strict restore"},
                    {"kind": "error", "http_code": None, "curl_exit": None, "kubectl_exit": None,
                     "body_ok": None, "layer": "strict"}, False,
                    [f"policy transition check failed: {type(exc).__name__}"])
    finally:
        try:
            runtime.apply_mode("strict")
        except Exception as exc:
            row["status"] = "ERROR"
            row["observed"]["kind"] = "error"
            row["observed"]["restore_error"] = type(exc).__name__
            row["evidence"].append("strict policy restoration failed")
    return row


def _dashboard_module():
    path = Path(__file__).resolve().parents[1] / "visualizer/server.py"
    spec = importlib.util.spec_from_file_location("zta_v2_dashboard_server", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _dashboard_post(port, origin, csrf):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request("POST", "/api/run/test-all", headers={
            "Host": "localhost:5002", "Origin": origin, "X-ZTA-CSRF": csrf})
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


def _dashboard_checks(run_id):
    module = _dashboard_module()
    server = ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    port = server.server_address[1]
    try:
        origin_code = _dashboard_post(port, "https://attacker.invalid", module.CSRF)
        with tempfile.TemporaryDirectory() as tempdir:
            fixture = Path(tempdir) / "run" / "results.jsonl"
            fixture.parent.mkdir()
            (fixture.parent / 'manifest.json').write_text(json.dumps({'status': 'FAIL', 'started_at': '2026-10-06T00:00:00+00:00'}), encoding='utf-8')
            fixture.write_text(json.dumps({"case_id": "S01", "expected": {"claim": "<script>alert(1)</script>"},
                                           "observed": {"http_code": "<img src=x onerror=alert(1)>", "kind": "http"},
                                           "status": "FAIL"}) + "\n", encoding="utf-8")
            module.EVIDENCE = Path(tempdir)
            rendered = module.result_rows()["S01"]
            xss_safe = "<script" not in rendered["expect"] and "<img" not in rendered["result"]
        held_fd = None
        inherited_lock = os.environ.pop("ZTA_LOCK_FD", None)
        try:
            try:
                held_fd = module.acquire_lock()
            except module.RuntimeError:
                pass
            conflict_code = _dashboard_post(port, "http://localhost:5002", module.CSRF)
        finally:
            if held_fd is not None:
                os.close(held_fd)
            if inherited_lock is not None:
                os.environ["ZTA_LOCK_FD"] = inherited_lock
        return [
            _row(run_id, "S27", "dashboard", {"foreign_origin": 403},
                 {"kind": "http", "http_code": origin_code, "curl_exit": None,
                  "kubectl_exit": None, "body_ok": origin_code == 403, "layer": "dashboard"},
                 origin_code == 403, ["foreign Origin POST was rejected before dispatch"]),
            _row(run_id, "S28", "dashboard", {"untrusted_result_text_is_escaped": True},
                 {"kind": "http", "http_code": 200, "curl_exit": None,
                  "kubectl_exit": None, "body_ok": xss_safe, "layer": "dashboard"},
                 xss_safe, ["hostile evidence values were HTML-escaped before DOM rendering"]),
            _row(run_id, "S29", "dashboard", {"concurrent_run": 409},
                 {"kind": "http", "http_code": conflict_code, "curl_exit": None,
                  "kubectl_exit": None, "body_ok": conflict_code == 409, "layer": "dashboard"},
                 conflict_code == 409, ["second dashboard run was blocked by the shared file lock"]),
        ]
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def _performance_failure_lifecycle(run_id):
    import performance
    import zta as cli
    from unittest.mock import patch
    class FakeRuntime:
        mode = 'opa-role'
        def manifest(self): return {'profile': 'test-only'}
        def live_contract(self): return {'fixture': 'unit lifecycle test'}
        def apply_mode(self, mode): self.mode = mode
    steps = []
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        latest = directory / 'latest-perf.json'
        latest.write_text('{"run_id":"previous-valid"}\n')
        for condition in ('mixed-status', 'environment-error', 'cancel'):
            runtime = FakeRuntime()
            identifier = str(uuid.uuid4())
            sample = {'schema_version':1,'run_id':identifier,'case_id':'S32','level':'experiment',
                      'request_id':None,'status':'FAIL' if condition == 'mixed-status' else 'ERROR',
                      'expected':{'all_200':True},'observed':{'kind':'http','status_histogram':{'200':99,'503':1}},'evidence':[]}
            def fixture(_runtime, _directory):
                if condition == 'cancel': raise KeyboardInterrupt()
                return [sample]
            with patch.object(cli, 'EVIDENCE', directory), patch.object(performance, 'run_performance', fixture), patch.object(cli, 'canaries', lambda _r: None), contextlib.redirect_stdout(io.StringIO()):
                try: code = cli.execute_results(runtime, 'perf', identifier)
                except KeyboardInterrupt: code = 2
            manifest = json.loads((directory / identifier / 'manifest.json').read_text())
            expected = 'FAIL' if condition == 'mixed-status' else 'ERROR'
            unchanged = latest.read_text() == '{"run_id":"previous-valid"}\n'
            ok = code == (1 if expected == 'FAIL' else 2) and manifest['status'] == expected and manifest['restored_strict'] and runtime.mode == 'strict' and unchanged
            steps.append({'condition':condition,'process_exit':code,'manifest_status':manifest['status'],
                          'restored_strict':manifest['restored_strict'],'latest_unchanged':unchanged,'passed':ok})
    passed = all(s['passed'] for s in steps)
    return _row(run_id,'S31','local-runner',{'failure_error_cancel':'restore strict without publishing latest'},
                {'kind':'http' if passed else 'error','http_code':None,'body_ok':passed,'steps':steps},passed,
                ['unit-level fault injection executes the shared CLI lifecycle for mixed responses, environment failure, and cancellation'])


def _readiness_timeout_check(run_id):
    if "yaml" not in sys.modules:
        sys.modules["yaml"] = type("YamlStub", (), {})()
    import runtime as runtime_module

    class Clock:
        now = 0
        @classmethod
        def monotonic(cls): return cls.now
        @classmethod
        def sleep(cls, _seconds): cls.now = 121

    required = {"frontend", "backend", "keycloak", "opa", "curl-client", "rogue-client",
                "wrongsa-client", "frontend-probe", "fortio-client"}

    class FakeRuntime:
        istioctl = "istioctl"
        namespace = "zta-v2"
        def __init__(self, condition): self.condition = condition
        def kubectl(self, *args, **kwargs):
            if args[:2] == ("get", "deployments"):
                return {"items": [{"metadata": {"name": name}, "spec": {'replicas': 1}} for name in required]}
            if args[:2] == ("get", "pods"):
                return {"items": [{"metadata": {"name": name + '-pod', "namespace": "zta-v2", 'labels': {'app':name}},
                                   "spec": {"containers": [{'name': 'app'}] if self.condition == 'missing-sidecar' and name == 'frontend' else [{"name": "istio-proxy"}]}} for name in required - {'opa','rogue-client'}]}
            return ""
        def run(self, argv, **kwargs):
            rows = [{'proxy': name + '-pod.zta-v2', 'cluster_sent':'v2', 'cluster_acked':'v1'} for name in required - {'opa','rogue-client'}] if self.condition == 'nack' else []
            return subprocess.CompletedProcess(argv, 0, json.dumps(rows), "")

    original_time = runtime_module.time
    try:
        runtime_module.time = Clock
        checks = []
        for condition in ('missing-proxy-status', 'nack', 'missing-sidecar'):
            Clock.now = 0
            try:
                runtime_module.Runtime.wait_ready(FakeRuntime(condition))
                checks.append({'condition':condition, 'rejected':False})
            except runtime_module.RuntimeError as exc:
                checks.append({'condition':condition, 'rejected': 'acknowledgement' in str(exc).lower() or 'proxy missing' in str(exc).lower()})
        rejected = all(c['rejected'] for c in checks)
    finally:
        runtime_module.time = original_time
    return _row(run_id, "S33", "local-runner", {"unsynced_required_proxy": "abort run"},
                {"kind": "error" if rejected else "http", "http_code": None,
                 "curl_exit": None, "kubectl_exit": None, "body_ok": rejected,
                 "layer": "local-runner", 'steps':checks}, rejected,
                ["missing Envoy ACK caused readiness to fail before test/perf execution"])


def _live_readiness_failure(runtime, run_id):
    from runtime import RuntimeError
    _activate_mode(runtime, 'strict')
    with runtime.fault('frontend-probe') as injected:
        try:
            runtime.wait_ready()
            rejected = False
        except RuntimeError as error:
            rejected = 'scaled to zero' in str(error)
    tokens = identity.issue_tokens(runtime, 'admin-user')
    control = request(runtime, path='/api/data', headers=_token_headers(tokens['access'], {'X-ZTA-Posture':tokens['posture']}))
    healthy = control['http_code'] == 200 and DATA_BODY in control['body']
    live = _row(run_id, 'S33-live-missing-proxy', 'strict', {'required_proxy_absent':'readiness rejects before test/perf'},
                {'kind':'http' if rejected and healthy else 'error','http_code':control['http_code'],'request_id':control['request_id'],
                 'body_ok':healthy,'fault':injected,'gate_rejected':rejected}, rejected and healthy,
                ['required frontend-probe workload removed in the real v2 cluster; shared readiness gate rejected it; rollout and normal canary restored'])
    return _combine(run_id, 'S33', 'strict', [live, _readiness_timeout_check(run_id)],
                    {'missing_required_workload':'live gate failure', 'mesh_sync_timeout':'unit clock fixture'})


def _restart_recovery(runtime, run_id):
    try:
        _activate_mode(runtime, "strict")
        before_tokens = identity.issue_tokens(runtime, username="admin-user")
        before = request(runtime, path="/api/data", headers=_token_headers(
            before_tokens["access"], {"X-ZTA-Posture": before_tokens["posture"]}))
        runtime.kubectl("rollout", "restart", "deployment/frontend")
        runtime.kubectl("rollout", "status", "deployment/frontend", "--timeout=300s", timeout=310)
        runtime.kubectl("rollout", "restart", "deployment/opa")
        runtime.kubectl("rollout", "status", "deployment/opa", "--timeout=300s", timeout=310)
        runtime.wait_ready()
        after_tokens = identity.issue_tokens(runtime, username="admin-user")
        after = request(runtime, path="/api/data", headers=_token_headers(
            after_tokens["access"], {"X-ZTA-Posture": after_tokens["posture"]}))
        viewer = identity.issue_tokens(runtime, username="viewer-user")
        denied = request(runtime, path="/api/admin", headers=_token_headers(
            viewer["access"], {"X-ZTA-Posture": viewer["posture"]}))
        passed = (before["http_code"] == 200 and after["kind"] == "http" and after["http_code"] == 200
                  and DATA_BODY in after.get("body", "") and denied["kind"] == "http"
                  and denied["http_code"] == 403)
        obs = {"kind": "http" if after["kind"] == "http" else after["kind"],
               "http_code": after.get("http_code"), "curl_exit": after.get("curl_exit"),
               "kubectl_exit": after.get("kubectl_exit"), "body_ok": DATA_BODY in after.get("body", ""),
               "layer": "strict", "steps": [{"request_id": result["request_id"],
                    "http_code": result.get("http_code"), "body_ok": DATA_BODY in result.get("body", "")}
                    for result in (before, after, denied)]}
        return _row(run_id, "S23", "strict", {"after_restart_allow": 200, "viewer_admin": 403},
                    obs, passed, ["frontend and OPA rollouts completed; proxy readiness and policy canaries passed"])
    except Exception as exc:
        return _row(run_id, "S23", "strict", {"recovery": "allow and deny canaries pass"},
                    {"kind": "error", "http_code": None, "curl_exit": None, "kubectl_exit": None,
                     "body_ok": None, "layer": "strict"}, False,
                    [f"restart/recovery check failed: {type(exc).__name__}"])


def run_suite(runtime, run_dir, only=None):
    run_id = Path(run_dir).name
    rows = []
    valid_ids = {f"S{i:02d}" for i in range(1, 35)} - {"S32"}
    if only is not None and only not in valid_ids:
        raise ValueError(f"Unknown security scenario: {only}")
    runtime.wait_ready()

    def token(username):
        return identity.issue_tokens(runtime, username=username, kind='unhealthy' if username.startswith('unhealthy-') else 'healthy')

    def add(case_id, action):
        if only is None or only == case_id:
            print('Executing ' + case_id, flush=True)
            try:
                rows.append(action())
            except Exception as exc:
                rows.append(_row(run_id, case_id, "strict", {"scenario_executed": True},
                                 {"kind": "error", "http_code": None, "curl_exit": None,
                                  "kubectl_exit": None, "body_ok": None, "layer": "strict"}, False,
                                 [f"scenario setup failed: {type(exc).__name__}"]))
            print(case_id + ' ' + rows[-1]['status'], flush=True)
            if Path(run_dir).is_dir():
                with (Path(run_dir) / 'case-progress.jsonl').open('a', encoding='utf-8') as progress:
                    progress.write(json.dumps(rows[-1]) + '\n')
            if getattr(runtime, 'config_ready', True) is False:
                from runtime import RuntimeError
                raise RuntimeError('Configuration or restoration gate failed; remaining scenarios were not executed')

    add("S01", lambda: _check(runtime, run_id, "S01", "strict", "/api/admin", 403,
                                headers={"role": "admin"}))
    add('S02', lambda: _combine(run_id, 'S02', 'strict', [
        _check(runtime,run_id,'S02-read','strict','/api/admin',403,token('viewer-user')['access'],headers={'role':'admin','X-ZTA-Posture':token('viewer-user')['posture']}),
        _check(runtime,run_id,'S02-write','strict','/api/write',403,token('viewer-user')['access'],'POST','{}',headers={'role':'admin','X-Device-Firewall':'enabled','X-ZTA-Posture':token('viewer-user')['posture'],'Content-Type':'application/json'}),
    ], {'viewer_admin_read_write':'denied despite role/firewall headers'}))
    add("S03", lambda: _combine(run_id, "S03", "strict", [
        _check(runtime,run_id,'S03-root','strict','/',200,token('viewer-user')['access'],body_text='backend',headers={'X-ZTA-Posture':token('viewer-user')['posture']}),
        _check(runtime, run_id, "S03-viewer-read", "strict", "/api/data", 200,
               token("viewer-user")["access"], body_text=DATA_BODY, headers={'X-ZTA-Posture': token('viewer-user')['posture']}),
        _check(runtime, run_id, "S03-admin-read", "strict", "/api/admin", 200,
               token("admin-user")["access"], body_text="admin-config", headers={'X-ZTA-Posture': token('admin-user')['posture']}),
        _check(runtime, run_id, "S03-admin-write", "strict", "/api/write", 200,
               token("admin-user")["access"], "POST", '{"data":"suite-write"}', "write-accepted", headers={'X-ZTA-Posture': token('admin-user')['posture'], 'Content-Type': 'application/json'}),
        _check(runtime, run_id, 'S03-array-rejected', 'strict', '/api/write', 400,
               token('admin-user')['access'], 'POST', '[1,2]', headers={'X-ZTA-Posture': token('admin-user')['posture'], 'Content-Type':'application/json'}),
        _check(runtime, run_id, 'S03-size-rejected', 'strict', '/api/write', 413,
               token('admin-user')['access'], 'POST', json.dumps({'data':'x'*65536}), headers={'X-ZTA-Posture': token('admin-user')['posture'], 'Content-Type':'application/json'}),
    ], {"all_steps_must_pass": True}))
    add("S04", lambda: _check(runtime, run_id, "S04", "strict", "/api/admin", [401, 403],
                               _alter_payload(token('viewer-user')['access'], lambda p: {**p, 'realm_access': {**p.get('realm_access',{}), 'roles': [*p.get('realm_access',{}).get('roles',[]), 'admin']}}),
                               headers={'X-ZTA-Posture':token('viewer-user')['posture']}))
    add("S05", lambda: _check(runtime, run_id, "S05", "strict", "/api/admin", [401, 403],
                               identity.test_tokens(runtime, "wrong_issuer", "admin-user")["access"], headers={'X-ZTA-Posture':token('admin-user')['posture']}))
    add("S06", lambda: _check(runtime, run_id, "S06", "strict", "/api/admin", [401, 403],
                               identity.test_tokens(runtime, "wrong_audience", "admin-user")["access"], headers={'X-ZTA-Posture':token('admin-user')['posture']}))
    add("S07", lambda: _combine(run_id, "S07", "strict", [
        _check(runtime, run_id, "S07-expired", "strict", "/api/admin", [401, 403],
               identity.test_tokens(runtime, "expired", "admin-user")["access"], headers={'X-ZTA-Posture':token('admin-user')['posture']}),
        _check(runtime, run_id, "S07-future-nbf", "strict", "/api/admin", [401, 403],
               identity.test_tokens(runtime, "future_nbf", "admin-user")["access"], headers={'X-ZTA-Posture':token('admin-user')['posture']}),
    ], {"expired_and_future_nbf": 'denied by JWT or OPA before backend'}))
    def s08():
        tokens = token('admin-user')
        unsigned = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip('=') + '.' + tokens['access'].split('.')[1] + '.'
        return _combine(run_id,'S08','strict',[
            _check(runtime,run_id,'S08-format','strict','/api/admin',[401,403],'not-a-jwt',headers={'X-ZTA-Posture':tokens['posture']}),
            _check(runtime,run_id,'S08-unsigned','strict','/api/admin',[401,403],unsigned,headers={'X-ZTA-Posture':tokens['posture']}),
            _check(runtime,run_id,'S08-scheme','strict','/api/admin',[401,403],headers={'Authorization':'Basic invalid','X-ZTA-Posture':tokens['posture']}),
        ],{'malformed_unsigned_wrong_scheme':'denied before backend'})
    add('S08', s08)
    add("S09", lambda: _key_rotation(runtime, run_id))
    add("S10", lambda: _ttl_revocation(runtime, run_id))
    add("S11", lambda: _east_west(runtime, run_id, "S11", "rogue-client", "http://backend", "/", "GET"))
    add("S12", lambda: _wrong_service_account(runtime, run_id))
    def s13():
        service = _east_west(runtime, run_id, "S13-service", "rogue-client", "http://backend", "/", "GET")
        try:
            ip = runtime.kubectl("get", "pods", "-l", "app=backend",
                                 "-o", "jsonpath={.items[0].status.podIP}").strip()
            if not ip:
                raise RuntimeError("backend pod IP unavailable")
            direct = _east_west(runtime, run_id, "S13-pod-ip", "rogue-client", f"http://{ip}:8080", "/", "GET")
        except Exception as exc:
            direct = _row(run_id, "S13-pod-ip", "mtls", {"kind": "transport_denied"},
                          {"kind": "error", "http_code": None, "curl_exit": None,
                           "kubectl_exit": None, "body_ok": None, "layer": "mtls"}, False,
                          [f"direct pod-IP check unavailable: {type(exc).__name__}"])
        return _combine(run_id, "S13", "strict", [service, direct],
                        {"service_and_pod_ip": "deny with matched TLS evidence and positive controls"})
    add("S13", s13)
    add("S14", lambda: _combine(run_id, "S14", "strict", [
        _check(runtime, run_id, "S14-admin-read", "strict", "/api/admin", 403,
               client="frontend-probe", url="http://backend"),
        _check(runtime, run_id, "S14-admin-write", "strict", "/api/write", 403,
               method="POST", body='{"data":"suite-direct"}',
               client="frontend-probe", url="http://backend"),
    ], {"frontend_workload_identity_without_user_jwt": 403}))
    add("S15", lambda: _combine(run_id, "S15", "strict", [
        _check(runtime, run_id, "S15-viewer-admin", "strict", "/api/admin", 403,
               token("viewer-user")["access"],
               headers={"X-ZTA-Posture": token("viewer-user")["posture"]},
               client="frontend-probe", url="http://backend"),
        _check(runtime, run_id, "S15-viewer-write", "strict", "/api/write", 403,
               token("viewer-user")["access"], method="POST", body='{"data":"suite-viewer"}',
               headers={"X-ZTA-Posture": token("viewer-user")["posture"]},
               client="frontend-probe", url="http://backend"),
    ], {"frontend_workload_with_viewer_token_cannot_admin_or_write": 403}))
    add("S16", lambda: _opa_management_boundary(runtime, run_id))
    add("S17", lambda: _opa_outage(runtime, run_id))
    add("S18", lambda: _policy_transition(runtime, run_id))
    def s34():
        observed = runtime.rebuild_probe()
        observed.update(kind='http', kubectl_exit=0, body_ok=True)
        return _row(run_id, 'S34', 'strict', {'new_image_deployed': True, 'original_source_unchanged': True},
                    observed, observed['original_source_unchanged'], ['native rebuild, image IDs, live canaries, original image restored'])
    add('S34', s34)
    add("S23", lambda: _restart_recovery(runtime, run_id))
    add("S22", lambda: _backend_failure(runtime, run_id))
    add("S19", lambda: _combine(run_id, "S19", "strict", [
        _check(runtime, run_id, "S19-admin", "strict", "/api/admin", 403,
               token("unhealthy-admin")["access"], headers={"X-ZTA-Posture": token("unhealthy-admin")["posture"]}),
        _check(runtime, run_id, "S19-viewer", "strict", "/api/data", 403,
               token("unhealthy-viewer")["access"], headers={"X-ZTA-Posture": token("unhealthy-viewer")["posture"]}),
    ], {"admin_and_viewer_with_unhealthy_signed_posture": 403}))
    add("S20", lambda: _combine(run_id, "S20", "strict", [
        _check(runtime, run_id, "S20-missing", "strict", "/api/admin", 403, token("admin-user")["access"]),
        _check(runtime, run_id, "S20-forged", "strict", "/api/admin", 403,
               token("admin-user")["access"], headers={"X-ZTA-Posture": "enabled"}),
        _check(runtime, run_id, 'S20-tampered-signature', 'strict', '/api/admin', 403,
               token('admin-user')['access'], headers={'X-ZTA-Posture': _alter_payload(token('admin-user')['posture'], lambda p: {**p, 'sub': 'tampered-user'}), 'X-Device-Firewall': 'enabled'}),
    ], {"missing_and_forged_signed_posture": 403}))
    add("S21", lambda: _combine(run_id, "S21", "strict", [
        _check(runtime, run_id, "S21-wrong-subject", "strict", "/api/admin", 403,
               token("admin-user")["access"],
               headers={"X-ZTA-Posture": token("viewer-user")["posture"]}),
        _check(runtime, run_id, "S21-stale", "strict", "/api/admin", 403,
               token("admin-user")["access"],
               headers={"X-ZTA-Posture": identity.test_tokens(runtime, "stale_posture", "admin-user")["posture"]}),
        _check(runtime, run_id, 'S21-expired', 'strict', '/api/admin', 403,
               token('admin-user')['access'], headers={'X-ZTA-Posture': identity.test_tokens(runtime, 'expired_posture', 'admin-user')['posture']}),
    ], {"wrong_subject_and_stale_signed_posture": 403,
        "posture_ttl_and_max_age_seconds": 120}))
    add("S24", lambda: _idp_outage(runtime, run_id))
    add("S31", lambda: _performance_failure_lifecycle(run_id))
    add("S30", lambda: _secret_log_check(runtime, run_id))
    add("S33", lambda: _live_readiness_failure(runtime, run_id))
    if only is None or only in {"S27", "S28", "S29"}:
        try:
            rows.extend(row for row in _dashboard_checks(run_id)
                        if only is None or row["case_id"] == only)
        except Exception as exc:
            rows.extend(_row(run_id, case_id, "dashboard", {"check": "pass"},
                             {"kind": "error", "http_code": None, "curl_exit": None,
                              "kubectl_exit": None, "body_ok": None, "layer": "dashboard"}, False,
                             [f"dashboard integration check unavailable: {type(exc).__name__}"])
                        for case_id in ("S27", "S28", "S29")
                        if only is None or only == case_id)
    add("S25", lambda: _combine(run_id, "S25", "strict", [
        _check(runtime, run_id, "S25-canonical", "strict", "/api/admin", 200,
               token("admin-user")["access"], headers={"X-ZTA-Posture": token("admin-user")["posture"]},
               body_text="admin-config"),
        _check(runtime, run_id, "S25-double-slash", "strict", "/api//admin", 200,
               token("admin-user")["access"], headers={"X-ZTA-Posture": token("admin-user")["posture"]}),
        _check(runtime, run_id, "S25-encoded", "strict", "/api/%61dmin", 200,
               token("admin-user")["access"], headers={"X-ZTA-Posture": token("admin-user")["posture"]}),
        _check(runtime, run_id, 'S25-encoded-slash', 'strict', '/api%2fadmin', 200,
               token('admin-user')['access'], headers={'X-ZTA-Posture': token('admin-user')['posture']}),
        _check(runtime, run_id, 'S25-viewer-encoded-slash', 'strict', '/api%2fadmin', 403,
               token('viewer-user')['access'], headers={'X-ZTA-Posture': token('viewer-user')['posture'], 'role':'admin'}),
        _check(runtime, run_id, "S25-query", "strict", "/api/admin?case=1", 200,
               token("admin-user")["access"], headers={"X-ZTA-Posture": token("admin-user")["posture"]}),
        _check(runtime, run_id, "S25-head", "strict", "/api/admin", 403,
               token("admin-user")["access"], method="HEAD",
               headers={"X-ZTA-Posture": token("admin-user")["posture"]}),
        _check(runtime, run_id, 'S25-options', 'strict', '/api/data', 403,
               token('admin-user')['access'], method='OPTIONS', headers={'X-ZTA-Posture': token('admin-user')['posture']}),
    ], {"normalized_admin_paths_allow_only_signed_admin_get": True}))
    add("S26", lambda: _combine(run_id, "S26", "strict", [
        _check(runtime, run_id, "S26-authorization", "strict", "/api/admin", [401, 403],
               token("admin-user")["access"],
               headers=[("Authorization", "Bearer invalid"), ('X-ZTA-Posture',token('admin-user')['posture'])]),
        _check(runtime, run_id, "S26-posture", "strict", "/api/admin", 403,
               token("admin-user")["access"], headers=[("X-ZTA-Posture", token("admin-user")["posture"]),
                                                        ("X-ZTA-Posture", "enabled")]),
        _check(runtime,run_id,'S26-role','strict','/api/admin',403,token('viewer-user')['access'],
               headers=[('role','viewer'),('role','admin'),('X-ZTA-Posture',token('viewer-user')['posture'])]),
    ], {"ambiguous_duplicate_identity_headers": 'denied'}))
    return rows


def run_case(runtime, case_id, run_dir=None):
    rows = run_suite(runtime, run_dir or f"case-{uuid.uuid4()}", only=case_id)
    if len(rows) != 1:
        raise RuntimeError(f"Scenario {case_id} did not return exactly one result")
    return rows[0]


def _east_west(runtime, run_id, case_id, client, url, path, method):
    try:
        _activate_mode(runtime, "strict")
        control_tokens = identity.issue_tokens(runtime, username="admin-user")
        control = request(runtime, "http://backend", path, headers=_token_headers(
            control_tokens["access"], {"X-ZTA-Posture": control_tokens["posture"]}), client="frontend-probe")
        start = time.time()
        denied = request(runtime, url, path, method, client=client)
        end = time.time()
        after_tokens = identity.issue_tokens(runtime, username="admin-user")
        after = request(runtime, "http://backend", path, headers=_token_headers(
            after_tokens["access"], {"X-ZTA-Posture": after_tokens["posture"]}), client="frontend-probe")
        source_ip = runtime.kubectl("get", "pods", "-l", f"app={client}",
                                    "-o", "jsonpath={.items[0].status.podIP}", check=False)
        matches = []
        for attempt in range(5):
            log = runtime.kubectl("logs", "deploy/backend", "-c", "istio-proxy", "--since=90s", check=False)
            for line in str(log).splitlines():
                try:
                    event = json.loads(line)
                    when = datetime.fromisoformat(event['time'].replace('Z', '+00:00')).timestamp()
                    if source_ip.strip() == str(event.get('downstream_remote', '')).split(':')[0] and start - 0.5 <= when <= end + 0.5 and event.get('response_code_details') == 'filter_chain_not_found':
                        matches.append(event)
                except (ValueError, KeyError):
                    continue
            if matches:
                break
            if attempt < 4:
                time.sleep(0.5)
        matched_log = bool(matches)
        proof = (control["kind"] == "http" and control["http_code"] == 200
                 and after["kind"] == "http" and after["http_code"] == 200
                 and denied["kind"] == "transport_denied" and matched_log)
        if denied["kind"] == "transport_denied" and not proof:
            denied["kind"] = "error"
        denied["layer"] = "mtls"
        denied['connection'] = {'source_ip': source_ip.strip(), 'destination': url, 'start_utc': datetime.fromtimestamp(start, timezone.utc).isoformat(), 'end_utc': datetime.fromtimestamp(end, timezone.utc).isoformat()}
        denied['envoy_transport_evidence'] = matches
        denied["body_ok"] = None
        return _row(run_id, case_id, "strict", {"kind": "transport_denied", "positive_controls": 2},
                    denied, bool(proof), ["positive controls succeeded",
                    "destination Envoy log matches source pod IP and TLS/transport denial" if proof else "transport result unproven: no matching destination Envoy evidence"])
    except Exception as exc:
        return _row(run_id, case_id, "mtls", {"kind": "transport_denied"},
                    {"kind": "error", "http_code": None, "curl_exit": None, "kubectl_exit": None,
                     "body_ok": None, "layer": "mtls"}, False,
                    [f"runner exception: {type(exc).__name__}"])


def _wrong_service_account(runtime, run_id):
    try:
        _activate_mode(runtime, "strict")
        before_token = identity.issue_tokens(runtime, username="admin-user")
        before = request(runtime, "http://backend", "/api/admin", headers=_token_headers(
            before_token["access"], {"X-ZTA-Posture": before_token["posture"]}), client="frontend-probe")
        wrong_token = identity.issue_tokens(runtime, username="admin-user")
        denied = request(runtime, "http://backend", "/api/admin", headers=_token_headers(
            wrong_token["access"], {"X-ZTA-Posture": wrong_token["posture"]}), client="wrongsa-client")
        event = _envoy_line(runtime, "backend", denied["request_id"])
        reason = " ".join(str(event.get(key, "")) for key in ("response_code_details", "response_flags")) if event else ""
        after_token = identity.issue_tokens(runtime, username="admin-user")
        after = request(runtime, "http://backend", "/api/admin", headers=_token_headers(
            after_token["access"], {"X-ZTA-Posture": after_token["posture"]}), client="frontend-probe")
        proof = (denied["kind"] == "http" and denied["http_code"] == 403
                 and bool(event) and re.search(r"rbac_access_denied", reason))
        passed = (before["http_code"] == 200 and proof and after["http_code"] == 200)
        obs = {"kind": "http" if denied["kind"] == "http" else denied["kind"],
               "http_code": denied.get("http_code"), "curl_exit": denied.get("curl_exit"),
               "kubectl_exit": denied.get("kubectl_exit"), "body_ok": None, "layer": "spiffe-authorization",
               "steps": [{"request_id": r["request_id"], "http_code": r.get("http_code")}
                         for r in (before, denied, after)], "rbac_deny_correlated": bool(proof)}
        return _row(run_id, "S12", "strict", {"mtls": "pass", "wrong_service_account": 403},
                    obs, passed, ["same backend route allowed for frontend-sa and correlated RBAC-denied for wrong SA"])
    except Exception as exc:
        return _row(run_id, "S12", "strict", {"wrong_service_account": 403},
                    {"kind": "error", "http_code": None, "curl_exit": None, "kubectl_exit": None,
                     "body_ok": None, "layer": "strict"}, False,
                    [f"wrong-SA check failed: {type(exc).__name__}"])
